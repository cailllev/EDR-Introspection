#define WIN32_LEAN_AND_MEAN // wtf c++
#include <windows.h>
#include <chrono>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <string>
#include <string.h>
#include <unordered_map>
#include <vector>
#include <wchar.h>
#include <TraceLoggingProvider.h>

#include "helpers/cxxopts.hpp"
#include "helpers/json.hpp"

#include "globals.h"
#include "hooker.h"
#include "sandblast.h"
#include "utils.h"
#include "filter.h"
#include "profile.h"
#include "etwreader.h"
#include "output.h"
#include "main.h"

/*
- creates krabs ETW traces for Antimalware, Kernel, etc. and the attack provider
- invokes the attack
- then transforms all captured events into a "filtered" csv, ready for Timeline Explorer
*/


// my provider
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "EDRi-Provider", // name in the ETW, cannot be a variable
    (0x72248477, 0x7177, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

// globals
std::vector<int> g_tracking_PIDs = std::vector<int>{};
std::vector<int> g_newly_hooked_procs = std::vector<int>{};
std::vector<ProcInfo> g_running_procs = std::vector<ProcInfo>{};
std::shared_mutex g_procs_mutex;
std::vector<std::string> g_exes_to_track = {
    "smartscreen.exe", "System"
};

// attack exe paths
std::string g_attack_exe_name = "attack-" + get_random_3digit_num() + ".exe"; // random every run
std::string g_attack_exe_path = "C:\\Users\\Public\\Downloads\\" + g_attack_exe_name;

// more debug info
bool g_debug = false;
bool g_super_debug = false;

// misc settings
bool reflective_inject = true;

// wait times
static const int add_wait_for_other_traces = 10000; // ensure all other traces are also started (additional wait)
static const int wait_between_events_ms = 1000;
static const int wait_after_termination_ms = 5000;
static const int wait_attack_not_found_threshold_ms = 20000;
static const int wait_time_between_start_markers_ms = 1000;
static const int wait_callbacks_reenable_ms = 10000;
static const int timeout_for_hooker_init = 30;

// etw print prefixes
std::string ok = "[+] ";
std::string fail = "[!] ";
std::string bef = "[<]  ";
std::string aft = "[>]  ";

void emit_etw_event(std::string msg, std::string pre, bool print_when_debug) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "EDRi-Event", // this is the event name, not further used
        TraceLoggingValue(msg.c_str(), "message"), // cannot be a variable
        TraceLoggingUInt64(ns, "ns_since_epoch")
    );
    if (g_debug && print_when_debug) {
        std::cout << pre << msg << "\n";
    }
}

void process_results(std::string output, bool dump_sig, bool colored) {
	std::vector<json> all_etw_events = get_all_etw_events();
    std::map<Classifier, std::vector<json>> etw_events = filter_all_events(all_etw_events);
    write_events_to_file(etw_events, output, colored);

    print_etw_counts(etw_events);
    if (g_debug) {
        print_time_differences();
    }

    if (dump_sig) {
        dump_signatures(etw_events); // can only dump from antimalware provider
    }
    std::cout << "[*] EDRi: Done\n";
}

void cleanup(std::string output, bool dump_sig, bool colored) {
    remove_file(g_attack_exe_path); // remove again if it still exists
    stop_all_etw_traces();
    process_results(output, dump_sig, colored);
}

int main(int argc, char* argv[]) {
    cxxopts::Options options("EDRi", "EDR Introspection Framework");
    
    // PARSER OPTIONS
    options.add_options()
        ("h,help", "Print usage")
        ("e,encrypt", "The path of the attack executable to encrypt", cxxopts::value<std::string>())
        ("p,edr-profile", "The EDR to track, supporting: " + get_available_edrs(), cxxopts::value<std::string>())
        ("a,attack-exe", "The attack to execute, supporting: " + get_available_attacks(), cxxopts::value<std::string>())
        ("r,run-as-child", "If the attack should run (automatically) as a child of the EDRi.exe or if it should be executed manually")
        ("o,output", "The Path of the all-events.csv, default " + all_events_output_default, cxxopts::value<std::string>())
        ("m,trace-etw-misc", "Trace misc ETW")
        ("i,trace-etw-ti", "Trace ETW-TI (needs PPL)")
        ("n,hook-ntdll", "Hook ntdll.dll (needs PPL)")
        ("t,track-all", "Trace misc ETW, ETW-TI and hooks ntdll.dll")
        ("d,debug", "Print debug info")
        ("v,verbose-debug", "Print very verbose debug info");
        ("c,color", "Add color formatting information");

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    }
    catch (const cxxopts::exceptions::parsing& e) {
        std::cerr << "Error parsing options: " << e.what() << "\n";
        std::cout << options.help() << "\n";
        return 1;
	}
    std::cout << "[*] EDRi: EDR Introspection Framework\n";

    // PARSING
    // encrypt an exe
    if (result.count("e") > 0) {
        std::string in_path = result["encrypt"].as<std::string>();
        std::string out_path = in_path + ".enc";
        if (xor_file(in_path, out_path)) {
            std::cout << "[*] EDRi: XOR encrypted " << in_path << " to " << out_path << "\n";
            return 0;
        }
        else {
            std::cerr << "[!] EDRi: Failed to encrypt " << in_path << "\n";
			return 1;
        }
    }
    if (result.count("help")) {
        std::cout << options.help() << "\n";
        return 0;
    }
    build_device_map();

    // check edr profile, attack exe and output
    if (result.count("edr-profile") == 0) {
        std::cerr << "[!] EDRi: No EDR specified, use -p and one of: " << get_available_edrs() << "\n";
        return 1;
	}
	std::string edr_name = result["edr-profile"].as<std::string>();
    if (edr_profiles.find(edr_name) == edr_profiles.end()) {
        std::cerr << "[!] EDRi: Unsupported EDR specified, use one of: " << get_available_edrs() << "\n";
        return 1;
    }
    EDR_Profile edr_profile = edr_profiles.at(edr_name);
    if (result.count("attack-exe") == 0) {
        std::cerr << "[!] EDRi: No attack specified, use -a and one of: " << get_available_attacks() << "\n";
        return 1;
	}
	std::string attack_name = result["attack-exe"].as<std::string>();
    if (!is_attack_available(attack_name)) {
        std::cerr << "[!] EDRi: Unsupported attack specified, use one of: " << get_available_attacks() << "\n";
        return 1;
	}
	std::string attack_exe_enc_path = get_attack_enc_path(attack_name);
    std::string output;
    if (result.count("output") == 0) {
        output = all_events_output_default;
    }
    else {
        output = result["output"].as<std::string>();
    }
    std::cout << "[*] EDRi: Writing events to: " << output << "\n";

    bool run_as_child = false;
    if (result.count("run-as-child") > 0) {
        run_as_child = true;
	}

    // check tracking options
    bool trace_etw_misc = false, trace_etw_ti = false, hook_ntdll = false;
    if (result.count("track-all") > 0) {
        trace_etw_misc = true, trace_etw_ti = true, hook_ntdll = true;
    }
    else {
        if (result.count("trace-etw-misc") > 0) {
            trace_etw_misc = true;
        }
        if (result.count("trace-etw-ti") > 0) {
            trace_etw_ti = true;
        }
        if (result.count("hook-ntdll") > 0) {
            hook_ntdll = true;
        }
    }
	std::cout << "[*] EDRi: Tracking options: ETW-Misc: " << (trace_etw_misc ? "Yes" : "No") 
		<< ", ETW-TI: " << (trace_etw_ti ? "Yes" : "No")
		<< ", Hook-ntdll: " << (hook_ntdll ? "Yes" : "No") << "\n";
	bool dump_sig = trace_etw_misc; // can only dump signatures if antimalware provider is traced

    // debug
    if (result.count("debug") > 0) {
        g_debug = true;
    }
    if (result.count("verbose-debug") > 0) {
        g_debug = true;
        g_super_debug = true;
    }
    bool colored = false;
    if (result.count("color") > 0) {
        colored = true;
    }

    // TRACKING PREPARATION + INIT ETW TRACES
    TraceLoggingRegister(g_hProvider);
    std::cout << "[+] EDRi: Own provider registered\n";

    std::vector<HANDLE> threads;
    if (hook_ntdll) {
        if (!start_etw_hook_trace(threads)) {
            std::cerr << "[!] EDRi: Failed to start ETW-Hook traces\n";
            return 1;
        }
    }
    if (trace_etw_ti) {
        if (!start_etw_ti_trace(threads)) {
            std::cerr << "[!] EDRi: Failed to start ETW-TI traces\n";
            return 1;
        }
    }
    if (trace_etw_misc) {
        if (!start_etw_misc_traces(threads)) {
            std::cerr << "[!] EDRi: Failed to start misc ETW traces(s)\n";
            return 1;
        }
    }
    if (!start_etw_default_traces(threads)) { // start last
        std::cerr << "[!] EDRi: Failed to start default ETW traces(s)\n";
        return 1;
	}

    // WAIT UNTIL TRACES ARE READY
    std::cout << "[*] EDRi: Waiting until start marker is registered\n";
    while (!g_traces_started) {
        emit_etw_event(EDRi_TRACE_START_MARKER, "", false);
        Sleep(wait_time_between_start_markers_ms);
    }
    if (hook_ntdll || trace_etw_ti || trace_etw_misc) {
        Sleep(add_wait_for_other_traces); // other traces may take longer to start, wait for them too
    }
    std::cout << "[*] EDRi: Traces started\n";

    // GET PROCS TO TRACK
    // etw traces also add procs over time
    // -> taking a snapshot of procs first and then starting etw would omit procs started
    //    between snapshot_procs() and "traces ready to track new proc creations"
    // --> therefore snapshot_procs() after traces started
    std::cout << "[*] EDRi: Get running procs\n";
    snapshot_procs();
    UINT64 proc_snapshot_timestamp = get_ns_time();
    for (auto& e : g_exes_to_track) {
        std::vector<int> pids = get_PID_by_name(e, proc_snapshot_timestamp);
        for (auto& p : pids) {
            std::cout << "[+] EDRi: Got pid for " << e << ":" << p << "\n";
            g_tracking_PIDs.push_back(p);
        }
        if (pids.empty() && g_debug) {
            std::cout << "[-] EDRi: Process tracking, could not find " << e << "\n";
		}
    }
    for (auto& e : get_all_edr_exes(edr_profile)) {
        std::vector<int> pids = get_PID_by_name(e, proc_snapshot_timestamp);
        for (auto& p : pids) {
            std::cout << "[+] EDRi: Got pid for " << e << ":" << p << "\n";
            g_tracking_PIDs.push_back(p);
        }
        if (pids.empty() && g_debug) {
            std::cout << "[-] EDRi: Process tracking, could not find EDR specific " << e << "\n";
        }
    }
	std::string up = unnecessary_tools_running();
    if (!up.empty()) {
        std::cout << "[!] EDRi: Unnecessary tools running: " << up << "\n";
        std::cout << "[!] EDRi: It is recommended to close them and start again, continuing in 3 sec...\n";
		Sleep(3000);
	}

    // HOOK NTDLL
    // hooking emits etw events, so hooking must be done after the traces are started
    if (hook_ntdll) {
        if (!disable_kernel_callbacks_ok()) {
            std::cerr << "[!] EDRi: Failed to disable kernel callbacks, check manually if this is needed\n";
            stop_all_etw_traces();
            return 1;
        }
        std::cout << "// --------------------------- EDR Sandblast end marker ---------------------------\n"; // mark end in logs

		// get main edr processes and inject the hooker
        std::vector<std::string> main_edr_exes = edr_profile.main_exes;
        std::vector<int> hooked_procs = get_hooked_procs();
        bool check_init_needed = false;
        bool found_none = true;
        for (auto& exe : main_edr_exes) {
            std::vector<int> pids = get_PID_by_name(exe, proc_snapshot_timestamp);
            if (pids.empty()) {
                std::cerr << "[!] EDRi: Could not find the EDR process " << exe << ", is it running?\n";
                continue;
            }
            found_none = false;
            for (auto& pid : pids) {
                if (std::find(hooked_procs.begin(), hooked_procs.end(), pid) != hooked_procs.end()) {
                    std::cout << "[+] EDRi: Found the EDR process " << exe << ":" << pid << ", but already hooked, continuing...\n";
                    g_newly_hooked_procs.push_back(pid); // add for next run, only when PID stayed the same
                    continue; // already hooked
                }
                std::cout << "[+] EDRi: Found the EDR process " << exe << ":" << pid << ". Injecting...\n";
                if (!inject_dll(pid, get_hook_dll_path(), g_debug, reflective_inject)) {
                    std::cerr << "[!] EDRi: Failed to inject the hooker dll into " << exe << "\n";
                    stop_all_etw_traces();
                    return 1;
                }
                g_newly_hooked_procs.push_back(pid); // add for next run
                check_init_needed = true; // new proc hooked, must check if hooks started
				std::cout << "[+] EDRi: Successfully injected the hooker into " << exe << ":" << pid << "\n";
            }
        }
        if (found_none) {
			std::cerr << "[!] EDRi: Could not find any of the main EDR processes";
            stop_all_etw_traces();
            return 1;
		}
        save_hooked_procs(g_newly_hooked_procs);

        // check if the hooker is successfully initialized
        if (!check_init_needed) {
            std::cout << "[+] EDRi: No new process hooked, no need to check for initialization of the hooker\n";
        }

        // check if ALL newly hooked procs emitted the hook start msg
        int wait = 0;
        while (check_init_needed && !g_hooker_started) {
			Sleep(1000);
            if (++wait > timeout_for_hooker_init) {
                std::cerr << "[!] EDRi: Could not detect a successful initialization of the hooker!\n";
                stop_all_etw_traces();
                return 1;
			}
        }
        std::cout << "[*] EDRi: Hooker initialization detected on all relevant processes, wait for re-enabling of kernel callbacks by EDRSandblast...\n";
		Sleep(wait_callbacks_reenable_ms); // wait until callbacks are reenabled
    }

    // ATTACK
	// decrypt the attack exe
	emit_etw_event("Before decrypting the attack exe from " + attack_exe_enc_path, bef, true);
    if (xor_file(attack_exe_enc_path, g_attack_exe_path)) {
        std::cout << "[*] EDRi: Decrypted the attack exe: " << g_attack_exe_path << "\n";
    }
    else {
        std::cerr << "[!] EDRi: Failed to decrypt the attack exe: " << attack_exe_enc_path << "\n";
        stop_all_etw_traces();
        return 1;
    }
    emit_etw_event("After decrypting the attack exe", aft, true);
    Sleep(wait_between_events_ms);

    // start the attack
    emit_etw_event("Before starting the attack exe", bef, true);
    if (g_debug) {
        std::cout << "[~] EDRi: The EDR might block the attack and a pop up is displayed. In this case, just close it or click OK\n";
    }
    Sleep(wait_between_events_ms);
    if (run_as_child) {
        try {
            if (!launch_as_child(g_attack_exe_path)) {
                std::cerr << "[!] EDRi: Failed to launch the attack exe: " << g_attack_exe_path << ". Was it marked as a virus?\n";
                cleanup(output, dump_sig, colored);
                return 0;
            }
        }
        catch (...) {
            std::cerr << "[!] EDRi: Launching attack as child failed: " << GetLastError() << "\n";
            Sleep(wait_after_termination_ms);
            cleanup(output, dump_sig, colored);
        }
    }
    else {
        std::cout << "[*] EDRi: Execute " << g_attack_exe_path << " now manually\n";
    }
    int cnt_waited = 0;
    while (g_attack_proc.PID == 0) { // always wait for the attack_PID, lauch_as_child() might succeed even when attack is not started
        Sleep(100);
        cnt_waited += 100;
        if (cnt_waited > wait_attack_not_found_threshold_ms) {
            std::cerr << "[!] EDRi: Timeout waiting for attack PID, did you start " << g_attack_exe_path << ", or was it marked as a virus?\n";
            cleanup(output, dump_sig, colored);
            return 0;
        }
    }
	emit_etw_event("After starting the attack exe", aft, true);

	// wait until the attack.exe terminates again
    std::cout << "[+] EDRi: Waiting for the attack exe to finish...\n";
    while (!g_attack_terminated) {
        Sleep(100);
	}
    std::cout << "[+] EDRi: Waiting for any final events...\n";
    Sleep(wait_after_termination_ms);

    // threading stop and cleanup
    std::cout << "[*] EDRi: Stopping traces\n";
    stop_all_etw_traces();
    DWORD res = WaitForMultipleObjects(
        static_cast<DWORD>(threads.size()),
        threads.data(),
        TRUE,
        INFINITE
    ); // wait for all ETW threads to exit
    if (res == WAIT_FAILED) {
        std::cout << "[!] EDRi: Wait failed";
    }
    std::cout << "[*] EDRi: All " << threads.size() << " threads finished\n";
    for (auto h : threads) {
        try {
            CloseHandle(h);
        }
		catch (...) {
			std::cerr << "[!] EDRi: Closing thread handle failed, ignoring...\n";
        }
    }
    threads.clear();

    remove_file(g_attack_exe_path); // remove again

    process_results(output, dump_sig, colored);
	return 0;
}