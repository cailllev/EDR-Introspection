#define WIN32_LEAN_AND_MEAN // wtf c++
#include <windows.h>
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
#include "utils.h"
#include "etwreader.h"
#include "manager.h"
#include "profile.h"
#include "hooker.h"
#include "sandblast.h"

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
std::vector<int> g_tracking_PIDs = {};
std::map<int, std::string> g_running_procs = {};
std::shared_mutex g_procs_mutex;
bool g_with_hooks = false;

// attack exe paths
std::string g_attack_exe_name = "attack.exe";
std::string g_attack_exe_path = "C:\\Users\\Public\\Downloads\\" + g_attack_exe_name;

// more debug info
bool g_debug = false;
bool g_super_debug = false;
bool g_technicolor = false;

// wait times
static const int wait_after_traces_started_ms = 15000;
static const int wait_between_events_ms = 1000;
static const int wait_after_termination_ms = 5000;
static const int wait_time_between_start_markers_ms = 250;
static const int wait_callbacks_reenable_ms = 10000;
static const int timeout_for_hooker_init = 30;

void emit_etw_event(std::string msg, bool print_when_debug) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRi-Event", // this is the event name, not further used
        TraceLoggingValue(msg.c_str(), "message") // cannot be a variable
    );
    if (g_debug && print_when_debug) {
        std::cout << msg << "\n";
    }
}

void process_results(std::string output, bool dump_sig) {
    std::map<Classifier, std::vector<json>> cleaned_events = get_cleaned_events();
    print_etw_counts();

    write_events_to_file(output);

    if (dump_sig) {
        dump_signatures(); // can only dump from antimalware provider
    }
    std::cout << "[*] EDRi: Done\n";
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
        ("c,technicolor", "Store CSV with Timeline-Explorer technicolor markup");

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
    if (result.count("c") > 0) {
        std::string in_path = result["encrypt"].as<std::string>();
        std::string out_path = in_path + ".enc";
        xor_file(in_path, out_path);
        std::cout << "[*] EDRi: XOR encrypted " << in_path << " to " << out_path << "\n";
        return 0;
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
			g_with_hooks = true;
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
    if (result.count("technicolor") > 0) {
        g_technicolor = true;
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
    if (!start_etw_default_traces(threads)) {
        std::cerr << "[!] EDRi: Failed to start default ETW traces(s)\n";
        return 1;
	}

    // GET PROCS TO TRACK
    std::cout << "[*] EDRi: Get running procs\n";
    snapshot_procs();
    for (auto& e : exes_to_track) {
        std::vector<int> pids = get_PID_by_name(e);
        for (auto& p : pids) {
            std::cout << "[+] EDRi: Got pid for " << e << ":" << p << "\n";
            g_tracking_PIDs.push_back(p);
        }
        if (pids.empty() && g_debug) {
            std::cout << "[-] EDRi: Process tracking, could not find " << e << "\n";
		}
    }
    for (auto& e : get_all_edr_exes(edr_profile)) {
        std::vector<int> pids = get_PID_by_name(e);
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

    // WAIT UNTIL TRACES ARE READY
    Sleep(wait_after_traces_started_ms);
    std::cout << "[*] EDRi: Waiting until start marker is registered\n";
	while (!g_traces_started) {
        emit_etw_event(EDRi_TRACE_START_MARKER, false);
		Sleep(wait_time_between_start_markers_ms);
	}
	std::cout << "[*] EDRi: Traces started\n";

    // hooking emits etw events, so hooking must be done after the traces are started
    if (hook_ntdll) {
        if (!disable_kernel_callbacks_ok()) {
            std::cerr << "[!] EDRi: Failed to disable kernel callbacks, check manually if needed\n";
            stop_all_etw_traces();
            return 1;
        }

		// get main edr processes and inject the hooker
        std::vector<std::string> main_edr_exes = edr_profile.main_exes;
        //std::vector<std::string> main_edr_exes = { "cmd.exe" } ; // TODO debug
        bool found_none = true;
        for (auto& exe : main_edr_exes) {
            std::vector<int> pids = get_PID_by_name(exe);
            if (pids.empty()) {
                std::cerr << "[!] EDRi: Could not find the EDR process " << exe << ", is it running?\n";
                continue;
            }
            found_none = false;
            for (auto& pid : pids) {
                std::cout << "[*] EDRi: Found the EDR process " << exe << ":" << pid << ". Injecting...\n";
                if (!inject_dll(pid, get_hook_dll_path(), g_debug)) {
                    std::cerr << "[!] EDRi: Failed to inject the hooker dll into " << exe << "\n";
                    stop_all_etw_traces();
                    exit(1);
                }
            }
        }
        if (found_none) {
			std::cerr << "[!] EDRi: Could not find any of the main EDR processes";
            stop_all_etw_traces();
            return 1;
		}

        // check if the hooker is successfully initialized // TODO check all procs not just one start marker
        int wait = 0;
        while (!g_hooker_started) {
			Sleep(1000);
            if (++wait > timeout_for_hooker_init) {
                std::cerr << "[!] EDRi: Could not detect a successful initialization of the hooker!\n";
                stop_all_etw_traces();
                return 1;
			}
        }
		std::cout << "[*] EDRi: Wait for re-enabling of kernel callbacks by EDRSandblast...\n";
		Sleep(wait_callbacks_reenable_ms); // wait a bit until callbacks are reenabled
    }

    // ATTACK
	// decrypt the attack exe
	emit_etw_event("[<] Before decrypting the attack exe", true);
    if (xor_file(attack_exe_enc_path, g_attack_exe_path)) {
        std::cout << "[*] EDRi: Decrypted the attack exe: " << g_attack_exe_path << "\n";
    }
    else {
        std::cerr << "[!] EDRi: Failed to decrypt the attack exe: " << attack_exe_enc_path << "\n";
        stop_all_etw_traces();
        return 1;
    }
    emit_etw_event("[>]  After decrypting the attack exe", true);
    Sleep(wait_between_events_ms);

    // start the attack
    emit_etw_event("[<] Before starting the attack exe", true);
    Sleep(wait_between_events_ms);
    if (run_as_child) {
        if (!launch_as_child(g_attack_exe_path)) {
            std::cerr << "[!] EDRi: Failed to launch the attack exe: " << g_attack_exe_path << ". Was it marked as a virus?\n";
            stop_all_etw_traces();
            process_results(output, dump_sig);
            return 0;
        }
    }
    else {
        std::cout << "[*] EDRi: Execute " << g_attack_exe_path << " now manually\n";
		int cnt_waited = 0;
        while (g_attack_PID == 0) {
            Sleep(100);
            cnt_waited += 100;
            if (cnt_waited > 20000) {
                std::cerr << "[!] EDRi: Timeout waiting for attack PID, did you start " << g_attack_exe_path << ", or was it marked as a virus?\n";
                stop_all_etw_traces();
				process_results(output, dump_sig);
                return 0;
            }
        }
    }
	emit_etw_event("[>]  After starting the attack exe", true);

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

    process_results(output, dump_sig);
	return 0;
}