#define WIN32_LEAN_AND_MEAN // wtf c++
#include <windows.h>
#include <iostream>
#include <fstream>
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

// attack exe paths
std::string attack_exe_path = "C:\\Users\\Public\\Downloads\\attack.exe";
std::string attack_exe_enc_path = attack_exe_path + ".enc";

// more debug info
bool g_debug = false;
bool g_super_debug = false;

// wait times
static const int wait_after_traces_started_ms = 15000;
static const int wait_between_events_ms = 1000;
static const int wait_after_termination_ms = 5000;
static const int wait_time_between_start_markers_ms = 250;

void emit_etw_event(std::string msg, bool print_when_debug) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRi-Event", // this is the event name, can be anything with the current implementation
        TraceLoggingValue(msg.c_str(), "message") // cannot be a variable
    );
    if (g_debug && print_when_debug) {
        std::cout << msg << "\n";
    }
}

// translate device paths to drive letters
std::string translate_if_path(const std::string& s) {
    std::vector<std::string> to_replace = { "\\Device\\HarddiskVolume4\\", "\\\\?\\C:\\" };
    std::string replacement = "C:\\";
	std::string s2 = s;
    for (const auto& tr : to_replace) {
        size_t idx = s.find(tr);
        if (idx != std::string::npos) {
            s2 = s2.substr(0, idx) + replacement + s2.substr(idx + tr.length());
            if (g_super_debug) {
                std::cout << "[~] EDRi: Translated path " << s << " to " << s2 << "\n";
            }
        }
	}
    return s2;
}

std::string normalized_value(json ev, std::string key) {
    if (ev[key].is_string()) {
        std::string s = ev[key].get<std::string>();
        s = translate_if_path(s);
        std::replace(s.begin(), s.end(), '"', '\'');
        return "\"" + s + "\"";
    }
    else {
        return ev[key].dump();
    }
}

// output all events as a sparse CSV timeline with merged PPID and FilePath
std::string create_timeline_csv(const std::vector<json>& events) {
    std::ostringstream csv_output;

    std::vector<std::string> all_keys;
    if (g_super_debug) {
        std::cout << "[+] EDRi: Adding predefined key for CSV header: ";
    }
    for (const auto& k : csv_header_start) {
        all_keys.push_back(k);
        if (g_super_debug) {
			 std::cout << k << ", ";
        }
    }
    if (g_super_debug) {
        std::cout << "\n";
    }

    // collect all property keys except merged ones
    if (g_super_debug) {
        std::cout << "[+] EDRi: Adding new key for CSV header: ";
    }
    for (const auto& ev : events) {
        for (auto it = ev.begin(); it != ev.end(); ++it) {
            // skip already inserted keys
            if (std::find(all_keys.begin(), all_keys.end(), it.key()) != all_keys.end()) continue;

			// or insert new key
            all_keys.push_back(it.key());
            if (g_super_debug) {
                std::cout << it.key() << ", ";
            }
        }
    }
    if (g_super_debug) {
        std::cout << "\n";
    }

    // add header to csv_output
    for (size_t i = 0; i < all_keys.size(); ++i) {
        csv_output << all_keys[i];
        if (i + 1 < all_keys.size()) csv_output << ","; // only add comma if not last value
    }
    csv_output << "\n";

    int num_events_final = 0;

    // print each event as a row
    // TODO SORT BY TIMESTAMP??
    for (const auto& ev : events) {
        // traverse keys IN ORDER OF CSV HEADER
		// i.e. given: key from csv, check: if event has it, add value, else skip (add "")
        for (size_t i = 0; i < all_keys.size(); ++i) {
			const auto& key = all_keys[i];
            // check if this event has a value for this key
            if (ev.contains(key)) {
                csv_output << normalized_value(ev, key);
            }
            // else print "" to skip it
            else {
                csv_output << "";
            }
			if (i + 1 < all_keys.size()) csv_output << ","; // only add comma if not last value
        }
        csv_output << "\n";
        num_events_final++;
    }
	return csv_output.str();
}

int main(int argc, char* argv[]) {
    cxxopts::Options options("EDRi", "EDR Introspection Framework");
    
    // PARSER OPTIONS
    options.add_options()
        ("c,encrypt", "The path of the attack executable to encrypt", cxxopts::value<std::string>())
        ("e,edr", "The EDR to track, supporting: " + get_available_edrs(), cxxopts::value<std::string>())
        ("o,output", "The Path of the all-events.csv, default " + all_events_output_default, cxxopts::value<std::string>())
        ("a,attack-exe", "The path of the encrypted attack exe to execute", cxxopts::value<std::string>())
        ("r,run-as-child", "If the attack should run (automatically) as a child of the EDRi.exe or if it should be executed manually")
        ("m,trace-etw-misc", "Trace misc ETW")
        ("i,trace-etw-ti", "Trace ETW-TI (needs PPL)")
        ("n,hook-ntdll", "Hook ntdll.dll (needs PPL)")
        ("t,track-all", "Trace misc ETW, ETW-TI and hooks ntdll.dll")
        ("d,debug", "Print debug info")
        ("v,verbose-debug", "Print very verbose debug info")
        ("h,help", "Print usage");

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
        xor_file(in_path, attack_exe_enc_path);
        std::cout << "[*] EDRi: XOR encrypted " << in_path << " to " << attack_exe_enc_path << "\n";
        exit(0);
    }
    if (result.count("help") || result.count("edr") == 0) {
        std::cout << options.help() << "\n";
        return 0;
    }

    // check edr profile, output, and attack exe
	std::string edr_name = result["edr"].as<std::string>();
    std::vector<std::string> edr_specific_exes = edr_profiles.at(edr_name);

    std::string output;
    if (result.count("output") == 0) {
        output = all_events_output_default;
    }
    else {
        output = result["output"].as<std::string>();
    }
    std::cout << "[*] EDRi: Writing events to: " << output << "\n";

	bool run_as_child = false;
    if (result.count("attack-exe") > 0) {
		attack_exe_enc_path = result["attack-exe"].as<std::string>();
		std::cout << "[*] EDRi: Using non-default attack exe: " << attack_exe_enc_path << "\n";
    }
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

    // debug
    if (result.count("debug") > 0) {
        g_debug = true;
    }
    if (result.count("verbose-debug") > 0) {
        g_debug = true;
        g_super_debug = true;
	}

    // TRACKING PREPARATION
    TraceLoggingRegister(g_hProvider);
    std::cout << "[+] EDRi: Own provider registered\n";

    std::vector<HANDLE> threads;
    if (hook_ntdll) {
        // TODO
    }
    if (trace_etw_ti) {
        if (!start_etw_ti_trace(threads)) {
            std::cerr << "[!] EDRi: Failed to start ETW-TI traces\n";
            exit(1);
        }
    }
    if (trace_etw_misc) {
        if (!start_etw_misc_traces(threads)) {
            std::cerr << "[!] EDRi: Failed to start misc ETW traces(s)\n";
            exit(1);
        }
    }
    if (!start_etw_default_traces(threads)) {
        std::cerr << "[!] EDRi: Failed to start default ETW traces(s)\n";
        exit(1);
	}

    std::cout << "[*] EDRi: Get running procs\n";
    snapshot_procs();
    for (auto& e : exes_to_track) {
        int pid = get_PID_by_name(e);
        if (pid != -1) {
            std::cout << "[+] EDRi: Got pid for " << e << ":" << pid << "\n";
            g_tracking_PIDs.push_back(pid);
        }
    }
    for (auto& e : edr_specific_exes) {
        int pid = get_PID_by_name(e);
        if (pid != -1) {
            std::cout << "[+] EDRi: Got pid for " << e << ":" << pid << "\n";
            g_tracking_PIDs.push_back(pid);
        }
    }

    Sleep(wait_after_traces_started_ms);
    std::cout << "[*] EDRi: Waiting until start marker is registered\n";
	while (!g_traces_started) {
        emit_etw_event(EDRi_TRACE_START_MARKER, false);
		Sleep(wait_time_between_start_markers_ms);
	}
	std::cout << "[*] EDRi: Trace started\n";

    // ATTACK
	// decrypt the attack exe
	emit_etw_event("[<] Before decrypting the attack exe", true);
    if (xor_file(attack_exe_enc_path, attack_exe_path)) {
        std::cout << "[*] EDRi: Decrypted the attack exe: " << attack_exe_path << "\n";
    }
    else {
        std::cerr << "[!] EDRi: Failed to decrypt the attack exe: " << attack_exe_enc_path << "\n";
        stop_all_etw_traces();
        return 1;
    }
    emit_etw_event("[>]  After decrypting the attack exe", true);
    Sleep(wait_between_events_ms);

    // start the attack
    emit_etw_event("[<] Before executing the attack exe", true);
    Sleep(wait_between_events_ms);
    if (run_as_child) {
        if (!launch_as_child(attack_exe_path)) {
            std::cerr << "[!] EDRi: Failed to launch the attack exe: " << attack_exe_path << "\n";
            stop_all_etw_traces();
            return 1;
        }
    }
    else {
        std::cout << "[*] EDRi: Execute " << attack_exe_path << " now manually\n";
		int cnt_waited = 0;
        while (g_attack_PID == 0) {
            Sleep(100);
            cnt_waited += 100;
            if (cnt_waited > 20000) {
                std::cerr << "[!] EDRi: Timeout waiting for attack PID, did you start the " << attack_exe_path << "?\n";
                stop_all_etw_traces();
				return 1;
            }
        }
    }
	emit_etw_event("[>]  After executing the attack exe", true);

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
        CloseHandle(h);
    }
    threads.clear();

    print_etw_counts();
    std::map<Classifier, std::vector<json>> all_events = get_events();
    for (auto& c : all_events) {
        std::vector<json>& events = all_events[c.first];
        std::string csv_output = create_timeline_csv(events);
		std::string output_base = output.substr(0, output.find_last_of('.')); // without .csv
		std::string output_final = output_base + "-" + get_classifier_name(c.first) + ".csv"; // add classifier to filename
        std::ofstream out(output_final);
        out << csv_output;
        out.close();
	}

    std::cout << "[*] EDRi: Done\n";
	return 0;
}