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

#include "cxxopts.hpp"
#include "json.hpp"
#include "globals.h"
#include "utils.h"
#include "etwreader.h"
#include "manager.h"

/*
- creates krabs ETW traces for Antimalware, Kernel, etc. and the attack provider
- invokes the attack
- then transforms all captured events into a "filtered" csv, ready for Timeline Explorer
*/

// PID logic:
int g_EDR_PID = 0;  // is set with get_PID_by_name
int g_attack_PID = 0;  // is set with the incoming ETW events
int g_injected_PID = 0;  // is set with the incoming ETW events

// currently running processes
std::map<int, std::string> g_running_procs;

// more debug info
bool g_debug = false;
bool g_super_debug = false;

// translate device paths to drive letters
std::string translate_if_path(const std::string& s) {
    std::vector<std::string> to_replace = { "\\Device\\HarddiskVolume4\\", "\\\\?\\C:\\" };
    std::string replacement = "C:\\";
	std::string s2 = s;
    for (const auto& tr : to_replace) {
        size_t idx = s.find(tr);
        if (idx != std::string::npos) {
            s2 = s2.substr(0, idx) + replacement + s2.substr(idx + tr.length());
            if (g_debug) {
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
    for (const auto& k : csv_header_start) {
        all_keys.push_back(k);
        if (g_debug) {
			std::cout << "[+] EDRi: Added predefined key for CSV header: " << k << "\n";
        }
    }

    // collect all property keys except merged ones
    for (const auto& ev : events) {
        for (auto it = ev.begin(); it != ev.end(); ++it) {
            // skip already inserted keys
            if (std::find(all_keys.begin(), all_keys.end(), it.key()) != all_keys.end()) continue;

			// or insert new key
            all_keys.push_back(it.key());
            if (g_debug) {
                std::cout << "[+] EDRi: Added new key for CSV header: " << it.key() << "\n";
            }
        }
    }

    // add header to csv_output
    for (const auto& key : all_keys) {
        csv_output << key << ",";
    }
    csv_output.seekp(-1, std::ios_base::end); // remove the last ","
    csv_output << "\n";

    int num_events_final = 0;

    // print each event as a row
    for (const auto& ev : events) {
		int num_keys_added = 0; // all rows must have the same number of columns (commas)

        // traverse keys IN ORDER OF CSV HEADER
		// i.e. given: key from csv, check: if event has it, add value, else skip (add "")
        for (const auto& key : all_keys) {
            // check if this event has a value for this key
            if (ev.contains(key)) {
                csv_output << normalized_value(ev, key);
                num_keys_added++;
            }
            // else print "" to skip it
            else {
                csv_output << "";
            }
            csv_output << ",";
        }

		// print missing commas if some keys were not printed
        for (int i = num_keys_added; i < all_keys.size(); i++) {
            csv_output << ",";
		}
        csv_output.seekp(-1, std::ios_base::end); // remove the last ","
        csv_output << "\n";
        num_events_final++;
    }
	return csv_output.str();
}

int main(int argc, char* argv[]) {
    cxxopts::Options options("EDRi", "EDR Introspection Framework");

    options.add_options()
        ("e,exe", "EDR Executable Name", cxxopts::value<std::string>())
        ("o,output", "The Path of the all-events.csv, default " + all_events_output_default, cxxopts::value<std::string>())
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
    std::string output;
    if (result.count("o") == 0) {
        output = all_events_output_default;
    }
    else {
        output = result["output"].as<std::string>();
	}
	std::cout << "[*] EDRi: Writing events to: " << output << "\n";

    if (result.count("help") || result.count("e") == 0) {
        std::cout << options.help() << "\n";
        return 0;
    }
	std::string exe_name = result["exe"].as<std::string>();

    if (result.count("debug") > 0) {
        g_debug = true;
    }
    if (result.count("verbose-debug") > 0) {
        g_debug = true;
        g_super_debug = true;
	}

    // PREPARATION
    g_running_procs = snapshot_procs();
    g_EDR_PID = get_PID_by_name(g_running_procs, exe_name);
    if (g_EDR_PID == 0) {
        std::cerr << "[!] EDRi: Unable to find PID for: " << exe_name;
        exit(1);
    }
    std::cerr << "[*] EDRi: Got PID for " << exe_name << ": " << g_EDR_PID << "\n";

    // TODO unencrypt attack exe and store to disk

    // TRACKING
    std::vector<HANDLE> threads;
    if (!start_etw_reader(threads)) { // try to start trace
        exit(1);
    }
	// wait untiil g_trace_running is true
	while (!g_trace_running) {
		Sleep(10);
	}
	std::cout << "[*] EDRi: Trace started, ready for attack\n";

    // start the attack via explorer (breaks process tree)
    std::string command = "explorer.exe \"" + attack_exe_path + "\"";
	std::cout << "[*] EDRi: Starting attack: " << command << "\n";
	system(command.c_str());

	// wait until the attack and injection is done, i.e. event_id 73 with "Termination"
    // TODO non defender "attack done" filter
    std::cout << "[+] EDRi: Waiting for attack to finish...\n";
    while (!g_attack_done) {
        Sleep(100);
	}
    std::cout << "[+] EDRi: Waiting for any final events...\n";
    Sleep(2000);

    std::cout << "[*] EDRi: Stopping traces\n";
    stop_etw_reader();
    DWORD res = WaitForMultipleObjects((DWORD)threads.size(), threads.data(), TRUE, INFINITE);
    if (res == WAIT_FAILED) {
        std::cout << "[!] EDRi: Wait failed";
    }
    std::cout << "[*] EDRi: All " << threads.size() << " threads finished\n";

    std::vector<json> events = get_events();
    std::string csv_output = create_timeline_csv(events);
	std::ofstream out(output);
	out << csv_output;
	out.close();

    if (g_super_debug) {
        std::vector<json> events_unfiltered = get_events_unfiltered();
        std::string csv_output_unfiltered = create_timeline_csv(events_unfiltered);
        std::string output_unfiltered = output.substr(0, output.find_last_of('.')) + "-unfiltered.csv";
        std::ofstream out2(output_unfiltered);
        out2 << csv_output_unfiltered;
        out2.close();
	}

    std::cout << "[*] EDRi: Done\n";
	return 0;
}