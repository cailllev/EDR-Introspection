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
#include <windows.h>
#include <tlhelp32.h> // import after windows.h, else all breaks, that's crazy, yo
#include <wchar.h>

#include "cxxopts.hpp"
#include "json.hpp"
#include "etwreader.h"
#include "globals.h"
#include "parser.h"

/*
- creates krabs ETW traces for Antimalware, Kernel, etc. and the attack provider
- invokes the attack
- then transforms all captured events into a "filtered" csv, ready for Timeline Explorer
*/

// PID of the EDR process, used to filter the ETW Antimalware provider
int g_EDR_PID = 0;


// translate device paths to drive letters
std::string translate_if_path(const std::string& s) {
    std::string to_replace = "\\Device\\HarddiskVolume4\\";
    std::string replacement = "C:\\";
    size_t idx = s.find(to_replace);
    if (idx != std::string::npos) {
        return s.substr(0, idx) + replacement + s.substr(idx + to_replace.length());
    }
    return s;
}

// todo quoting errors with Timeline Explorer
void print_value(json ev, std::string key) {
    if (ev[key].is_string()) {
        std::string s = ev[key].get<std::string>();
        s = translate_if_path(s);
        std::replace(s.begin(), s.end(), '"', '\'');
        std::cout << "\"" << s << "\"";
    }
    else {
        std::cout << ev[key].dump();
    }
}


// output all events as a sparse CSV timeline with merged PPID and FilePath
void output_timeline_csv(const std::vector<json>& events) {
    std::vector<std::string> all_keys;
    for (const auto& k : csv_header_start) {
        all_keys.push_back(k);
    }

    // TODO: Timeline Explorer: "name" not allowed?
    // collect all property keys except merged ones, set automatically rejects duplicates
    for (const auto& ev : events) {
        for (auto it = ev.begin(); it != ev.end(); ++it) {
            // skip merged keys
            if (std::find(ppid_keys.begin(), ppid_keys.end(), it.key()) != ppid_keys.end()) continue;
            if (std::find(filepath_keys.begin(), filepath_keys.end(), it.key()) != filepath_keys.end()) continue;

            // skip already inserted keys
            if (std::find(all_keys.begin(), all_keys.end(), it.key()) != all_keys.end()) continue;

            // insert if it does not exists yet
            all_keys.push_back(it.key());
        }
    }

    // print CSV header
    for (const auto& key : all_keys) {
        std::cout << key << ",";
    }
    std::cout << "\n";

    // print each event as a row
    for (const auto& ev : events) {
        // traverse keys in order of csv header, print "" if the current event does not have this key
        for (const auto& key : all_keys) {
			// check if the key (from the csv header, not the event) is a merged key
			bool is_merged_key = false;
            for (const auto& cat : key_categories_to_merge) {
                // example: PPID (this is a merged key, there are no other keys like Parent PID, ... in the header)
                if (std::find(cat.begin(), cat.end(), key) != cat.end()) {
                    for (auto& it : ev.items()) { // get the original key from the EVENT, not CSV HEADER
                        if (std::find(cat.begin(), cat.end(), it.key()) != cat.end()) {
                            print_value(ev, it.key());
                            is_merged_key = true;
                            break;
                        }
                    }
                }
				if (is_merged_key) break; // no need to check other categories
            }
			if (is_merged_key) break; // no need to check the rest of the csv header keys

            // else check if this event has a value for this key
            if (ev.contains(key)) {
                print_value(ev, key);
            }

            // else print "" to skip it
            else {
                std::cout << "";
            }
            std::cout << ",";
        }
        std::cout << "\n";
    }
}

// https://stackoverflow.com/questions/14265581/parse-split-a-string-in-c-using-string-delimiter-standard-c#answer-46931770
std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss(s);
    std::string item;

    while (getline(ss, item, delim)) {
        result.push_back(item);
    }
    return result;
}

int get_PID_by_name(std::string exe_name) {
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &pe)) {
        while (Process32Next(snapshot, &pe)) {
            if (wcscmp(pe.szExeFile, std::wstring(exe_name.begin(), exe_name.end()).c_str()) == 0) {
                return pe.th32ProcessID;
            }
        }
    }
    std::cerr << "[!] EDRi: Unable to find PID for: " << exe_name;
    exit(1);
}

int main(int argc, char* argv[]) {
    cxxopts::Options options("EDRi", "EDR Introspection Framework");

    options.add_options()
        ("e,exe", "EDR Executable Name", cxxopts::value<std::string>())
        ("o,output", "The Path of the all-events.csv, default " + all_events_output_default, cxxopts::value<std::string>())
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

    std::string output;
    if (result.count("m") == 0) {
        output = all_events_output_default;
    }
    else {
        output = result["output"].as<std::string>();
	}
	std::cout << "[*] EDRi: Writing merged events to: " << output << "\n";

    if (result.count("help") || result.count("e") == 0) {
        std::cout << options.help() << "\n";
        return 0;
    }
	std::string exe_name = result["exe"].as<std::string>();

    g_EDR_PID = get_PID_by_name(exe_name);
    std::cerr << "[+] EDRi: Got PID for " << exe_name << ": " << g_EDR_PID << "\n";
    std::cout << "[*] EDRi: Start the attack when the 'Trace started' appears\n";

    std::vector<HANDLE> threads;
    if (!start_etw_reader(threads)) { // try to start trace
        exit(1);
    }
	// wait untiil g_trace_running is true
	while (!g_trace_running) {
		Sleep(10);
	}
	std::cout << "[*] EDRi: Trace started, ready for attack\n";
    std::cout << "[*] EDRi: Press ENTER after the attack is finished\n"; // todo invoke the attack here and observe?
    std::cin.get();

    std::vector<json> events = get_events();
    std::cout << "[*] EDRi: Stopping traces\n";
    stop_etw_reader();
    DWORD res = WaitForMultipleObjects((DWORD)threads.size(), threads.data(), TRUE, INFINITE);
    if (res == WAIT_FAILED) {
        std::cout << "[!] EDRi: Wait failed";
    }
    std::cout << "[*] EDRi: All " << threads.size() << " threads finished\n";

    //TODO write events to file
    output_timeline_csv(events);

    std::cout << "[*] EDRi: Done\n";
	return 0;
}