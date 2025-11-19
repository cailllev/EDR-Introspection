#include <iostream>
#include <fstream>
#include <map>
#include <regex>
#include <string>
#include <vector>

#include "helpers/json.hpp"

#include "globals.h"
#include "utils.h"
#include "output.h"


// ------------------- CSV IMPLEMENTATION ------------------- //
static const std::string COLOR_HEADER = ",Color";
static const std::string COLOR_GREEN = ",green";
static const std::string COLOR_RED = ",red";
static const std::string COLOR_BLUE = ",blue";
static const std::string COLOR_PURPLE = ",purple";
static const std::string COLOR_YELLOW = ",yellow";
static const std::string COLOR_GRAY = ",gray";

static std::unordered_map<std::string, std::string> g_deviceMap;

// define start of CSV header, all other keys are added in order of occurence later
std::vector<std::string> csv_header_start = {
    TIMESTAMP_SYS, TIMESTAMP_ETW, TYPE, PROVIDER_NAME, EVENT_ID, TASK, PID, TID, PPID, ORIGINATING_PID, TARGET_PID, TARGET_TID, MESSAGE,
    FILEPATH, "cachename", "result", "vname", "name", "sigseq", "sigsha", "commandline", "firstparam", "secondparam",
};

// store translations like \\Device\\HarddiskVolumeX -> C:
void build_device_map() {
    if (!g_deviceMap.empty()) return; // build only once

    WCHAR drives[512];
    DWORD len = GetLogicalDriveStringsW(512, drives);
    if (!len) return;

    for (WCHAR* d = drives; *d; d += wcslen(d) + 1) {
        // drive like L"C:\\"
        std::wstring driveW(d, 2); // just "C:"
        WCHAR target[MAX_PATH];
        if (QueryDosDeviceW(driveW.c_str(), target, MAX_PATH)) {
            std::wstring targetW(target);
            // store as UTF-8
            std::string drive = wstring2string(driveW); // "C:"
            std::string ntpath = wstring2string(targetW); // "\Device\HarddiskVolume3"
            g_deviceMap[ntpath] = drive + "\\"; // "C:\"
        }
    }
}

// translate any path in string
std::string translate_if_path(const std::string& s) {
    std::string s2 = s;

    // replace any \Device\HarddiskVolumeX\ with its actual drive letter
    for (const auto& m : g_deviceMap) {
        const std::string& nt = m.first;
        const std::string& drive = m.second;
        // build escaped regex like "\Device\HarddiskVolume3\"
        std::string pattern;
        for (char c : nt) {
            if (c == '\\') pattern += "\\\\";
            else pattern += c;
        }
        pattern += "\\\\"; // must end with slash

        std::regex r(pattern, std::regex_constants::icase);
        s2 = std::regex_replace(s2, r, drive);
    }

    // replace "\\?\X:\"  (any drive letter) with "X:\"
    static const std::regex extendedPrefix(R"(\\\\\?\\([A-Za-z]:)\\)",
        std::regex_constants::icase);
    s2 = std::regex_replace(s2, extendedPrefix, "$1\\\\");

	// finally replace any double backslashes with single backslashes
	static const std::regex doubleBackslash(R"(\\\\+)");
	s2 = std::regex_replace(s2, doubleBackslash, R"(\)");

    return s2;
}

std::string normalized_value(const json::iterator& it) {
    const json& val = it.value();
    if (val.is_string()) {
        std::string s = val.get<std::string>();
        s = translate_if_path(s);
        std::replace(s.begin(), s.end(), '"', '\'');
        return "\"" + s + "\"";
    }
    else {
        return val.dump();
    }
}

std::string add_color_info(const json& ev) {
    if (!ev.contains(PROVIDER_NAME)) {
        if (g_debug) {
            std::cout << "[-] Output: Warning: Event missing " << PROVIDER_NAME << " field: " << ev.dump() << "\n";
        }
        return COLOR_GRAY;
    }
    if (ev[PROVIDER_NAME] == EDRi_PROVIDER) {
        return COLOR_GREEN;
    }
    if (ev[PROVIDER_NAME] == ANTIMALWARE_PROVIDER) {
        return COLOR_BLUE;
    }
    if (ev[PROVIDER_NAME] == THREAT_INTEL_PROVIDER) {
        return COLOR_PURPLE;
    }
    if (ev[PROVIDER_NAME] == ATTACK_PROVIDER) {
        return COLOR_RED;
    }
    if (ev[PROVIDER_NAME] == HOOK_PROVIDER) {
        return COLOR_YELLOW;
    }
    return ""; // event / provider not mapped
}

// output all events as a sparse CSV timeline with merged PPID and FilePath
std::string create_timeline_csv(std::vector<json*>& events, std::vector<std::string> header_start, bool colored) {
    std::ostringstream csv_output;

    std::vector<std::string> all_keys;
    if (g_super_debug) {
        std::cout << "[+] Output: Adding predefined keys for CSV header: ";
    }
    for (const auto& k : header_start) {
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
        std::cout << "[+] Output: Adding new keys for CSV header: ";
    }
    for (const auto& ev : events) {
        for (auto it = ev->begin(); it != ev->end(); ++it) {
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
        if (i < all_keys.size() - 1) csv_output << ","; // add comma, except for last
    }
    if (colored) {
        csv_output << COLOR_HEADER; // add color info column
    }

    int c = 0;
    if (g_debug) {
        std::cout << "[+] Output: Transforming " << events.size() << " events to CSV: ";
    }
    // print each event as a row    
    for (auto& ev : events) {
        // traverse keys IN ORDER OF CSV HEADER
        // i.e. given: key from csv, check: if event has it, add value, else skip (add "")
        for (const auto& key : all_keys) {
            auto it = ev->find(key);
            if (it != ev->end()) {
                csv_output << normalized_value(it);
            }
            else {
                csv_output << ""; // add empty if key not in event
            }
            if (&key != &all_keys.back()) csv_output << ",";
        }
        if (colored) {
            csv_output << add_color_info((*ev));
        }
        if (g_debug && (c % 100 == 0)) {
            std::cout << c << ", ";
        }
        csv_output << "\n";
        c++;
    }
    if (g_debug) {
        std::cout << " done\n";
    }
    return csv_output.str();
}

void write_events_to_file(std::map<Classifier, std::vector<json*>>& etw_events, const std::string& output, bool colored) {
    for (auto& c : etw_events) {
        std::vector<json*>& events = etw_events[c.first];
        std::string classifier_name = classifier_names[c.first];
        try {
            // construct filename
            std::string output_base = output.substr(0, output.find_last_of('.')); // without .csv
            std::string output_final = output_base + "-" + classifier_name + ".csv"; // add classifier to filename
            
            if (g_debug) {
                std::cout << "[+] Output: Sorting " << events.size() << " events in " << classifier_name << "\n";
            }

            // sort events by timestamp
            std::sort(events.begin(), events.end(), [](const json* a, const json* b) {
                return a->at(TIMESTAMP_NS) < b->at(TIMESTAMP_NS); // all events must have a TIMESTAMP_NS field and be int, as by filter_all_events
                });

            if (g_debug) {
                std::cout << "[+] Output: Creating csv from events and writing to file " << output_final << "\n";
            }
            // create and save csv
            std::string csv_output = create_timeline_csv(events, csv_header_start, colored);
            std::ofstream out(output_final);
            std::string backup_path = "C:\\Users\\Public\\Downloads\\" + classifier_name + "-events.csv";

			if (!out.is_open()) { // check if normal path failed
                std::cerr << "[!] Output: Failed to open output file: " << output_final << ", trying backup: " << backup_path << "\n";
                out.open(backup_path);
            }
			if (!out.is_open()) { // backup failed too
                std::cerr << "[!] Output: Failed to open backup path: " << backup_path << ", dumping to console...\n";
				std::cout << csv_output;
				std::cout << "[!] Output: End of dumped events, press ENTER to continue\n";
				std::cin.get();
			}
			else { // normal or backup path succeeded --> write to file
                out << csv_output;
                out.close();
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "[!] Output: write_events_to_file exception: " << ex.what() << "\n";
        }
        catch (...) {
            std::cerr << "[!] Output: write_events_to_file unknown exception\n";
        }
    }
}

// ------------------- MISC stuff ------------------- //
// print count by provider by classification
void print_etw_counts(std::map<Classifier, std::vector<json*>>& etw_events) {
    for (auto& c : etw_events) {
        std::ostringstream oss;
        Classifier classifier = c.first;
        std::vector<json*>& events = c.second;

        // count by provider
        std::map<std::string, int> provider_counts;
        for (auto& ev : events) {
            try {
                std::string provider = "<empty provider>";
                if (ev->contains(PROVIDER_NAME)) {
                    provider = ev->at(PROVIDER_NAME);
                }
                if (provider_counts.find(provider) == provider_counts.end()) {
                    provider_counts[provider] = 1;
                }
                else {
                    provider_counts[provider]++;
                }
            }
            catch (const std::exception& ex) {
                std::cerr << "[!] Output: print_etw_counts exception: " << ex.what() << "\n";
            }
            catch (...) {
                std::cerr << "[!] Output: print_etw_counts unknown exception\n";
            }
        }

        for (auto it = provider_counts.begin(); it != provider_counts.end(); ++it) {
            if (it != provider_counts.begin()) {
                oss << ", ";
            }
            oss << it->first << ": " << it->second;
        }
        std::cout << "[*] Output: Classification " << classifier_names[c.first] << ": " << events.size() << " events.";
        std::cout << " Filtered events per provider > " << oss.str() << "\n";
    }
}

// print diffs between timestamp_sys and timestamp_etw per provider
void print_time_differences() {
    std::map<std::string, std::vector<UINT64>> time_diffs_ns = get_time_diffs();
    std::cout << std::fixed << std::setprecision(1); // set precision to one decimal place
    for (auto& c : time_diffs_ns) {
        std::vector<UINT64>& diffs = c.second;
        if (diffs.size() == 0) {
            continue;
        }
        double avg = (double)std::accumulate(diffs.begin(), diffs.end(), 0LL) / diffs.size() / 1000.0; // in mircoseconds
        double max = (double)*std::max_element(diffs.begin(), diffs.end()) / 1000.0; // in mircoseconds
        std::cout << "[+] Output: Time differences in microseconds for " << c.first << ": avg=" << avg << ", max=" << max << "\n";
    }
    std::cout.unsetf(std::ios::fixed); // revert precision
}

// dumps all relevant info from antimalware provider event id 3,8,74,104
void dump_signatures(std::map<Classifier, std::vector<json*>>& etw_events, std::string output_path) {
    std::vector<std::string> data = {};
	std::vector<std::string> yara_rules = {};
    for (const auto& ev : etw_events[Relevant]) {
        try {
            if (ev->contains(PROVIDER_NAME) && ev->at(PROVIDER_NAME) != ANTIMALWARE_PROVIDER) {
                continue; // only this provider contains the signatures
            }
            if (ev->contains(EVENT_ID) && ev->at(EVENT_ID) == 3) {
                if (!ev->contains(MESSAGE)) {
                    if (g_debug) {
                        std::cout << "[-] Output: Warning: Event with ID 3 missing " << MESSAGE << " field: " << ev->dump() << "\n";
                    }
                    continue;
                }
                std::string m = get_val((*ev), MESSAGE);
                std::string s = "signame=";
                std::string r = "resource=";
                size_t ss = m.find(s);
                size_t sr = m.find(r);
                if (ss != std::string::npos && sr != std::string::npos) { // only some id=3 events have signatures
                    size_t es = m.find(", ", ss);
                    size_t er = m.find(", ", sr);
                    ss += s.length();
                    sr += r.length();
                    std::string sig = m.substr(ss, es - ss);
                    std::string res = m.substr(sr, er - sr);
                    data.push_back("Found signal/signature: " + sig + " for " + translate_if_path(res));
                }
            }
            if (ev->contains(EVENT_ID) && ev->at(EVENT_ID) == 8) {
                if (!ev->contains(PID)) {
                    if (g_debug) {
                        std::cout << "[-] Output: Warning: Event with ID 8 missing " << PID << " field: " << ev->dump() << "\n";
                    }
                    continue;
                }
                if (!ev->contains(NAME)) {
                    if (g_debug) {
                        std::cout << "[-] Output: Warning: Event with ID 8 missing " << NAME << " field: " << ev->dump() << "\n";
                    }
                    continue;
                }
				std::string sig = get_val((*ev), NAME);
                data.push_back("Behaviour Monitoring Detection: pid=" + get_val((*ev), PID) + ", sig=" + sig);
                std::string rule = get_yara_rule(sig);
                if (!rule.empty()) {
                    yara_rules.push_back(rule);
				}
            }
            if (ev->contains(EVENT_ID) && ev->at(EVENT_ID) == 74) {
                std::ostringstream oss;
                oss << "Sense Remidiation" <<
                    ": threatname=" << get_val((*ev), THREATNAME) <<
                    ", signature=" << get_val((*ev), SIGSEQ) <<
                    ", sigsha=" << get_val((*ev), SIGSHA) <<
                    ", classification=" << get_val((*ev), CLASSIFICATION) <<
                    ", determination=" << get_val((*ev), DETERMINATION) <<
                    ", realpath=" << get_val((*ev), REALPATH) <<
                    ", resource=" << get_val((*ev), RESOURCESCHEMA);
                data.push_back(oss.str());
            }
            if (ev->contains(EVENT_ID) && ev->at(EVENT_ID) == 104) {
                if (!ev->contains(FIRST_PARAM) || !ev->contains(SECOND_PARAM)) {
                    if (g_debug) {
                        std::cout << "[-] Output: Warning: Event with ID 104 missing " << FIRST_PARAM << " or " << SECOND_PARAM << " field: " << ev->dump() << "\n";
                    }
                }
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "[!] Output: dump_signatures exception: " << ex.what() << "\n";
        }
    }

    std::ofstream out(output_path);
    if (!out.is_open()) {
        std::string backup_path = "C:\\Users\\Public\\Downloads\\signatures.txt";
        std::cerr << "[!] Output: Failed to open output file: " << output_path << ", trying backup: " << backup_path << "\n";
        out.open(backup_path);
        if (!out.is_open()) {
            std::cerr << "[!] Output: Failed to open backup output file: " << backup_path << ", printing to console instead\n";
        }
    }
    else {
        for (auto& d : data) {
            if (out.is_open()) {
                out << d << "\n";
            }
            std::cout << "[*] Output: " << d << "\n";
        }
    }

    if (yara_rules.empty()) {
        if (g_debug) {
            std::cout << "[-] Output: No matching YARA rules found from events\n";
        }
        return;
	}

	std::string yara_output_path = output_path + ".yara";
    out.open(yara_output_path);
    if (!out.is_open()) {
        std::string backup_path = "C:\\Users\\Public\\Downloads\\signatures.yara";
        std::cerr << "[!] Output: Failed to open output file: " << yara_output_path << ", trying backup: " << backup_path << "\n";
        out.open(backup_path);
        if (!out.is_open()) {
            std::cerr << "[!] Output: Failed to open backup output file: " << backup_path << ", printing to console instead\n";
        }
    }
    else {
        std::cout << "[*] Output: Printing YARA rules...\n";
        for (auto& d : yara_rules) {
            if (out.is_open()) {
                out << d << "\n";
            }
            std::cout << d << "\n";
        }
    }
}
