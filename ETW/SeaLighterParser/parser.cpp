#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <set>
#include <map>
#include <regex>
#include "json.hpp"

using json = nlohmann::json;

struct Event {
    json header;
    json properties;
    json property_types;
};

// Helper: load multiple JSON objects from a file
std::vector<Event> load_events(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        throw std::runtime_error("Could not open file: " + filename);
    }

    std::vector<Event> events;
    std::stringstream buffer;
    std::string line;
    int brace_count = 0;

    while (std::getline(file, line)) {
        for (char c : line) {
            if (c == '{') brace_count++;
            if (c == '}') brace_count--;
        }

        buffer << line << "\n";

        if (brace_count == 0 && !buffer.str().empty()) {
            try {
                json j = json::parse(buffer.str(), nullptr, true, true);
                Event ev{ j.value("header", json::object()),
                          j.value("properties", json::object()),
                          j.value("property_types", json::object()) };
                events.push_back(ev);
            }
            catch (...) {
                // std::cerr << "Error parsing partial JSON: " << e.what() << "\nBuffer was:\n" << buffer.str() << "\n";
            }
            buffer.str("");
            buffer.clear();
        }
    }
    return events;
}

// Group by event_id
void group_by_event_id(const std::vector<Event>& events) {
    struct Group {
        int count = 0;
        std::string event_name;
        std::string task_name;
        json first_properties;
    };

    std::unordered_map<int, Group> groups;

    for (const auto& ev : events) {
        int eid = ev.header.value("event_id", -1);
        auto& g = groups[eid];
        g.count++;
        if (g.count == 1) {
            g.event_name = ev.header.value("event_name", "");
            g.task_name = ev.header.value("task_name", "");
            g.first_properties = ev.properties;
        }
    }

    // sort groups by event_id
	std::vector<std::pair<int, Group>> sorted_groups(groups.begin(), groups.end());
    std::sort(sorted_groups.begin(), sorted_groups.end(),
		[](const auto& a, const auto& b) { return a.first < b.first; });

    for (auto it = sorted_groups.begin(); it != sorted_groups.end(); ++it) {
        int eid = it->first;
        auto& g = it->second;
        std::cout << "event_id=" << eid
            << " count=" << g.count
            << " event_name=\"" << g.event_name << "\""
            << " task_name=\"" << g.task_name << "\"\n"
            << " first_properties=" << g.first_properties.dump(2) << "\n\n";
    }
}

// Filter by event_id
void filter_by_event_id(const std::vector<Event>& events, int filter_id) {
    for (const auto& ev : events) {
        int eid = ev.header.value("event_id", -1);
        if (eid == filter_id) {
            std::cout << "event_id=" << eid
                << " task_name=\"" << ev.header.value("task_name", "") << "\"\n"
                << " properties=" << ev.properties.dump(2) << "\n\n";
        }
    }
}

// Filter by property key/value
void filter_by_property(const std::vector<Event>& events, const std::string& key, const std::string& value) {
    std::cout << "Filtering events with property \"" << key << "\" = \"" << value << "\"\n\n";
    for (const auto& ev : events) {
        if (ev.properties.contains(key) && ev.properties[key] == value) {
            int eid = ev.header.value("event_id", -1);
            std::cout << "event_id=" << eid
                << " task_name=\"" << ev.header.value("task_name", "") << "\"\n"
                << " properties=" << ev.properties.dump(2) << "\n\n";
        }
    }
}

// Filter by property key/value (int)
void filter_by_int_property(const std::vector<Event>& events, const std::string& key, const int value) {
    std::cout << "Filtering events with property \"" << key << "\" = \"" << value << "\"\n\n";
    for (const auto& ev : events) {
        if (ev.properties.contains(key) && ev.properties[key] == value) {
            int eid = ev.header.value("event_id", -1);
            std::cout << "event_id=" << eid
                << " task_name=\"" << ev.header.value("task_name", "") << "\"\n"
                << " properties=" << ev.properties.dump(2) << "\n\n";
        }
    }
}

// Helper: translate device paths to drive letters
std::string translate_if_path(const std::string& s) {
    std::string to_replace = "\\Device\\HarddiskVolume4\\";
    std::string replacement = "C:\\";
    int idx = s.find(to_replace);
    if (idx != std::string::npos) {
        return s.substr(0, idx) + replacement + s.substr(idx + to_replace.length());
    }
    return s;
}

// todo quoting errors with Timeline Explorer
void print_value(Event ev, std::string key) {
    if (ev.properties[key].is_string()) {
        std::string s = ev.properties[key].get<std::string>();
        s = translate_if_path(s);
        std::cout << "\"" << s << "\"";
    }
    else {
        std::cout << ev.properties[key].dump();
    }
}

// Output all events as a sparse CSV timeline with merged PPID and FilePath
void output_timeline_csv(const std::vector<Event>& events) {
    // Keys to merge for PPID and FilePath
    static const std::vector<std::string> ppid_keys = {
        "Parent PID", "TPID", "Target PID"
    };
    static const std::vector<std::string> filepath_keys = {
        "File Name", "File Path", "Process Image Path", "Name", "Reason Image Path"
    };

	// start of CSV header
    // TODO: "name" not allowed?
    std::vector<std::string> all_keys = { "timestamp","event_id","task_name","PID",
        "PPID","Message","Command Line","FilePath","VName","Sig Seq","Sig Sha"};

    // collect all property keys except merged ones, set automatically rejects duplicates
    for (const auto& ev : events) {
        for (auto it = ev.properties.begin(); it != ev.properties.end(); ++it) {
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

            // check if this event has a value for this key
            if (ev.properties.contains(key)) {
                print_value(ev, key);
            }
            // else check if the key is a merged key
            else if (std::find(ppid_keys.begin(), ppid_keys.end(), key) != ppid_keys.end()) {
                print_value(ev, key);
            }
            else if (std::find(filepath_keys.begin(), filepath_keys.end(), key) != filepath_keys.end()) {
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

// setup: 
// 1. Get-Process MsMpEng
// 2. adapt antimaleware-msmpeng.json with the PID from above
// 3. .\SeaLighter.exe .\anitmalware-msmpeng.json | Tee-Object antimalware-msmpeng.txt.utf16
// 4. execute .\Injector.exe in new window, as soon as output is visible from SeaLighter.exe
// 5. stop .\SeaLighter.exe after ~15 seconds
// 6. Get-Content antimalware-msmpeng.txt.utf16 | Out-File -FilePath antimalware-msmpeng.txt -Encoding utf8
// 7. .\parser.exe antimalware-msmpeng.txt group
// or .\parser.exe antimalware-msmpeng.txt toTimeline
int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage:\n"
            << argv[0] << " <file.json> group\n"
            << argv[0] << " <file.json> event <event_id>\n"
            << argv[0] << " <file.json> prop <key> <value>\n"
            << argv[0] << " <file.json> toTimeline\n";
        return 1;
    }

    std::string filename = argv[1];
    std::string mode = argv[2];

    try {
        auto events = load_events(filename);

        if (mode == "group") {
            group_by_event_id(events);
        }
        else if (mode == "event" && argc >= 4) {
            int eid = std::stoi(argv[3]);
            filter_by_event_id(events, eid);
        }
        else if (mode == "prop" && argc >= 5) {
            std::string key = argv[3];
            std::string value = argv[4];
            filter_by_property(events, key, value);
        }
        else if (mode == "propInt" && argc >= 5) {
            std::string key = argv[3];
            int value = std::stoi(argv[4]);
            filter_by_int_property(events, key, value);
        }
        else if (mode == "toTimeline") {
            output_timeline_csv(events);
        }
        else {
            std::cerr << "Invalid arguments.\n";
            return 1;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
