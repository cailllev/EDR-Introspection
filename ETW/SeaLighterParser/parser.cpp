#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <set>
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

// Output all events as a sparse CSV timeline
void output_timeline_csv(const std::vector<Event>& events) {
    // collect all property keys
    std::set<std::string> all_keys;
    for (const auto& ev : events) {
        for (auto it = ev.properties.begin(); it != ev.properties.end(); ++it) {
            all_keys.insert(it.key());
        }
    }

    // print CSV header
    std::cout << "timestamp,event_id,task_name,PID,PPID,Message,Command Line,FilePath,VName,Sig Seq,Sig Sha";
    for (const auto& key : all_keys) {
        std::cout << "," << key;
    }
    std::cout << "\n";

    // print each event as a row
    for (const auto& ev : events) {
        // timestamp: try header["timestamp"], fallback to ""
        if (ev.header.contains("timestamp")) {
            std::cout << "\"" << ev.header["timestamp"].get<std::string>() << "\",";
        } else {
            std::cout << ",";
        }
        std::cout << ev.header.value("event_id", -1) << ",";
        std::cout << "\"" << ev.header.value("task_name", "") << "\"";

        // Properties
        for (const auto& key : all_keys) {
            std::cout << ",";
            if (ev.properties.contains(key)) {
                // Quote string values, else dump as is
                if (ev.properties[key].is_string()) {
                    std::cout << "\"" << ev.properties[key].get<std::string>() << "\"";
                } else {
                    std::cout << ev.properties[key].dump();
                }
            } else {
                std::cout << "";
            }
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
