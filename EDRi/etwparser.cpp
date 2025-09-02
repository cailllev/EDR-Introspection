#include <krabs.hpp>
#include "helpers/json.hpp"
#include <iostream>

#include "utils.h"
#include "filter.h"
#include "profile.h"
#include "etwparser.h"


std::vector<json> etw_events;
std::vector<json> etw_events_unfiltered;
std::map<std::string, int> etw_events_counter;
std::map<std::string, int> etw_events_counter_unfiltered;

// keys to merge
MergeCategory ppid_keys = {
    "PPID",
    {"ParentPID"}
};
MergeCategory tpid_keys = {
    "TargetPID",
    {"TPID"}
};
MergeCategory filepath_keys = {
    FILEPATH,
    {"BasePath", "FileName", "filepath", "ImagePath", "ImageName", "Path", "Name", "ReasonImagePath"}
};
std::vector<MergeCategory> key_categories_to_merge = { ppid_keys, tpid_keys, filepath_keys };

// hand over schema for parsing
void my_event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        json ev = parse_my_etw_event(Event{ record, schema });
        count_event(ev, false);
        etw_events.push_back(ev);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] ETW: my_event_callback exception: " << e.what();
    }
    catch (...) {
        std::cerr << "[!] ETW: my_event_callback unknown exception";
    }
}

// pre-filter EDR events and hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        //std::cout << wchar2string(schema.provider_name()) << "\n";

        // convert it to json NOW or lose the property values
        json ev = parse_etw_event(Event{ record, schema });
        post_parsing_checks(ev);
        etw_events_unfiltered.push_back(ev);

        // check if event can be filtered out
        if (filter(ev)) {
            count_event(ev, true);
            if (g_super_debug) {
                std::cout << "[-] ETW: Filtered out event: " << ev.dump() << "\n";
            }
        }
        else {
            etw_events.push_back(ev);
            count_event(ev, false);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[!] ETW: event_callback exception: " << e.what();
    }
    catch (...) {
        std::cerr << "[!] ETW: event_callback unknown exception";
    }
}

// global filter for all etw providers
bool filter(json& ev) {
    if (ev[PROVIDER_NAME] == "Microsoft-Antimalware-Engine") {
        return filter_antimalware_etw(ev);
    }

    if (ev[PROVIDER_NAME] == "Microsoft-Windows-Kernel-Audit-API-Calls") {
        return filter_kernel_api_calls(ev);
    }

    if (g_super_debug) {
        std::cout << "[+] ETW: Unfiltered provider " << ev[PROVIDER_NAME] << ", not filtering event ID " << ev[EVENT_ID] << "\n";
    }
    return false; // do not filter unregistered providers
}

// filter events based on known exclude values (e.g. wrong PID for given event id)
bool filter_antimalware_etw(json& ev) {
    // events to remove
    if (std::find(event_ids_to_remove.begin(), event_ids_to_remove.end(), ev[EVENT_ID]) != event_ids_to_remove.end()) {
        return true;
    }

    // events to keep if PID matches
    if (std::find(event_ids_with_pid.begin(), event_ids_with_pid.end(), ev[EVENT_ID]) != event_ids_with_pid.end()) {
        return ev[PID] != g_attack_PID && ev[PID] != g_injected_PID;
    }

    // events to keep if PID or TargetPID matches
    if (std::find(event_ids_with_pid_or_tpid.begin(), event_ids_with_pid_or_tpid.end(), ev[EVENT_ID]) != event_ids_with_pid_or_tpid.end()) {
        if (ev.contains("TargetPID")) {
            return ev[PID] != g_attack_PID && ev[PID] != g_injected_PID && ev["TargetPID"] != g_attack_PID && ev["TargetPID"] != g_injected_PID;
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing TargetPID field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    // events to keep if PID in Data matches
    if (std::find(event_ids_with_pid_in_data.begin(), event_ids_with_pid_in_data.end(), ev[EVENT_ID]) != event_ids_with_pid_in_data.end()) {
        if (ev.contains("Data")) {
            return ev["Data"] != g_attack_PID && ev["Data"] != g_injected_PID;
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing Data field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    // events to keep if Message contains filter string (case insensitive)
    if (std::find(event_ids_with_message.begin(), event_ids_with_message.end(), ev[EVENT_ID]) != event_ids_with_message.end()) {
        if (ev.contains("Message")) {
            std::string msg = ev["Message"].get<std::string>();
            std::transform(msg.begin(), msg.end(), msg.begin(), [](unsigned char c) { return std::tolower(c); });
            if (msg.find("injector.exe") != std::string::npos ||
                msg.find("microsoft.windowsnotepad") != std::string::npos ||
                msg.find("microsoft.windowscalculator") != std::string::npos) {
                return false; // do not filter if any of the strings match
            }
            return true; // else filter out
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing Message field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    // events to keep if filepath matches
    if (std::find(event_ids_with_filepath.begin(), event_ids_with_filepath.end(), ev[EVENT_ID]) != event_ids_with_filepath.end()) {
        if (ev.contains("FilePath")) {
            return std::strcmp(ev["FilePath"].get<std::string>().c_str(), attack_exe_path.c_str());
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing FilePath field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    return false; // do not filter unregistered event ids
}

// filter kernel api calls on known exclude values (e.g. VBoxService.exe)
bool filter_kernel_api_calls(json& ev) {
    if (ev[EVENT_ID] == 5) {
        return std::find(excluded_procs.begin(), excluded_procs.end(), ev[EXE]) != excluded_procs.end();
    }

    return false; // keep the rest
}

// parses attack events
json parse_my_etw_event(Event e) {
    krabs::parser parser(e.schema);
    json j;

    try {
        j[TYPE] = "Custom";
        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
        );
        j[PID] = e.record.EventHeader.ProcessId;
        j[PROVIDER_NAME] = wchar2string(e.schema.provider_name());
        j[EVENT_ID] = 13337;

        // get exe name
        if (g_running_procs.find(j[PID]) == g_running_procs.end()) {
            if (g_debug) {
                std::cout << "[!] ETW: Warning: PID " << j[PID] << " not found in running procs\n";
            }
            j[EXE] = "<not found>";
        }
        else {
            j[EXE] = g_running_procs[j[PID]];
        }

        std::string msg;
        if (parser.try_parse(L"message", msg)) {
            j[TASK] = std::string(msg.begin(), msg.end());
        }
        else {
            j[TASK] = "(no message field)";
            std::cout << "[*] ETW: Warning: Custom event missing Message field " << j.dump() << "\n";
        }

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: Custom Trace Exception: " << ex.what() << "\n";
        return json();
    }
}

// parses all other ETW events
json parse_etw_event(Event e) {
    try {
        krabs::parser parser(e.schema);
        json j;

        j[TYPE] = "ETW";
        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
        );
        j[PID] = e.record.EventHeader.ProcessId;
        j[TID] = e.record.EventHeader.ThreadId;
        j[EVENT_ID] = e.schema.event_id(); // opcode is the same as event_id, sometimes just a different number
        j[PROVIDER_NAME] = wchar2string(e.schema.provider_name());

        // task = task_name + opcode_name
        std::wstring combined = std::wstring(e.schema.task_name()) + std::wstring(e.schema.opcode_name());
        j[TASK] = wstring2string(combined);
        std::string last_key;
        int last_type;

        // Iterate over all properties defined in the schema
        for (const auto& property : parser.properties()) {
            try {
                const std::wstring& property_name = property.name();
                const auto property_type = property.type();
                std::string key = wstring2string((std::wstring&)property_name);
                last_key = key;
                last_type = property_type;

                // check if it's a merged key --> write value to merged_key
                for (const auto& cat : key_categories_to_merge) {
                    if (std::find(cat.keys_to_merge.begin(), cat.keys_to_merge.end(), key) != cat.keys_to_merge.end()) {
                        std::string old_key = key;
                        key = cat.merged_key;
                        if (j.contains(key)) {
                            std::cerr << "[!] ETW: Warning: Event ID " << j[EVENT_ID] << ", old key " << old_key << ", overwriting existing " << key << ":" << j[key] << "\n";
                        }
                    }
                }

                // Special cases
                if (property_name == L"ProtectionMask" || property_name == L"LastProtectionMask") {
                    uint32_t protection_mask = parser.parse<uint32_t>(property_name);
                    j[key] = get_memory_region_protect(protection_mask);
                    continue;
                }

                switch (property_type) {

                case TDH_INTYPE_UNICODESTRING:
                {
                    std::wstringstream wss;
                    wss << parser.parse<std::wstring>(property_name);
                    std::string s = wstring2string((std::wstring&)wss.str());
                    j[key] = s;
                    break;
                }

                case TDH_INTYPE_ANSISTRING:
                    j[key] = parser.parse<std::string>(property_name);
                    break;
                case TDH_INTYPE_INT8:
                    j[key] = (int32_t)parser.parse<CHAR>(property_name);
                    break;
                case TDH_INTYPE_UINT8:
                    j[key] = (uint32_t)parser.parse<UCHAR>(property_name);
                    break;
                case TDH_INTYPE_INT16: 
                    j[key] = (int32_t)parser.parse<SHORT>(property_name);
                    break;
                case TDH_INTYPE_UINT16:
                    j[key] = (int32_t)parser.parse<USHORT>(property_name);
                    break;
                case TDH_INTYPE_UINT32:
                    j[key] = (uint32_t)parser.parse<uint32_t>(property_name);
                    break;
                case TDH_INTYPE_UINT64:
                    j[key] = (uint64_t)parser.parse<uint64_t>(property_name);
                    break;
                case TDH_INTYPE_BOOLEAN:
                    j[key] = (bool)parser.parse<BOOL>(property_name);
                    break;
                case TDH_INTYPE_POINTER:
                    j[key] = (uint64_t)parser.parse<PVOID>(property_name);
                    break;
                
                case TDH_INTYPE_FILETIME:
                {
                    FILETIME fileTime = parser.parse<FILETIME>(property_name);
                    ULARGE_INTEGER uli;
                    uli.LowPart = fileTime.dwLowDateTime;
                    uli.HighPart = fileTime.dwHighDateTime;
                    j[key] = uli.QuadPart;
                    break;
                }

                case TDH_INTYPE_SID:
                {
                    std::vector<uint8_t> raw;
                    if (parser.try_parse(property_name, raw)) {
                        // try to convert raw bytes to a SID string
                        if (!raw.empty() && IsValidSid((PSID)raw.data())) {
                            LPWSTR sidString = nullptr;
                            if (ConvertSidToStringSidW((PSID)raw.data(), &sidString)) {
                                std::wstring ws(sidString);
                                j[key] = wstring2string(ws);
                                LocalFree(sidString);
                            }
                            else {
                                j[key] = "invalid_sid";
                            }
                        }
                        else {
                            // fallback: output raw data as hex
                            std::ostringstream oss;
                            oss << "0x";
                            for (auto b : raw) {
                                oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
                            }
                            j[key] = oss.str();
                        }
                    }
                    else {
                        // parsing failed, fallback: empty hex
                        j[key] = "0x";
                    }
                    break;
                }

                case TDH_INTYPE_HEXINT32:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint32_t>(property_name);
                    j[key] = oss.str();
                    break;
                }

                case TDH_INTYPE_HEXINT64:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint64_t>(property_name);
                    j[key] = oss.str();
                    break;
                }

                default:
                    std::cout << "[*] ETW: Warning: Unsupported property type " << property_type << " for " << j[TASK] << "'s " << key << "\n";
                    j[key] = "unsupported";
                    break;
                }

            }
            catch (const std::exception& ex) {
                std::cerr << 
                    "[!] ETW: Failed to parse " << j[TASK] << 
                    ", key: " << last_key << 
                    ", type: " << last_type <<
                    ", error: " << ex.what() << "\n";
            }
        }

        // add a newly spawned procs to process map
        if (j[EVENT_ID] == PROC_START_EVENT_ID) {
            std::string exe_path = j[FILEPATH].get<std::string>();
            g_running_procs[j[PID]] = exe_path.substr(exe_path.find_last_of("\\") + 1);
        }

        // check if process is listed in running procs
        if (g_running_procs.find(j[PID]) == g_running_procs.end()) {
            if (g_debug) {
                std::cout << "[-] ETW: Warning: Name of PID " << j[PID] << " not found\n";
            }
            j[EXE] = "<not found>";
        }
        else {
            j[EXE] = g_running_procs[j[PID]];
        }

        // callstack
        try {
            j["stack_trace"] = json::array();
            int idx = 0;
            for (auto& return_address : e.schema.stack_trace())
            {
                // Only add non-kernelspace addresses
                if (return_address < 0xFFFF080000000000) {
                    j["stack_trace"].push_back({
                        { "addr", return_address},
                        { "idx", idx }
                        });
                    idx++;
                }
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "[!] ETW: Failed to parse " << j[TASK] << "'s call stack: " << ex.what() << "\n";
        }

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: General Exception: " << ex.what() << "\n";
        return json();
    }
}


// monitors events, sets started and ended flags, attack and injected PID
void post_parsing_checks(json& j) {
    // checks if the trace started
    edr_profile_check_start(j);

    // checks if the attack is done
    edr_profile_check_end(j);

    // check if the attack_PID and injected_PID can be set, TODO etw independent way?
    if (g_attack_PID == 0 && j[EVENT_ID] == PROC_START_EVENT_ID) {
        if (j.contains(FILEPATH) && j[FILEPATH] == attack_exe_path) {
            g_attack_PID = j[PID];
            std::cout << "[+] ETW: Got attack PID: " << g_attack_PID << "\n";
        }
    }
    if (g_injected_PID == 0 && j[EVENT_ID] == PROC_START_EVENT_ID) {
        if (j.contains(FILEPATH) && j[FILEPATH] == injected_exe_path) {
            g_injected_PID = j[PID];
            std::cout << "[+] ETW: Got injected PID: " << g_injected_PID << "\n";
        }
    }
}

std::vector<json> get_events() {
    std::cout << "[+] ETW: Got " << etw_events.size() << " filtered events\n";
    return etw_events;
}

std::vector<json> get_events_unfiltered() {
    std::cout << "[+] ETW: Got " << etw_events_unfiltered.size() << " unfiltered events\n";
    return etw_events_unfiltered;
}

void count_event(json ev, bool unfiltered) {
    std::map<std::string, int>& m = unfiltered ? ::etw_events_counter_unfiltered : ::etw_events_counter;

    if (m.find(ev[PROVIDER_NAME]) == m.end()) {
        m[ev[PROVIDER_NAME]] = 1;
    }
    else {
        m[ev[PROVIDER_NAME]]++;
    }
}

void print_etw_counts() {
    std::ostringstream oss;
    for (auto it = etw_events_counter.begin(); it != etw_events_counter.end(); ++it) {
        oss << it->first << "=" << it->second << ",";
    }
    std::cout << "[*] ETW: Filtered events per provider: " << oss.str() << "\n";
    oss.str("");
    for (auto it = etw_events_counter_unfiltered.begin(); it != etw_events_counter_unfiltered.end(); ++it) {
        oss << it->first << "=" << it->second << ",";
    }
    std::cout << "[*] ETW: Filtered out events per provider: " << oss.str() << "\n";
}