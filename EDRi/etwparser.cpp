#include <krabs.hpp>
#include "helpers/json.hpp"
#include <iostream>

#include "globals.h"
#include "utils.h"
#include "filter.h"
#include "profile.h"
#include "etwparser.h"


std::vector<json> etw_events;
std::vector<json> all_etw_events;
std::map<std::string, int> etw_events_counter;
std::map<std::string, int> all_etw_events_counter;

// globals
int g_attack_PID = 0;
int g_injected_PID = 0;
bool g_traces_started = false;
bool g_attack_terminated = false;

// keys that get merged together
MergeCategory ppid_keys = {
    "ppid",
    {"parentpid"}
};
MergeCategory tpid_keys = { // all refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_PID,
    {"processid", "tpid", "targetprocessid"} // TODO processid in kernel means tpid, processid in antimalware means pid (but only event 95 has this)
};
MergeCategory ttid_keys = { // both refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_TIP,
    {"targetthreadid", "ttid"}
};
MergeCategory filepath_keys = {
    FILEPATH,
    {"basepath", "filename", "imagepath", "imagename", "path", "name", "reasonimagepath"}
};
std::vector<MergeCategory> key_categories_to_merge = { ppid_keys, tpid_keys, ttid_keys, filepath_keys };

// pid fields that should have the exe name added at print time
static const std::vector<std::string> fields_to_add_exe_name = { PID, ppid_keys.merged_key, tpid_keys.merged_key, KERNEL_PID, ORIGINATING_PID };


// hand over schema for parsing
void my_event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        json ev = parse_my_etw_event(Event{ record, schema });
        post_my_parsing_checks(ev);
        add_exe_information(ev); // must be after all parsing checks and filtering but before adding it to events

        count_event(ev, false);
        etw_events.push_back(ev);
        all_etw_events.push_back(ev);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] ETW: my_event_callback exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cerr << "[!] ETW: my_event_callback unknown exception\n";
    }
}

// pre-filter EDR events and hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        json ev = parse_etw_event(Event{ record, schema });
        post_parsing_checks(ev);

        if (!g_traces_started) {
            if (g_super_debug) {
                std::cout << "[-] Waiting for EDRi start marker, ignoring early event: " << ev.dump() << "\n";
            }
        }

        // check if event can be filtered out
        bool filter_out = filter(ev); // TODO filter after all events captured?
        add_exe_information(ev); // must be after all parsing checks and filtering but before adding it to events
        if (!filter_out) {
            etw_events.push_back(ev);
        }
        else if (g_super_debug)  {
            std::cout << "[-] ETW: Filtered out event: " << ev.dump() << "\n";
        }
        count_event(ev, filter_out);
        all_etw_events.push_back(ev);
    }
    catch (const std::exception& e) {
        std::cerr << "[!] ETW: event_callback exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cerr << "[!] ETW: event_callback unknown exception\n";
    }
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
        if (j[PROVIDER_NAME] == EDRi_PROVIDER_NAME) {
            j[EVENT_ID] = EDRi_PROVIDER_EVENT_ID;
        }
        else {
            j[EVENT_ID] = ATTACK_PROVIDER_EVENT_ID;
        }

        std::string msg;
        if (parser.try_parse(MY_MESSAGE_W, msg)) {
            j[TASK] = std::string(msg.begin(), msg.end());
        }
        else {
            j[TASK] = "(no " + MY_MESSAGE + " field)";
            std::cout << "[*] ETW: Warning: Custom event missing " << MY_MESSAGE << " field " << j.dump() << "\n";
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
        bool overwritten = false;
        std::string overwritten_key;
        std::string overwritten_value;

        // Iterate over all properties defined in the schema
        for (const auto& property : parser.properties()) {
            try {
                // get property name and type
                const std::wstring& property_name = property.name();
                const auto property_type = property.type();

                // create key and convert it to lowercase
                std::string key = wstring2string((std::wstring&)property_name);
                std::transform(key.begin(), key.end(), key.begin(),
                    [](unsigned char c) { return std::tolower(c); });

                // for error messages
                last_key = key;
                last_type = property_type;

                // check if it's a merged key --> write value to merged_key
                for (const auto& cat : key_categories_to_merge) {
                    if (std::find(cat.keys_to_merge.begin(), cat.keys_to_merge.end(), key) != cat.keys_to_merge.end()) {
                        std::string old_key = key;
                        key = cat.merged_key;
                    }
                }
                if (j.contains(key)) {
                    overwritten = true;
                    overwritten_key = key;
                    overwritten_value = get_string_or_convert(j, key);
                }

                // Special cases
                if (key == "protectionmask" || key == "lastprotectionmask") {
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

                case TDH_INTYPE_GUID:
                {
                    GUID guid = parser.parse<GUID>(property_name);
                    std::ostringstream oss;
                    oss << std::hex << std::setfill('0')
                        << std::setw(8) << guid.Data1 << "-"
                        << std::setw(4) << guid.Data2 << "-"
                        << std::setw(4) << guid.Data3 << "-";

                    for (int i = 0; i < 2; i++)
                        oss << std::setw(2) << static_cast<int>(guid.Data4[i]);
                    oss << "-";
                    for (int i = 2; i < 8; i++)
                        oss << std::setw(2) << static_cast<int>(guid.Data4[i]);

                    j[key] = oss.str();
                    break;
                }

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
                    "[!] ETW: parse_etw_event failed to parse " << j[TASK] <<
                    ", key: " << last_key <<
                    ", type: " << last_type <<
                    ", error: " << ex.what() << "\n";
            }
        }

        // add a newly spawned procs to process map
        int pid = check_new_proc(j);
        if (pid != 0) {
            std::string exe_path = j[FILEPATH].get<std::string>();
            std::string exe_name = exe_path.substr(exe_path.find_last_of("\\") + 1);
            add_proc(pid, exe_name);
        }

        // callstack
        if (include_stacktrace) {
            try {
                j["stacktrace"] = json::array();
                int idx = 0;
                for (auto& return_address : e.schema.stack_trace()) {
                    // only add non-kernelspace addresses
                    if (return_address < 0xFFFF080000000000) {
                        j["stacktrace"].push_back(return_address);
                        idx++;
                    }
                }
            }
            catch (const std::exception& ex) {
                std::cerr << "[!] ETW: Failed to parse " << j[TASK] << "'s call stack: " << ex.what() << "\n";
            }
        }

        if (overwritten) {
            if (overwritten_value != j[overwritten_key]) { // only warn if the values differ
                std::cerr << "[!] ETW: Warning: Event ID " << j[EVENT_ID] << ", overwritten value for "
                    << overwritten_key << ":" << j[overwritten_key] << " with " << overwritten_value << "\n";
            }
        }

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: parse_etw_event general exception: " << ex.what() << "\n";
        return json();
    }
}

std::string get_string_or_convert(const json& j, const std::string& key) {
    std::cout << "in get string\n";
    if (!j.contains(key)) {
        return ""; // key not present
    }
    if (j[key].is_string()) {
        return j[key].get<std::string>();
    }
    else if (j[key].is_number()) {
        return std::to_string(j[key].get<double>());
    }
    else if (j[key].is_boolean()) {
        return j[key].get<bool>() ? "true" : "false";
    }
    else if (j[key].is_null()) {
        return "null";
    }
    else {
        // array or object
        return j[key].dump();
    }
}

// check proc started via kernel/antimalware etw
int check_new_proc(json& j) {
    if (j[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER && j[EVENT_ID] == KERNEL_PROC_START_EVENT_ID && j.contains(KERNEL_PID)) {
        return j[KERNEL_PID]; // kernel proc uses this key
    }
    if (j[PROVIDER_NAME] == ANTIMALWARE_PROVIDER && j[EVENT_ID] == ANTIMALWARE_PROC_START_STOP_EVENT_ID && j[SOURCE] == ANTIMALWARE_PROC_START_MSG && j.contains(ORIGINATING_PID)) {
        return j[ORIGINATING_PID]; // antimalware uses this key
    }
    return 0;
}

// check when the first EDRi event is registered --> trace running
bool check_traces_started(json& j) {
    if (j.contains(TASK)) {
        return j[TASK] == EDRi_TRACE_START_MARKER;
    }
    return false;
}

// monitors my events, sets started flag
void post_my_parsing_checks(json& j) {
    // checks if the trace started
    if (!g_traces_started && check_traces_started(j)) {
        if (g_debug) {
            std::cout << "[+] ETW: Start marker detected\n";
        }
        g_traces_started = true;
    }
}

// monitors events, sets and ended flag, attack and injected PID
void post_parsing_checks(json& j) {
    int new_proc_id = check_new_proc(j);

    // check if the attack_PID and injected_PID can be set
    // TODO path independent?
    if (g_attack_PID == 0 && new_proc_id != 0) {
        if (j.contains(FILEPATH) && j[FILEPATH] == attack_exe_path) {
            g_attack_PID = new_proc_id;
            g_tracking_PIDs.push_back(g_attack_PID);
            std::cout << "[+] ETW: Got attack PID: " << g_attack_PID << "\n";
        }
    }
    if (g_injected_PID == 0 && new_proc_id != 0) {
        if (j.contains(FILEPATH) && j[FILEPATH] == injected_exe_path) {
            g_injected_PID = new_proc_id;
            g_tracking_PIDs.push_back(g_injected_PID);
            std::cout << "[+] ETW: Got injected PID: " << g_injected_PID << "\n";
        }
    }

    // checks if the attack is done
    if (!g_attack_terminated) {
        // check if the event contains the attack pid
        if ((j.contains(KERNEL_PID) && j[KERNEL_PID] == g_attack_PID) ||
            (j.contains(ORIGINATING_PID) && j[ORIGINATING_PID] == g_attack_PID)) {
            // then check if this event is a terminate event
            bool kernel_proc_stopped = j[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER && j[EVENT_ID] == KERNEL_PROC_STOP_EVENT_ID;
            bool antimalware_proc_stopped = j[PROVIDER_NAME] == ANTIMALWARE_PROVIDER && j[EVENT_ID] == ANTIMALWARE_PROC_START_STOP_EVENT_ID && j[SOURCE] == ANTIMALWARE_PROC_STOP_MSG;
            if (kernel_proc_stopped || antimalware_proc_stopped) {
                if (g_debug) {
                    std::cout << "[+] ETW: Attack termination detected\n";
                }
                g_attack_terminated = true;
            }
        }
    }
}

void add_exe_information(json& j) {
    for (auto it = j.begin(); it != j.end(); ++it) {
        const std::string& key = it.key();
        json& value = it.value();

        // add info for all pid fields
        if (std::find(fields_to_add_exe_name.begin(), fields_to_add_exe_name.end(), key) != fields_to_add_exe_name.end()) {
            std::string old_val = value.is_string() ? value.get<std::string>() : value.dump();
            std::string exe_name = get_proc_name(value);

            std::ostringstream oss;
            oss << std::setw(5) << value.get<int>(); // pad up to 5 digits
            value = oss.str() + " " + exe_name; // add exe name "in place" (reference)
        }
    }
}

// filter based on provider
bool filter(json& ev) {
    if (ev[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER) {
        return filter_kernel_process(ev);
    }

    else if (ev[PROVIDER_NAME] == KERNEL_API_PROVIDER) {
        return filter_kernel_api_call(ev);
    }

    else if (ev[PROVIDER_NAME] == KERNEL_FILE_PROVIDER) {
        return filter_kernel_file(ev);
    }

    else if (ev[PROVIDER_NAME] == KERNEL_NETWORK_PROVIDER) {
        return filter_kernel_network(ev);
    }

    else if (ev[PROVIDER_NAME] == ANTIMALWARE_PROVIDER) {
        return filter_antimalware(ev);
    }

    if (g_super_debug) {
        std::cout << "[+] ETW: Unfiltered provider " << ev[PROVIDER_NAME] << ", not filtering its event ID " << ev[EVENT_ID] << "\n";
    }

    return false; // do not filter unregistered providers
}

// filter kernel process events
bool filter_kernel_process(json& ev) {
    // all known kernel proc event ids are filtered for "interesting" ids --> TODO does not work
    if (std::find(kproc_event_ids_with_pid_or_tpid.begin(), kproc_event_ids_with_pid_or_tpid.end(), ev[EVENT_ID]) != kproc_event_ids_with_pid_or_tpid.end()) {
        bool in_pid = std::find(g_tracking_PIDs.begin(), g_tracking_PIDs.end(), ev[PID]) == g_tracking_PIDs.end();
        bool in_tpid = std::find(g_tracking_PIDs.begin(), g_tracking_PIDs.end(), ev[tpid_keys.merged_key]) == g_tracking_PIDs.end();
        return in_pid || in_tpid; // filter out PIDs that are not in tracking (==true)
    }
    return false; // keep the rest
}

// filter kernel api calls
bool filter_kernel_api_call(json& ev) {
    if (std::find(kapi_event_ids_with_pid.begin(), kapi_event_ids_with_pid.end(), ev[EVENT_ID]) != kapi_event_ids_with_pid.end()) {
        return std::find(g_tracking_PIDs.begin(), g_tracking_PIDs.end(), ev[PID]) == g_tracking_PIDs.end(); // filter out PIDs that are not in tracking (==true)
    }
    return false; // keep the rest
}

// filter kernel file events
bool filter_kernel_file(json& ev) {
    if (std::find(kfile_event_ids_with_pid.begin(), kfile_event_ids_with_pid.end(), ev[EVENT_ID]) != kfile_event_ids_with_pid.end()) {
        return std::find(g_tracking_PIDs.begin(), g_tracking_PIDs.end(), ev[PID]) == g_tracking_PIDs.end(); // filter out PIDs that are not in tracking (==true)
    }
    return false; // keep the rest
}

// filter kernel network events
bool filter_kernel_network(json& ev) {
    if (std::find(knetwork_event_ids_with_pid_or_pid.begin(), knetwork_event_ids_with_pid_or_pid.end(), ev[EVENT_ID]) != knetwork_event_ids_with_pid_or_pid.end()) {
        return std::find(g_tracking_PIDs.begin(), g_tracking_PIDs.end(), ev[PID]) == g_tracking_PIDs.end(); // filter out PIDs that are not in tracking (==true)
    }
    return false; // keep the rest
}

// filter events based on known exclude values (e.g. wrong PID for given event id)
bool filter_antimalware(json& ev) {
    // events to remove
    if (std::find(am_event_ids_to_remove.begin(), am_event_ids_to_remove.end(), ev[EVENT_ID]) != am_event_ids_to_remove.end()) {
        return true;
    }

    // events to keep if PID matches
    if (std::find(am_event_ids_with_pid.begin(), am_event_ids_with_pid.end(), ev[EVENT_ID]) != am_event_ids_with_pid.end()) {
        if (ev.contains(ORIGINATING_PID)) {
            int pid = ev[ORIGINATING_PID];
            return pid != g_attack_PID && pid != g_injected_PID;
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << ORIGINATING_PID << " field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    // events to keep if PID or TargetPID matches
    if (std::find(am_event_ids_with_pid_and_tpid.begin(), am_event_ids_with_pid_and_tpid.end(), ev[EVENT_ID]) != am_event_ids_with_pid_and_tpid.end()) {
        if (ev.contains(TARGET_PID) && ev.contains(ORIGINATING_PID)) {
            int pid = ev[ORIGINATING_PID];
            int tpid = ev[TARGET_PID];
            return ev[ORIGINATING_PID] != g_attack_PID && ev[ORIGINATING_PID] != g_injected_PID && ev[TARGET_PID] != g_attack_PID && ev[TARGET_PID] != g_injected_PID;
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << ORIGINATING_PID << " or " << TARGET_PID << " field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    // events to keep if PID in Data matches
    if (std::find(am_event_ids_with_pid_in_data.begin(), am_event_ids_with_pid_in_data.end(), ev[EVENT_ID]) != am_event_ids_with_pid_in_data.end()) {
        if (ev.contains(DATA)) {
            return ev[DATA] != g_attack_PID && ev[DATA] != g_injected_PID;
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << DATA << " field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    // events to keep if Message contains filter string (case insensitive)
    if (std::find(am_event_ids_with_message.begin(), am_event_ids_with_message.end(), ev[EVENT_ID]) != am_event_ids_with_message.end()) {
        if (ev.contains(MESSAGE)) {
            std::string msg = ev[MESSAGE].get<std::string>();
            std::transform(msg.begin(), msg.end(), msg.begin(), [](unsigned char c) { return std::tolower(c); });
            if (msg.find("injector.exe") != std::string::npos ||
                msg.find("microsoft.windowsnotepad") != std::string::npos ||
                msg.find("microsoft.windowscalculator") != std::string::npos) {
                return false; // do not filter if any of the strings match
            }
            return true; // else filter out
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << MESSAGE << " field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    // events to keep if filepath matches
    if (std::find(am_event_ids_with_filepath.begin(), am_event_ids_with_filepath.end(), ev[EVENT_ID]) != am_event_ids_with_filepath.end()) {
        if (ev.contains(FILEPATH)) {
            return std::strcmp(ev[FILEPATH].get<std::string>().c_str(), attack_exe_path.c_str());
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << FILEPATH << " field: " << ev.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

    return false; // do not filter unregistered event ids
}

std::vector<json> get_events() {
    std::cout << "[+] ETW: Got " << etw_events.size() << " filtered events\n";
    return etw_events;
}

std::vector<json> get_events_unfiltered() {
    std::cout << "[+] ETW: Got " << all_etw_events.size() << " unfiltered events\n";
    return all_etw_events;
}

void count_event(json ev, bool filtered_out) {
    std::map<std::string, int>& m = filtered_out ? ::all_etw_events_counter : ::etw_events_counter;

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
    for (auto it = all_etw_events_counter.begin(); it != all_etw_events_counter.end(); ++it) {
        oss << it->first << "=" << it->second << ",";
    }
    std::cout << "[*] ETW: Filtered out events per provider: " << oss.str() << "\n";
}