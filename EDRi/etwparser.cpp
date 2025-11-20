#include <krabs.hpp>
#include "helpers/json.hpp"
#include <iostream>
#include <cstdlib>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include "globals.h"
#include "profile.h"
#include "utils.h"
#include "etwparser.h"


// all events
std::vector<json> std_events = {};
std::vector<json> misc_events = {};
std::vector<json> etw_ti_events = {};
std::vector<json> hook_events = {};

std::map<std::string, std::vector<UINT64>> time_diffs_ns = { // differences in nanoseconds between ETW time and system time
    { EDRi_PROVIDER, {} },
    { ATTACK_PROVIDER, {} },
    { HOOK_PROVIDER, {} }
};

int null_events = 0; // errors

// globals
ProcInfo null_proc = { 0, 0, 0, "", false };
ProcInfo g_attack_proc = null_proc;
ProcInfo g_injected_proc = null_proc;
bool g_start_marked_detected = false;
bool g_hooker_started = false;
bool g_attack_terminated = false;

// when check is needed, they are set to false again
bool g_misc_trace_started = true;
bool g_etw_ti_trace_started = true;
bool g_hook_trace_started = true;

// procs to check for hook init msg
int detected_hook_start_markers = 0;

// static
static bool cleaned_events = false;

// keys that get merged together
MergeCategory ppid_keys = {
    PPID,
    {"parentpid"}
};
MergeCategory tpid_keys = { // all refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_PID,
    {"processid", "tpid", "targetprocessid", "frozenprocessid"} // processid in kernel means tpid, processid in antimalware means pid (but only event 95 has this)
};
MergeCategory ttid_keys = { // both refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_TID,
    {"targetthreatid", "ttid"} // yes, threat with a t, this is a typo in the property name
};
MergeCategory filepath_keys = {
    FILEPATH,
    {"basepath", "filename", "imagename", "path", "reasonimagepath"}
};
std::vector<MergeCategory> key_categories_to_merge = { ppid_keys, tpid_keys, ttid_keys, filepath_keys };

// get time difference statistics
std::map<std::string, std::vector<UINT64>> get_time_diffs() {
    return time_diffs_ns;
}

// potentially corrupted events, or complete parsing errors
int get_null_events_count() {
    return null_events;
}

// -------------- EVENT PARSING -------------- //
// parses attack events
json parse_custom_etw_event(const EVENT_RECORD& record, const krabs::schema& schema) {
    try {
        krabs::parser parser(schema);
        json j;

        std::string provider = wchar2string(schema.provider_name());

        UINT64 timestamp_filetime = static_cast<UINT64>(record.EventHeader.TimeStamp.QuadPart);
        j[TIMESTAMP_NS] = filetime_to_unix_epoch_ns(timestamp_filetime);
        j[TIMESTAMP_ETW] = filetime_to_iso8601(timestamp_filetime);
        j[TYPE] = "myETW";
        j[PID] = record.EventHeader.ProcessId;
        std::string task = wchar2string(schema.task_name());
        j[TASK] = task;
        j[PROVIDER_NAME] = wchar2string(schema.provider_name());
        if (j[PROVIDER_NAME] == EDRi_PROVIDER) {
            j[EVENT_ID] = EDRi_PROVIDER_EVENT_ID;
        }
        else if (j[PROVIDER_NAME] == ATTACK_PROVIDER) {
            j[EVENT_ID] = ATTACK_PROVIDER_EVENT_ID;
        }
        else if (j[PROVIDER_NAME] == HOOK_PROVIDER) {
            j[EVENT_ID] = HOOK_PROVIDER_EVENT_ID;
        }
        else { // unknown, return header info only
            if (g_debug) {
                std::cerr << "[!] ETW: Custom event with unknown provider: " << j.dump() << "\n";
            }
            j[EVENT_ID] = -1;
            return j;
        }

        // custom parsing when not using manifest based ETW --> cannot use property parsing
        // get payload size
        const BYTE* data = (const BYTE*)record.UserData;
        ULONG size = record.UserDataLength;

        // PARSE MESSAGE
        const char* msg = reinterpret_cast<const char*>(data); // read until first null byte
        size_t msg_len = strnlen(msg, size);
        if (msg_len == 0) {
            msg = "(empty message)";
            std::cout << "[*] ETW: Warning: Custom event with empty message " << j.dump() << "\n";
        }
        j[MESSAGE] = msg;
        const BYTE* ptr_field = data + msg_len + 1;

        // PARSE NS_SINCE_EPOCH
        UINT64 system_ns_since_unix_epoch = 0;
        if (ptr_field + sizeof(UINT64) <= data + size) {
            memcpy(&system_ns_since_unix_epoch, ptr_field, sizeof(UINT64));
            UINT64 etw_ns_since_unix_epoch = (timestamp_filetime - WINDOWS_TICKS_TO_UNIX_EPOCH) * NS_PER_WINDOWS_TICK;
            INT64 diff = static_cast<INT64>(etw_ns_since_unix_epoch) - static_cast<INT64>(system_ns_since_unix_epoch); // etw time should be greater, but do not trust time...
            time_diffs_ns[j[PROVIDER_NAME]].push_back(std::abs(diff));
            ptr_field += sizeof(UINT64);
        }
        else if (g_debug) {
            std::cerr << "[!] ETW: Custom event with no " << TIMESTAMP_NS << " field: " << j.dump() << "\n";
        }
        std::string iso_time = unix_epoch_ns_to_iso8601(system_ns_since_unix_epoch);
        j[TIMESTAMP_SYS] = iso_time;

        if (provider == HOOK_PROVIDER) {
            // PARSE TARGETPID
            UINT64 targetpid = -1;
            if (ptr_field + sizeof(UINT64) <= data + size) {
                memcpy(&targetpid, ptr_field, sizeof(UINT64));
            }
            else if (g_debug) {
                std::cerr << "[!] ETW: Hook event with no " << TARGET_PID << " field: " << j.dump() << "\n";
            }
            j[TARGET_PID] = targetpid;
        }

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: Custom Trace Exception: " << ex.what() << "\n";
        return json();
    }
}

std::string get_kernel_api_task_name(int event_id) {
    if (event_id == 1)
        return "PsSetLoadImageNotifyRoutineEx";
    if (event_id == 2)
        return "NtTerminateProcess";
    if (event_id == 3)
        return "NtCreateSymbolicLinkObject";
    if (event_id == 4)
        return "NtSetContextThread";
    if (event_id == 5)
        return "PsOpenProcess";
    if (event_id == 6)
        return "PsOpenThread";
    if (event_id == 7)
        return "IoRegisterLastChanceShutdownNotification";
    if (event_id == 8)
        return "IoRegisterShutdownNotification";
    return "unmapped kernel api event id";
}

std::string get_val(const json& j, const std::string& key) {
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

// parses all other ETW events
json parse_etw_event(const EVENT_RECORD& record, const krabs::schema& schema) {
    try {
        std::string provider_name = wchar2string(schema.provider_name());
        if (provider_name == EDRi_PROVIDER || provider_name == ATTACK_PROVIDER || provider_name == HOOK_PROVIDER) {
            return parse_custom_etw_event(record, schema);
        }

        json j;

        __int64 timestamp_filetime = static_cast<__int64>(record.EventHeader.TimeStamp.QuadPart);
        j[TIMESTAMP_NS] = filetime_to_unix_epoch_ns(timestamp_filetime);
        j[TIMESTAMP_ETW] = filetime_to_iso8601(timestamp_filetime);
        j[TIMESTAMP_SYS] = j[TIMESTAMP_ETW]; // normal ETW events only have their timestamp, not the custom system timestamp
        j[PID] = record.EventHeader.ProcessId;
        j[TID] = record.EventHeader.ThreadId;
        j[EVENT_ID] = schema.event_id(); // opcode is also an ID, but not documented?
        j[PROVIDER_NAME] = provider_name;

        if (j[PROVIDER_NAME] == THREAT_INTEL_PROVIDER) {
            j[TYPE] = "ETW-TI";
        }
        else {
            j[TYPE] = "ETW";
        }

        if (provider_name == KERNEL_API_PROVIDER) {
            // special handling for kernel api provider to get better task names
            std::string task_name = get_kernel_api_task_name(schema.event_id());
            j[TASK] = task_name;
        }
        else {
            std::wstring combined = std::wstring(schema.task_name()) + L" " + std::wstring(schema.opcode_name());
            j[TASK] = wstring2string(combined);
        }

        krabs::parser parser(schema);
        // parse all properties defined in the schema
        for (const auto& property : parser.properties()) {
            std::string last_key;
            std::string original_key = "";
            int last_type;

            try {
                // get property name and type
                const std::wstring& property_name = property.name();
                const auto property_type = property.type();

                // create key and convert it to lowercase
                std::string key = wstring2string((std::wstring&)property_name);
                std::transform(key.begin(), key.end(), key.begin(),
                    [](unsigned char c) { return std::tolower(c); });

                // for tracking potential overwrites & error messages
                std::string overwritten_value = "";
                last_key = key;
                last_type = property_type;

                // check if it's a merged key --> write value to merged_key
                for (const auto& cat : key_categories_to_merge) {
                    if (std::find(cat.keys_to_merge.begin(), cat.keys_to_merge.end(), key) != cat.keys_to_merge.end()) {
                        original_key = key;
                        key = cat.merged_key;
                    }
                }
                if (j.contains(key)) {
                    overwritten_value = get_val(j, key);
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
                case TDH_INTYPE_INT32:
                    j[key] = (int32_t)parser.parse<int32_t>(property_name);
                    break;
                case TDH_INTYPE_UINT32:
                    j[key] = (uint32_t)parser.parse<uint32_t>(property_name);
                    break;
                case TDH_INTYPE_INT64:
                    j[key] = (int64_t)parser.parse<int64_t>(property_name);
                    break;
                case TDH_INTYPE_UINT64:
                    j[key] = (uint64_t)parser.parse<uint64_t>(property_name);
                    break;
                case TDH_INTYPE_BOOLEAN:
                {
                    try {
                        j[key] = (bool)parser.parse<bool>(property_name);
                    }
                    catch (...) {
                        // fallback: dump raw bytes
                        auto bin = parser.parse<krabs::binary>(property_name);
                        const auto& bytes = bin.bytes();
                        std::ostringstream oss;
                        oss << "0x" << std::hex << std::setfill('0');
                        for (auto b : bytes)
                            oss << std::setw(2) << static_cast<int>(b);
                        j[key] = oss.str();
                    }
                    break;
                }
                case TDH_INTYPE_POINTER:
                    j[key] = (uint64_t)parser.parse<PVOID>(property_name);
                    break;

                case TDH_INTYPE_BINARY:
                {
                    try {
                        auto bin = parser.parse<krabs::binary>(property_name);
                        const auto& bytes = bin.bytes();
                        const auto size = bytes.size();
                        const auto data = bytes.empty() ? nullptr : bytes.data();

                        if (size == 4 && data) {
                            char ipStr[INET_ADDRSTRLEN] = { 0 };
                            if (inet_ntop(AF_INET, data, ipStr, sizeof(ipStr)))
                                j[key] = std::string(ipStr);
                            else
                                j[key] = "<inet_ntop_AF_INET_failed>";
                        }
                        else if (size == 16 && data) {
                            // detect IPv4-mapped IPv6 ::ffff:a.b.c.d (first 10 bytes 0, then 0xff,0xff)
                            bool ipv4_mapped = (std::equal(bytes.begin(), bytes.begin() + 10, std::vector<BYTE>(10, 0).begin())
                                && bytes[10] == 0xff && bytes[11] == 0xff);
                            if (ipv4_mapped) {
                                // convert last 4 bytes as IPv4
                                char ipStr[INET_ADDRSTRLEN] = { 0 };
                                if (inet_ntop(AF_INET, data + 12, ipStr, sizeof(ipStr)))
                                    j[key] = std::string("::ffff:") + std::string(ipStr); // or ipStr alone if you prefer
                                else
                                    j[key] = "<inet_ntop_mapped_failed>";
                            }
                            else {
                                char ipStr[INET6_ADDRSTRLEN] = { 0 };
                                if (inet_ntop(AF_INET6, data, ipStr, sizeof(ipStr)))
                                    j[key] = std::string(ipStr);
                                else
                                    j[key] = "<inet_ntop_AF_INET6_failed>";
                            }
                        }
                        else {
                            // fallback: hex dump
                            std::ostringstream oss;
                            oss << "0x" << std::hex << std::setfill('0');
                            for (BYTE b : bytes) {
                                oss << std::setw(2) << static_cast<int>(b);
                            }
                            j[key] = oss.str();
                        }
                    }
                    catch (...) {
                        // ignore conversion errors
                        j[key] = "<parse error>";
                    }
                    break;
                }

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
                /*
                if (key == ORIGINATING_PID && j[ORIGINATING_PID] == 0) {
                    j[ORIGINATING_PID] = -1; // orginating pid=0 does not make sense?
                }
                */
                if (overwritten_value != "") {
                    if (overwritten_value != j[key]) { // only warn if the values differ
                        std::cerr << "[!] ETW: Warning, " << j[PROVIDER_NAME] << ":" << j[EVENT_ID] <<
                            ", overwritten '" << key << ":" << overwritten_value <<
                            "' with '" << key << ":" << j[key] << "'";
                        if (original_key != "") { // include name of merged key (if overwrite was b.c. of a merge)
                            std::cerr << " because of merged key '" << original_key << "'";
                        }
                        std::cerr << "\n";
                    }
                }
            }
            catch (const std::exception& ex) {
                std::cerr <<
                    "[!] ETW: parse_etw_event failed to parse " << j[TASK] <<
                    ", key: " << last_key <<
                    ", type: " << last_type <<
                    ", error: " << ex.what() << "\n";
                j[last_key] = PARSE_ERROR; // write error and continue to next prop
            }
        }

        // callstack
        if (include_stacktrace) {
            try {
                j["stacktrace"] = json::array();
                int idx = 0;
                for (auto& return_address : schema.stack_trace()) {
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

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: parse_etw_event general exception: " << ex.what() << "\n";
        return json();
    }
}

// -------------- POST PARSING CHECKS -------------- //
// check proc started via kernel etw
int check_new_proc(json& j) {
    if (j[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER && j[EVENT_ID] == KERNEL_PROC_START_EVENT_ID && j.contains(TARGET_PID)) {
        return j[TARGET_PID]; // kernel proc uses this key
    }
    return 0;
}

// check proc ended via kernel etw
int check_proc_termination(json& j) {
    if (j[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER && j[EVENT_ID] == KERNEL_PROC_STOP_EVENT_ID && j.contains(TARGET_PID)) {
        return j[TARGET_PID]; // kernel proc uses this key
    }
    return 0;
}

// check when the first EDRi event is registered --> trace running
bool check_traces_started(json& j) {
    if (j.contains(MESSAGE)) {
        return j[MESSAGE] == EDRi_TRACE_START_MARKER;
    }
    return false;
}

// check if the hooker emits ETW messages --> hooks installed
bool check_hooker_started(json& j) {
    if (j[PROVIDER_NAME] == HOOK_PROVIDER && j.contains(MESSAGE)) {
        if (j[MESSAGE] == NTDLL_HOOKER_TRACE_START_MARKER) {
            detected_hook_start_markers++;
            if (g_debug) {
                std::cout << "[+] ETW: Detected hook initialization in " << j[PID] << "\n";
            }
        }
    }
    return detected_hook_start_markers == g_newly_hooked_procs.size();
}

// monitors events: mark procs as started or terminated (also attack and injected on their own), and check traces startes
void post_parsing_checks(json& j) {
    // add a newly spawned procs to process map
    int pid = check_new_proc(j);
    if (pid != 0) {
        if (!j.contains(FILEPATH)) {
            if (g_debug) {
                std::cout << "[!] ETW: New proc without a " << FILEPATH << ", " << j.dump() << "\n";
            }
        }
        else {
            std::string exe_path = j[FILEPATH].get<std::string>();
            std::string exe_name = exe_path.substr(exe_path.find_last_of("\\") + 1);
            UINT64 timestamp_ns = j[TIMESTAMP_NS];

            // check if this is a process to be tracked
            bool to_track = false;
            for (auto& e : g_exes_to_track) {
                if (_stricmp(exe_name.c_str(), e.c_str()) == 0) {
                    to_track = true;
                }
            }

            // also check if the attack_PID and injected_PID can be set
            if (g_attack_proc.PID == 0) {
                if (filepath_match(j[FILEPATH], g_attack_exe_path)) { // depends on the attack path, but this is fixed
                    g_attack_proc = ProcInfo{ pid, timestamp_ns, MAX_PROC_END, exe_name, true };
                    std::cout << "[+] ETW: Got attack PID: " << pid << "\n";
                    to_track = true;
                }
            }
            if (g_injected_proc.PID == 0) {
                if (filepath_match(j[FILEPATH], injected_path)) {
                    g_injected_proc = ProcInfo{ pid, timestamp_ns, MAX_PROC_END, exe_name, true };
                    std::cout << "[+] ETW: Got injected PID: " << pid << "\n";
                    to_track = true;
                }
            }

            add_proc(pid, exe_name, timestamp_ns, to_track);
        }
    }

    // or mark termination of process
    pid = check_proc_termination(j);
    if (pid != 0) {
        UINT64 timestamp_ns = j[TIMESTAMP_NS];
        mark_termination(pid, timestamp_ns);

        // also check if the attack is done
        if (!g_attack_terminated && pid == g_attack_proc.PID) {
            if (g_debug) {
                std::cout << "[+] ETW: Attack termination detected\n";
            }
            g_attack_terminated = true;
        }
        // no need to check for injected termination, only g_attack_terminated is relevant
    }

    // checks if the trace started
    if (!g_start_marked_detected && check_traces_started(j)) {
        if (g_debug) {
            std::cout << "[+] ETW: Start marker detected\n";
        }
        g_start_marked_detected = true;
    }
}

void post_parsing_checks_hooks(json& j) {
    // checks if the hooker is started (only if new procs were hooked, and the hooker is not started yet)
    if (!g_hooker_started && g_newly_hooked_procs.size() > 0 && check_hooker_started(j)) {
        g_hooker_started = true;
    }
}

// hand over schema for parsing
void event_callback_std(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    json ev = parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
    if (ev.is_null()) {
        null_events++;
        return; // ignore empty events
    }
    post_parsing_checks(ev);
    std_events.push_back(ev);
}

// hand over schema for parsing
void event_callback_misc(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_misc_trace_started = true;
    json ev = parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
    if (ev.is_null()) {
        null_events++;
        return; // ignore empty events
    }
    misc_events.push_back(ev);
}

// hand over schema for parsing
void event_callback_etw_ti(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_etw_ti_trace_started = true;
    json ev = parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
    if (ev.is_null()) {
        null_events++;
        return; // ignore empty events
    }
    etw_ti_events.push_back(ev);
}

// hand over schema for parsing
void event_callback_hooks(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_hook_trace_started = true;
    json ev = parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
    if (ev.is_null()) {
        null_events++;
        return; // ignore empty events
    }
    post_parsing_checks_hooks(ev);
    hook_events.push_back(ev);
}

// get all events as one flat vector
void concat_all_etw_events(std::vector<json>& out) {
    std::vector<std::vector<json>*> all_etw_events = { &std_events, &misc_events, &etw_ti_events, &hook_events };
    size_t events_count = 0;
    for (auto v_ptr : all_etw_events) {
        events_count += v_ptr->size();
    }

    if (g_debug) {
        std::cout << "[*] ETW: Flattening all " << events_count << " recorded events\n";
    }
    out.clear();
    out.reserve(events_count);

    for (auto v_ptr : all_etw_events) {
        out.insert(out.end(),
            std::make_move_iterator(v_ptr->begin()),
            std::make_move_iterator(v_ptr->end()));
        v_ptr->clear(); // original vectors are now empty
        v_ptr->shrink_to_fit(); // release the ~kraken~ memory
    }
}