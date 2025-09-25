#include <krabs.hpp>
#include "helpers/json.hpp"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

#include "globals.h"
#include "utils.h"
#include "filter.h"
#include "profile.h"
#include "etwparser.h"


enum Classifier { All, Relevant, Minimal };
std::map<Classifier, std::vector<json>> etw_events = {
    { All, {} },
    { Relevant, {} },
    { Minimal, {} }
};
std::map<Classifier, std::string> classifier_names = {
    { All, "All" },
    { Relevant, "Relevant" },
    { Minimal, "Minimal" }
};

// globals
int g_attack_PID = 0;
int g_injected_PID = 0;
bool g_traces_started = false;
bool g_attack_terminated = false;

// keys that get merged together
MergeCategory ppid_keys = {
    PPID,
    {"parentpid"}
};
MergeCategory tpid_keys = { // all refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_PID,
    {KERNEL_PID, "tpid", "targetprocessid", "frozenprocessid"} // processid in kernel means tpid, processid in antimalware means pid (but only event 95 has this)
};
MergeCategory ttid_keys = { // both refer to yet another pid (event has an emitter (process_id), original proc (pid), and the target proc (tpid))
    TARGET_TID,
    {"targetthreatid", "ttid"} // yes, threat with a t, this is a typo in the property name
};
MergeCategory filepath_keys = {
    FILEPATH,
    {"basepath", "filename", "imagename", "path", "name", "reasonimagepath"}
};
std::vector<MergeCategory> key_categories_to_merge = { ppid_keys, tpid_keys, ttid_keys, filepath_keys };

// pid fields that should have the exe name added at print time
static const std::vector<std::string> fields_to_add_exe_name = { PID, PPID, TARGET_PID, ORIGINATING_PID };


// hand over schema for parsing
void my_event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        json ev = parse_my_etw_event(Event{ record, schema });
        post_my_parsing_checks(ev);
        add_exe_information(ev); // must be after all parsing checks and filtering but before adding it to events

        etw_events[All].push_back(ev);
        etw_events[Relevant].push_back(ev);
        etw_events[Minimal].push_back(ev);
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
        Classifier c = filter(ev);
        add_exe_information(ev); // must be after all parsing checks and filtering but before adding it to events

        switch (c) {
        case Minimal:
            etw_events[Minimal].push_back(ev);
            // do not break, also add to relevant and all
        case Relevant:
            etw_events[Relevant].push_back(ev);
            // do not break, also add to all
        case All:
            etw_events[All].push_back(ev);
            if (g_super_debug) {
                std::cout << "[-] ETW: Filtered out event: " << ev.dump() << "\n";
            }
            break;
        }
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
        j[TYPE] = "myETW";
        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
        );
        j[PID] = e.record.EventHeader.ProcessId;
        j[PROVIDER_NAME] = wchar2string(e.schema.provider_name());
        if (j[PROVIDER_NAME] == EDRi_PROVIDER) {
            j[EVENT_ID] = EDRi_PROVIDER_EVENT_ID;
        }
        else if (j[PROVIDER_NAME] == HOOK_PROVIDER) {
            j[EVENT_ID] = HOOK_PROVIDER_EVENT_ID;
        }
        else if (j[PROVIDER_NAME] == ATTACK_PROVIDER) {
            j[EVENT_ID] = ATTACK_PROVIDER_EVENT_ID;
        } else {
            j[EVENT_ID] = -1; // unknown
		}

        std::string msg;
        if (parser.try_parse(MY_MESSAGE_W, msg)) {
            j[TASK] = std::string(msg.begin(), msg.end());
        }
        else {
            j[TASK] = "(no " + MY_MESSAGE + " field)";
            std::cout << "[*] ETW: Warning: Custom event missing " << MY_MESSAGE << " field " << j.dump() << "\n";
        }

		// if there are any other properties, parse them too
        parse_all_properties(parser, j);
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

        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
        );
        j[PID] = e.record.EventHeader.ProcessId;
        j[TID] = e.record.EventHeader.ThreadId;
        j[EVENT_ID] = e.schema.event_id(); // opcode is the same as event_id, sometimes just a different number
        j[PROVIDER_NAME] = wchar2string(e.schema.provider_name());

        if (j[PROVIDER_NAME] == THREAT_INTEL_PROVIDER) {
			j[TYPE] = "ETW-TI";
        }
        else {
			j[TYPE] = "ETW";
        }

        // task = task_name + opcode_name
        // TODO lookup missing info if either is null?
        std::wstring combined = std::wstring(e.schema.task_name()) + std::wstring(e.schema.opcode_name());
        j[TASK] = wstring2string(combined);

		parse_all_properties(parser, j);

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

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: parse_etw_event general exception: " << ex.what() << "\n";
        return json();
    }
}

void parse_all_properties(krabs::parser& parser, json& j) {
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
                j[key] = (bool)parser.parse<BOOL>(property_name);
                break;
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
        }
    }
}

std::string get_val(const json& j, std::string key) {
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
    if (j[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER && j[EVENT_ID] == KERNEL_PROC_START_EVENT_ID && j.contains(TARGET_PID)) {
        return j[TARGET_PID]; // kernel proc uses this key
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
        if (j.contains(FILEPATH) && filepath_match(j[FILEPATH], g_attack_exe_path)) {
            g_attack_PID = new_proc_id;
            g_tracking_PIDs.push_back(g_attack_PID);
            std::cout << "[+] ETW: Got attack PID: " << g_attack_PID << "\n";
        }
    }
    if (g_injected_PID == 0 && new_proc_id != 0) {
        if (j.contains(FILEPATH)) {
			std::string event_exe = j[FILEPATH].get<std::string>();
			event_exe = event_exe.substr(event_exe.find_last_of("\\") + 1); // only the exe name
            if (_stricmp(event_exe.c_str(), injected_exe.c_str()) == 0) {
                g_injected_PID = new_proc_id;
                g_tracking_PIDs.push_back(g_injected_PID);
                std::cout << "[+] ETW: Got injected PID: " << g_injected_PID << "\n";
            }
        }
    }

    // checks if the attack is done
    if (!g_attack_terminated) {
		// kernel event: check if the event contains the attack pid and is a terminate event
        bool kernel_proc_stopped = j[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER && j[EVENT_ID] == KERNEL_PROC_STOP_EVENT_ID &&
            j.contains(TARGET_PID) && j[TARGET_PID] == g_attack_PID;

        // am event: check if the event contains the attack pid and is a terminate event
        bool antimalware_proc_stopped = j[PROVIDER_NAME] == ANTIMALWARE_PROVIDER && j[EVENT_ID] == ANTIMALWARE_PROC_START_STOP_EVENT_ID &&
            j.contains(SOURCE) && j[SOURCE] == ANTIMALWARE_PROC_STOP_MSG &&
            j.contains(ORIGINATING_PID) && j[ORIGINATING_PID] == g_attack_PID;
        
        if (kernel_proc_stopped || antimalware_proc_stopped) {
            if (g_debug) {
                std::cout << "[+] ETW: Attack termination detected\n";
            }
            g_attack_terminated = true;
        }
    }
}

// adds exe name to all pid fields, only use AFTER filtering!
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
Classifier filter(json& ev) {
    if (ev[PROVIDER_NAME] == KERNEL_PROCESS_PROVIDER) {
        return filter_kernel_process(ev);
    }

    else if (ev[PROVIDER_NAME] == THREAT_INTEL_PROVIDER) {
        return filter_threat_intel(ev);
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

    return Relevant; // do not filter unregistered providers
}

// returns a classifier based on if the value is in list
Classifier classify_to(json& ev, std::string key, std::vector<int> list) {
    if (ev.contains(key)) {
        if (std::find(list.begin(), list.end(), ev[key]) == list.end()) {
            return All; // when value not found --> put in all
        }
		return Minimal; // when value found --> do not filter
    }
    else if (g_debug) {
        std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << key << " field to filter: " << ev.dump() << "\n";
    }
	return Relevant; // expected key does not exists, classify as relevant (for now)
}

// filter kernel process events
Classifier filter_kernel_process(json& ev) {
    // the interesting info is in target pid, process_id of msmpeng.exe/attack.exe/smartscreen.exe etc is not enough to filter
    if (std::find(kproc_event_ids_with_tpid.begin(), kproc_event_ids_with_tpid.end(), ev[EVENT_ID]) != kproc_event_ids_with_tpid.end()) {
        return classify_to(ev, TARGET_PID, g_tracking_PIDs);
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter threat intel events
Classifier filter_threat_intel(json& ev) {
	// either pid or tpid must match a tracked pid
    if (std::find(ti_events_with_pid_or_tpid.begin(), ti_events_with_pid_or_tpid.end(), ev[EVENT_ID]) != ti_events_with_pid_or_tpid.end()) {
        Classifier c_pid = classify_to(ev, PID, g_tracking_PIDs);
        Classifier c_orig = classify_to(ev, TARGET_PID, g_tracking_PIDs);
        if (c_pid == Minimal || c_orig == Minimal) {
            return Minimal; // put in minimal if either matches
        } // else put it in relevant
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter kernel api calls
Classifier filter_kernel_api_call(json& ev) {
    // the interesting info is in target pid, process_id of msmpeng.exe/attack.exe/smartscreen.exe etc is not enough to filter
    if (std::find(kapi_event_ids_with_tpid.begin(), kapi_event_ids_with_tpid.end(), ev[EVENT_ID]) != kapi_event_ids_with_tpid.end()) {
        return classify_to(ev, TARGET_PID, g_tracking_PIDs);
    }
    if (std::find(kapi_event_ids_with_pid.begin(), kapi_event_ids_with_pid.end(), ev[EVENT_ID]) != kapi_event_ids_with_pid.end()) {
        return classify_to(ev, PID, g_tracking_PIDs);
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter kernel file events
Classifier filter_kernel_file(json& ev) {
    // TODO also filters out Notepad.exe proc, why?
    if (std::find(kfile_event_ids_with_pid.begin(), kfile_event_ids_with_pid.end(), ev[EVENT_ID]) != kfile_event_ids_with_pid.end()) {
        return classify_to(ev, PID, g_tracking_PIDs);
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter kernel network events
Classifier filter_kernel_network(json& ev) {
    // events to keep if PID or originating PID match
    if (std::find(knetwork_event_ids_with_pid_or_opid.begin(), knetwork_event_ids_with_pid_or_opid.end(), ev[EVENT_ID]) != knetwork_event_ids_with_pid_or_opid.end()) {
        Classifier c_pid = classify_to(ev, PID, g_tracking_PIDs);
        Classifier c_orig = classify_to(ev, ORIGINATING_PID, g_tracking_PIDs); 
        if (c_pid == Minimal || c_orig == Minimal) {
            return Minimal; // put in minimal if either matches
		} // else put it in relevant
    }
    return Relevant; // put event ids without a filter into relevant
}

// filter events based on known exclude values (e.g. wrong PID for given event id)
Classifier filter_antimalware(json& ev) {
    // events to remove
    if (std::find(am_event_ids_to_remove.begin(), am_event_ids_to_remove.end(), ev[EVENT_ID]) != am_event_ids_to_remove.end()) {
        return All;
    }

    // events to keep if originating PID matches attack or injected PID
    if (std::find(am_event_ids_with_pid.begin(), am_event_ids_with_pid.end(), ev[EVENT_ID]) != am_event_ids_with_pid.end()) {
        Classifier c = classify_to(ev, ORIGINATING_PID, { g_attack_PID, g_injected_PID });
        if (c == All) {
			return All; // put in all if it does not match
        }
        if (std::find(am_event_ids_with_pid_but_noisy.begin(), am_event_ids_with_pid_but_noisy.end(), ev[EVENT_ID]) != am_event_ids_with_pid_but_noisy.end()) {
			return Relevant; // put noisy events into relevant (can overwrite minimal from above)
        }
		return c; // else return as classified originally
    }

    // events to keep if originating PID or TargetPID matches attack PID or injected PID
    if (std::find(am_event_ids_with_pid_and_tpid.begin(), am_event_ids_with_pid_and_tpid.end(), ev[EVENT_ID]) != am_event_ids_with_pid_and_tpid.end()) {
        Classifier c_orig = classify_to(ev, ORIGINATING_PID, { g_attack_PID, g_injected_PID });
        Classifier c_target = classify_to(ev, TARGET_PID, { g_attack_PID, g_injected_PID });
        if (c_orig == Minimal || c_target == Minimal) {
            return Minimal; // put in minimal if either matches
        } // else put it in relevant
		return Relevant;
    }

    // events to keep if PID in Data matches
    if (std::find(am_event_ids_with_pid_in_data.begin(), am_event_ids_with_pid_in_data.end(), ev[EVENT_ID]) != am_event_ids_with_pid_in_data.end()) {
        return classify_to(ev, DATA, { g_attack_PID, g_injected_PID });
    }

    // events to keep if Message contains filter string (case insensitive) // TODO without magic values
    if (std::find(am_event_ids_with_message.begin(), am_event_ids_with_message.end(), ev[EVENT_ID]) != am_event_ids_with_message.end()) {
        if (ev.contains(MESSAGE)) {
            std::string msg = ev[MESSAGE].get<std::string>();
            std::transform(msg.begin(), msg.end(), msg.begin(), [](unsigned char c) { return std::tolower(c); });
            if (msg.find("injector.exe") != std::string::npos ||
                msg.find("microsoft.windowsnotepad") != std::string::npos ||
                msg.find("microsoft.windowscalculator") != std::string::npos) {
                return Minimal; // do not filter if any of the strings match
            }
            return All; // else filter out
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << MESSAGE << " field: " << ev.dump() << "\n";
        }
        return Relevant; // unexpected event fields, do not filter
    }

    // events to keep if filepath matches (case insensitive)
    if (std::find(am_event_ids_with_filepath.begin(), am_event_ids_with_filepath.end(), ev[EVENT_ID]) != am_event_ids_with_filepath.end()) {
        if (ev.contains(FILEPATH)) {
            if (_stricmp(ev[FILEPATH].get<std::string>().c_str(), g_attack_exe_path.c_str())) {
				return Minimal; // do not filter if path matches
            }
			return All; // else filter out
        }
        else if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << ev[EVENT_ID] << " missing " << FILEPATH << " field: " << ev.dump() << "\n";
        }
        return Relevant; // unexpected event fields, do not filter
    }

    return Relevant; // put event ids without a filter into relevant
}

std::map<Classifier, std::vector<json>> get_events() {
    return etw_events;
}

std::string get_classifier_name(Classifier c) {
    return classifier_names[c];
}

void print_etw_counts() {
    for (auto& c : etw_events) {
        std::ostringstream oss;
		Classifier classifier = c.first;
		std::vector<json>& events = c.second;

        // count by provider
		std::map<std::string, int> provider_counts;
        for (auto it = events.begin(); it != events.end(); ++it) {
            std::string provider = "<empty provider>";
            if (it->contains(PROVIDER_NAME)) {
                provider = (*it)[PROVIDER_NAME];
            }
            if (provider_counts.find(provider) == provider_counts.end()) {
                provider_counts[provider] = 1;
            }
            else {
                provider_counts[provider]++;
			}
        }

        for (auto it = provider_counts.begin(); it != provider_counts.end(); ++it) {
            if (it != provider_counts.begin()) {
                oss << ", ";
            }
            oss << it->first << ": " << it->second;
		}
        std::cout << "[*] ETW: Classification " << classifier_names[c.first] << ": " << events.size() << " events.";
        std::cout << " Filtered events per provider > " << oss.str() << "\n";
	}
}

std::string add_color_info(const json& ev) {
    if (!ev.contains(PROVIDER_NAME)) {
        if (g_debug) {
            std::cout << "[-] Utils: Warning: Event missing " << PROVIDER_NAME << " field: " << ev.dump() << "\n";
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

// dumps all relevant info from antimalware provider event id 3,8,74,104
void dump_signatures() {
    for (const auto& ev : etw_events[Relevant]) {
        try {
            if (!ev.contains(EVENT_ID) || !ev.contains(PROVIDER_NAME)) {
                if (g_debug) {
                    std::cout << "[-] Parser: Warning: Event missing " << EVENT_ID << " field: " << ev.dump() << "\n";
                }
                continue;
            }
            if (ev[PROVIDER_NAME] != ANTIMALWARE_PROVIDER) {
                continue; // only this provider contains the signatures
            }
            if (ev[EVENT_ID] == 3) {
                if (!ev.contains(MESSAGE)) {
                    if (g_debug) {
                        std::cout << "[-] Parser: Warning: Event with ID 3 missing " << MESSAGE << " field: " << ev.dump() << "\n";
                    }
                    continue;
                }
                std::string m = get_val(ev, MESSAGE);
                std::string s = "signame=";
                std::string r = "resource=";
                size_t ss = m.find(s);
                size_t sr = m.find(r);
                if (ss != std::string::npos && sr != std::string::npos) { // only some 3 events have signatures
                    size_t es = m.find(", ", ss);
                    size_t er = m.find(", ", sr);
                    ss += s.length();
                    sr += r.length();
                    std::string sig = m.substr(ss, es - ss);
                    std::string res = m.substr(sr, er - sr);
                    std::cout << "[+] Parser: Found signature: " << sig << " in " << res << "\n";
                }
            }
            if (ev[EVENT_ID] == 8) {
                if (!ev.contains(PID)) {
                    if (g_debug) {
                        std::cout << "[-] Parser: Warning: Event with ID 8 missing " << PID << " field: " << ev.dump() << "\n";
                    }
                    continue;
                }
                std::cout << "[+] Parser: Behaviour Monitoring Detection: " <<
                    "pid=" << get_val(ev, PID) << ", sig=" << get_val(ev, FILEPATH); // THIS NEEDS DEBUGGING
            }
            if (ev[EVENT_ID] == 74) {
                std::cout << "[+] Parser: Sense Remidiation" <<
                    ": threatname=" << get_val(ev, THREATNAME) <<
                    ", signature=" << get_val(ev, SIGSEQ) <<
                    ", sigsha=" << get_val(ev, SIGSHA) <<
                    ", classification=" << get_val(ev, CLASSIFICATION) <<
                    ", determination=" << get_val(ev, DETERMINATION) <<
                    ", realpath=" << get_val(ev, REALPATH) <<
                    ", resource=" << get_val(ev, RESOURCESCHEMA) <<
                    "\n";
            }
            if (ev[EVENT_ID] == 104) {
                if (!ev.contains(FIRST_PARAM) || !ev.contains(SECOND_PARAM)) {
                    if (g_debug) {
                        std::cout << "[-] Parser: Warning: Event with ID 104 missing " << FIRST_PARAM << " or " << SECOND_PARAM << " field: " << ev.dump() << "\n";
                    }
                }
            }
        }
        catch (const std::exception& ex) {
            std::cerr << "[!] Parser: dump_signatures exception: " << ex.what() << "\n";
		}
    }
}
