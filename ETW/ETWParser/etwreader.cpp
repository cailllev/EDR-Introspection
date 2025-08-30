#include <krabs.hpp>
#include "json.hpp"
#include "globals.h"
#include "utils.h"
#include "etwreader.h"
#include "filter.h"


struct Event {
    const EVENT_RECORD& record;
    const krabs::schema schema;
};
std::vector<json> etw_events;

krabs::user_trace trace_user(L"EDRi");
bool extensive = false; // enable more providers and events
int errors = 0;
bool g_trace_running = false;
bool g_attack_done = false;

// keys to merge for PPID and FilePath
MergeCategory ppid_keys = {
    "PPID",
    {"Parent PID", "TPID"} // TargetPID?
};
MergeCategory filepath_keys = {
    "FilePath",
    {"BasePath", "FileName", "filepath", "File Path", "ImagePath", "ImageName", "Path", "ProcessImagePath", "Name", "ReasonImagePath"}
};
std::vector<MergeCategory> key_categories_to_merge = { ppid_keys, filepath_keys };


std::vector<json> get_events() {
    std::cout << "[+] ETW: Got " << etw_events.size() << " events\n";
    return etw_events;
}


// filter events based on known exclude values (e.g. wrong PID for given event id)
bool filter_out(json event) {
    // events to remove
    if (std::find(event_ids_to_remove.begin(), event_ids_to_remove.end(), event[EVENT_ID]) != event_ids_to_remove.end()) {
        return true;
	}

    // events to keep if PID matches
    if (std::find(event_ids_with_pid.begin(), event_ids_with_pid.end(), event[EVENT_ID]) != event_ids_with_pid.end()) {
        return event[PID] != g_attack_PID && event[PID] != g_injected_PID;
	}

	// events to keep if PID or TargetPID matches
    if (std::find(event_ids_with_pid_or_tpid.begin(), event_ids_with_pid_or_tpid.end(), event[EVENT_ID]) != event_ids_with_pid_or_tpid.end()) {
        if (event.contains("TargetPID")) {
            return event[PID] != g_attack_PID && event[PID] != g_injected_PID && event["TargetPID"] != g_attack_PID && event["TargetPID"] != g_injected_PID;
		}
        if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << event[EVENT_ID] << " missing TargetPID field: " << event.dump() << "\n";
        }
        return false;
    }

	// events to keep if PID in Data matches
    if (std::find(event_ids_with_pid_in_data.begin(), event_ids_with_pid_in_data.end(), event[EVENT_ID]) != event_ids_with_pid_in_data.end()) {
        if (event.contains("Data")) {
            return event["Data"] != g_attack_PID && event["Data"] != g_injected_PID;
        }
        if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << event[EVENT_ID] << " missing Data field: " << event.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
	}

	// events to keep if Message contains filter string
    if (std::find(event_ids_with_message.begin(), event_ids_with_message.end(), event[EVENT_ID]) != event_ids_with_message.end()) {
        if (event.contains("Message")) {
            std::string msg = event["Message"].get<std::string>();
            std::transform(msg.begin(), msg.end(), msg.begin(), ::tolower);
            if (msg.find("injector.exe") != std::string::npos || 
                msg.find("microsoft.windowsnotepad") != std::string::npos || 
                msg.find("microsoft.windowscalculator") != std::string::npos ) {
                return true; // TODO does not filter
            }
        }
        if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << event[EVENT_ID] << " missing Message field: " << event.dump() << "\n";
        }
        return false;
    }

    // events to keep if filepath matches
    if (std::find(event_ids_with_filepath.begin(), event_ids_with_filepath.end(), event[EVENT_ID]) != event_ids_with_filepath.end()) {
        if (event.contains("FilePath")) {
            return std::strcmp(event["FilePath"].get<std::string>().c_str(), attack_exe_path.c_str());
        }
        if (g_debug) {
            std::cout << "[-] ETW: Warning: Event with ID " << event[EVENT_ID] << " missing FilePath field: " << event.dump() << "\n";
        }
        return false; // unexpected event fields, do not filter
    }

	return false; // else do not filter
}


// parses attack events
json attack_etw_to_json(Event e) {
    krabs::parser parser(e.schema);
    json j;

    try {
        j[TYPE] = "Attack";
        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
        );
        j[PID] = e.record.EventHeader.ProcessId;
        //j[TID] = e.record.EventHeader.ThreadId;
        j[PROVIDER_NAME] = wchar2string(e.schema.provider_name());
        j[EVENT_ID] = 13337;

        std::string msg;
        if (parser.try_parse(L"message", msg)) {
            j[TASK] = std::string(msg.begin(), msg.end());
        }
        else {
            j[TASK] = "(no message field)";
            std::cout << "[*] ETW: Warning: Attack event missing Message field " << j.dump() << "\n";
        }

        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: Attack Trace Exception: " << ex.what() << "\n";
        errors++;
        return json();
    }
}

// parses all other ETW events, , sets g_attack_done
json krabs_etw_to_json(Event e) {
    try {
        krabs::parser parser(e.schema);
        json j;

        j[TYPE] = "ETW";
        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
            );
        j[PID] = e.record.EventHeader.ProcessId;  // the pid in the header should always be the EDR process
        //j[TID] = e.record.EventHeader.ThreadId;
        j[EVENT_ID] = e.schema.event_id(); // opcode is the same as event_id, sometimes just a different number
        j[PROVIDER_NAME] = wchar2string(e.schema.provider_name());

		// task = task_name + opcode_name
        std::wstring combined = std::wstring(e.schema.task_name()) + std::wstring(e.schema.opcode_name());
        j[TASK] = wstring2string(combined);


        // Iterate over all properties defined in the schema
        for (const auto& property : parser.properties()) {
            try {
                // Get the name and type of the property
                const std::wstring& propertyName = property.name();
                const auto propertyType = property.type();

                /*
                * Reserved1":"0","Reserved2":"0","Reserved3":"0","Reserved4":"0",
                * "SignatureLevel":"(Unsupported type)\n","SignatureType":"(Unsupported type)\n
                if (wstring_starts_with(propertyName, L"Reserved") || wstring_starts_with(propertyName, L"Signature")) {
                    continue;
                }
                */
                std::string key = wstring2string((std::wstring&)propertyName);

                // check if it's a merged key --> write value to merged_key
                // TODO, just append ";value" to existing? --> needs same type, is this possible?
                for (const auto& cat : key_categories_to_merge) {
                    if (std::find(cat.keys_to_merge.begin(), cat.keys_to_merge.end(), key) != cat.keys_to_merge.end()) {
                        key = cat.merged_key;
                        if (j.contains(key)) {
                            std::cerr << "[*] ETW: Warning: Overwriting existing " << key << ":" << j[key] << "\n";
                        }
                    }
                }

                // Special cases
                if (propertyName == L"ProtectionMask" || propertyName == L"LastProtectionMask") {
                    uint32_t protection_mask = parser.parse<uint32_t>(propertyName);
                    j[key] = get_memory_region_protect(protection_mask);
                    continue;
                }

                switch (propertyType) {

                case TDH_INTYPE_UNICODESTRING:
                {
                    std::wstringstream wss;
                    wss << parser.parse<std::wstring>(propertyName);
                    std::string s = wstring2string((std::wstring&)wss.str());
                    j[key] = s;
                    break;
                }

                case TDH_INTYPE_ANSISTRING:
                {
                    j[key] = parser.parse<std::string>(propertyName);
                    break;
                }

                case TDH_INTYPE_INT8:
                {
                    j[key] = (int32_t)parser.parse<CHAR>(propertyName);
                    break;
                }

                case TDH_INTYPE_UINT8:
                {
                    j[key] = (uint32_t)parser.parse<UCHAR>(propertyName);
                    break;
                }

                case TDH_INTYPE_UINT32:
                {
                    j[key] = (uint32_t)parser.parse<uint32_t>(propertyName);
                    break;
                }

                case TDH_INTYPE_UINT64:
                {
                    j[key] = (uint64_t)parser.parse<uint64_t>(propertyName);
                    break;
                }

                case TDH_INTYPE_BOOLEAN:
                {
                    j[key] = (bool)parser.parse<BOOL>(propertyName);
                    break;
                }

                case TDH_INTYPE_POINTER:
                {
                    j[key] = (uint64_t)parser.parse<PVOID>(propertyName);
                    break;
                }

                case TDH_INTYPE_FILETIME:
                {
                    FILETIME fileTime = parser.parse<FILETIME>(propertyName);
                    ULARGE_INTEGER uli;
                    uli.LowPart = fileTime.dwLowDateTime;
                    uli.HighPart = fileTime.dwHighDateTime;
                    j[key] = uli.QuadPart;
                    break;
                }

                case TDH_INTYPE_SID:
                {
                    PSID sid = parser.parse<PSID>(propertyName);
                    LPWSTR sidString = nullptr;
                    if (ConvertSidToStringSidW(sid, &sidString)) {
                        std::wstring ws(sidString);
                        j[key] = wstring2string(ws);
                        LocalFree(sidString);
                    }
                    else {
                        j[key] = "invalid_sid";
                    }
                    break;
                }

                case TDH_INTYPE_HEXINT32:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint32_t>(propertyName);
                    j[key] = oss.str();
                    break;
                }

                case TDH_INTYPE_HEXINT64:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint64_t>(propertyName);
                    j[key] = oss.str();
                    break;
                }

                default:
                {
                    std::cout << "[*] ETW: Warning: Unsupported property type " << propertyType << " for " << j[TASK] << "'s " << key << "\n";
                    j[key] = "unsupported";
                    break;
                }
                }

            }
            catch (const std::exception& ex) {
                std::cerr << "[!] ETW: Failed to parse " << j[TASK] << ": " << ex.what() << "\n";
				errors++;
            }
        }

        // check if the attack_PID and injected_PID can be set, TODO more elegant
        if (g_attack_PID == 0 && j[EVENT_ID] == 73) {
            if (j.contains("FilePath") && j["FilePath"] == attack_exe_path) {
                g_attack_PID = j[PID];
                std::cout << "[+] ETW: Got attack PID: " << g_attack_PID << "\n";
            }
        }
        if (g_injected_PID == 0 && j[EVENT_ID] == 73) {
            if (j.contains("FilePath") && j["FilePath"] == injected_exe_path) {
                g_injected_PID = j[PID];
                std::cout << "[+] ETW: Got injected PID: " << g_injected_PID << "\n";
            }
        }

		// check if the attack is done
        if (!g_attack_done && j[PID] == g_attack_PID && j[EVENT_ID] == 73 && j["Source"] == "Termination") {
            g_attack_done = true;
            std::cout << "[+] ETW: Detected termination of attack PID\n";
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
            errors++;
        }
        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: General Exception: " << ex.what() << "\n";
        errors++;
        return json();
	}
}


// hand over schema for parsing
void attack_event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        etw_events.push_back(attack_etw_to_json(Event{ record, schema }));
    }
    catch (const std::exception& e) {
        std::cerr << "[!] ETW: attack_event_callback exception: " << e.what();
    }
    catch (...) {
        std::cerr << "[!] ETW: attack_event_callback unknown exception";
    }
}


// pre-filter EDR events and hand over schema for parsing, monitors events -> sets g_trace_running to true
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);

        DWORD processId = record.EventHeader.ProcessId;
        if (processId != g_EDR_PID) {
            return;
        }

		// check for antimalware engine version event, this is always the first event
        if (!g_trace_running && std::wstring(schema.provider_name()) == std::wstring(L"Microsoft-Antimalware-Engine") &&
            schema.event_id() == 4 && std::wstring(schema.task_name()) == std::wstring(L"Versions ")) {
            g_trace_running = true;
        }

		// convert it to json NOW or lose the property values
        json ev = krabs_etw_to_json(Event{ record, schema });

        // check if event can be filtered out
        if (filter_out(ev)) {
            if (g_debug) {
                std::cout << "[-] ETW: Filtered out event: " << ev.dump() << "\n";
            }
        }
        else {
            etw_events.push_back(ev);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "[!] ETW: event_callback exception: " << e.what();
    }
    catch (...) {
        std::cerr << "[!] ETW: event_callback unknown exception";
    }
}

DWORD WINAPI t_start_etw_trace(LPVOID param) {
    try {
        if (extensive) {
            // https://github.com/jdu2600/Etw-SyscallMonitor/tree/main/src/ETW
            /*
                1 ProcessStart
                2 ProcessStop
                3 ThreadStart
                4 ThreadStop
                5 ImageLoad
                6 ImageUnload
                11 ProcessFreeze
            */
            krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
            std::vector<unsigned short> process_event_ids = { 1, 2, 3, 4, 5, 6, 11 };
            krabs::event_filter process_filter(process_event_ids);
            process_provider.trace_flags(process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
            process_filter.add_on_event_callback(event_callback);
            process_provider.add_filter(process_filter);
            trace_user.enable(process_provider);
            std::cout << "[+] ETW: Microsoft-Windows-Kernel-Process: 1, 2, 3, 4, 5, 6, 11\n";

            /*
                1: PspLogAuditSetLoadImageNotifyRoutineEvent(kernel)
                2: PspLogAuditTerminateRemoteProcessEvent
                3: NtCreateSymbolicLink
                4: PspSetContextThreadInternal
                5: PspLogAuditOpenProcessEvent
                6: PspLogAuditOpenThreadEvent
                7: IoRegisterLastChanceShutdownNotification(kernel)
                8: IoRegisterShutdownNotification(kernel)
            */
            krabs::provider<> auditapi_provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");
            std::vector<unsigned short> auditapi_event_ids = { 3, 4, 5, 6 };
            krabs::event_filter auditapi_filter(auditapi_event_ids);
            auditapi_provider.trace_flags(auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
            auditapi_filter.add_on_event_callback(event_callback);
            auditapi_provider.add_filter(auditapi_filter);
            trace_user.enable(auditapi_provider);
            std::cout << "[+] ETW: Microsoft-Windows-Kernel-Audit-API-Calls: 3, 4, 5, 6\n";

            /*
                10 NameCreate
                17 SetInformation
                19 Rename
                22 QueryInformation
                23 FSCTL
                25 DirNotify
                26 DeletePath
                27 RenamePath
                28 SetLinkPath
                29 Rename
                30 CreateNewFile
                31 SetSecurity
                32 QuerySecurity
                33 SetEA
                34 QueryEA
            */
            krabs::provider<> kernelfile_provider(L"Microsoft-Windows-Kernel-File");
            std::vector<unsigned short> kernelfile_event_ids = { 10, 30 };
            krabs::event_filter kernelfile_filter(kernelfile_event_ids);
            kernelfile_provider.trace_flags(kernelfile_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
            kernelfile_filter.add_on_event_callback(event_callback);
            kernelfile_provider.add_filter(kernelfile_filter);
            trace_user.enable(kernelfile_provider);
            std::cout << "[+] ETW: Microsoft-Windows-Kernel-File: 10, 30\n";

            /*
                12 KERNEL_NETWORK_TASK_TCPIPConnectionattempted
                15 KERNEL_NETWORK_TASK_TCPIPConnectionaccepted
                28 KERNEL_NETWORK_TASK_TCPIPConnectionattempted
                31 KERNEL_NETWORK_TASK_TCPIPConnectionaccepted

                42 KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol
                43 KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol
                58 KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol
                59 KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol
            */
            krabs::provider<> kernelnetwork_provider(L"Microsoft-Windows-Kernel-Network");
            std::vector<unsigned short> kernelnetwork_event_ids = { 12, 15, 28, 31, 42, 43, 58, 59 };
            krabs::event_filter kernelnetwork_filter(kernelnetwork_event_ids);
            kernelnetwork_provider.trace_flags(kernelnetwork_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
            kernelnetwork_filter.add_on_event_callback(event_callback);
            kernelnetwork_provider.add_filter(kernelnetwork_filter);
            trace_user.enable(kernelnetwork_provider);
            std::cout << "[+] ETW: Microsoft-Windows-Kernel-Network: 12, 15, 28, 31, 42, 43, 58, 59\n";
        }

        krabs::guid attack_guid(L"{72248466-7166-4feb-a386-34d8f35bb637}");
        krabs::provider<> attack_provider(attack_guid);
        attack_provider.add_on_event_callback(attack_event_callback);
        trace_user.enable(attack_provider);
        std::cout << "[+] ETW: Injector-Attack (all)\n";

        krabs::provider<> antimalwareengine_provider(L"Microsoft-Antimalware-Engine");
        antimalwareengine_provider.add_on_event_callback(event_callback);
        trace_user.enable(antimalwareengine_provider);
        std::cout << "[+] ETW: Microsoft-Antimalware-Engine (all)\n";

		// blocking, use etw_reader_stop() to stop the trace
		std::cout << "[+] ETW: Trace started...\n";
        trace_user.start();
    }
    catch (const std::exception& e) {
        std::cout << "[!] ETW TraceProcessingThread exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cout << "[!] ETW TraceProcessingThread unknown exception\n";
    }

    std::cout << "[+] ETW: Thread finished\n";
    return 0;
}


bool start_etw_reader(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_etw_trace, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start thread\n";
        return false;
    }
    std::cout << "[+] ETW: Started Thread (handle " << thread << ")\n";
    threads.push_back(thread);
    return true;
}


void stop_etw_reader() {
    trace_user.stop();
}
