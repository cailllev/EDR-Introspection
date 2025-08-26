#include <krabs.hpp>
#include "json.hpp"
#include "globals.h"
#include "utils.h"
#include "etwreader.h"


struct Event {
    const EVENT_RECORD& record;
    const krabs::schema schema;
};
std::vector<json> etw_events;

krabs::user_trace trace_user(L"EDRIntrospection");
bool extensive = false; // enable more providers and events
int errors = 0;
bool g_trace_running = false;


json attack_etw_to_json(Event e) {
    krabs::parser parser(e.schema);
    json j;

    try {
        j[TYPE] = "Attack";
        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
        );
        j[PID] = e.record.EventHeader.ProcessId;
        j[TID] = e.record.EventHeader.ThreadId;
        j[PROVIDER_NAME] = wchar2string(e.schema.provider_name());
        j[EVENT_ID] = 13337;
        std::wstring msg;
        if (parser.try_parse(L"message", msg)) {
            j[TASK] = std::string(msg.begin(), msg.end());
        }
        else {
            j[TASK] = "(no message field)";
            std::cout << "[*] ETW: Warning: Attack event missing Message field " << j.dump() << "\n";
        }
        j[TASK] = parser.parse<std::string>(L"message");
        return j;
    }
    catch (const std::exception& ex) {
        std::cerr << "[!] ETW: Attack Trace Exception: " << ex.what() << "\n";
        errors++;
        return json();
    }
}


json krabs_etw_to_json(Event e) {
    try {
        krabs::parser parser(e.schema);
        json j;

        j[TYPE] = "ETW";
        j[TIMESTAMP] = filetime_to_iso8601(
            static_cast<__int64>(e.record.EventHeader.TimeStamp.QuadPart)
            );
        j[PID] = e.record.EventHeader.ProcessId;  // the pid in the header should always be the EDR process
        j[TID] = e.record.EventHeader.ThreadId;
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
                std::string jsonKey = wstring2string((std::wstring&)propertyName);

                // Special cases
                if (propertyName == L"ProtectionMask" || propertyName == L"LastProtectionMask") {
                    uint32_t protection_mask = parser.parse<uint32_t>(propertyName);
                    j[jsonKey] = get_memory_region_protect(protection_mask);
                    continue;
                }

                switch (propertyType) {

                case TDH_INTYPE_UNICODESTRING:
                {
                    std::wstringstream wss;
                    wss << parser.parse<std::wstring>(propertyName);
                    std::string s = wstring2string((std::wstring&)wss.str());
                    j[jsonKey] = s;
                    break;
                }

                case TDH_INTYPE_ANSISTRING:
                {
                    j[jsonKey] = parser.parse<std::string>(propertyName);
                    break;
                }

                case TDH_INTYPE_INT8:
                {
                    j[jsonKey] = (int32_t)parser.parse<CHAR>(propertyName);
                    break;
                }

                case TDH_INTYPE_UINT8:
                {
                    j[jsonKey] = (uint32_t)parser.parse<UCHAR>(propertyName);
                    break;
                }

                case TDH_INTYPE_UINT32:
                {
                    j[jsonKey] = (uint32_t)parser.parse<uint32_t>(propertyName);
                    break;
                }

                case TDH_INTYPE_UINT64:
                {
                    j[jsonKey] = (uint64_t)parser.parse<uint64_t>(propertyName);
                    break;
                }

                case TDH_INTYPE_BOOLEAN:
                {
                    j[jsonKey] = (bool)parser.parse<BOOL>(propertyName);
                    break;
                }

                case TDH_INTYPE_POINTER:
                {
                    j[jsonKey] = (uint64_t)parser.parse<PVOID>(propertyName);
                    break;
                }

                case TDH_INTYPE_FILETIME:
                {
                    FILETIME fileTime = parser.parse<FILETIME>(propertyName);
                    ULARGE_INTEGER uli;
                    uli.LowPart = fileTime.dwLowDateTime;
                    uli.HighPart = fileTime.dwHighDateTime;
                    j[jsonKey] = uli.QuadPart;
                    break;
                }

                case TDH_INTYPE_SID:
                {
                    PSID sid = parser.parse<PSID>(propertyName);
                    LPWSTR sidString = nullptr;
                    if (ConvertSidToStringSidW(sid, &sidString)) {
                        std::wstring ws(sidString);
                        j[jsonKey] = wstring2string(ws);
                        LocalFree(sidString);
                    }
                    else {
                        j[jsonKey] = "invalid_sid";
                    }
                    break;
                }

                case TDH_INTYPE_HEXINT32:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint32_t>(propertyName);
                    j[jsonKey] = oss.str();
                    break;
                }

                case TDH_INTYPE_HEXINT64:
                {
                    std::ostringstream oss;
                    oss << "0x" << std::hex << std::uppercase << parser.parse<uint64_t>(propertyName);
                    j[jsonKey] = oss.str();
                    break;
                }

                default:
                {
                    std::cout << "[*] ETW: Warning: Unsupported property type " << propertyType << " for " << j[TASK] << "'s " << jsonKey << "\n";
                    j[jsonKey] = "unsupported";
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
            if (j.contains("filepath") && j["filepath"] == attack_exe_path) {
                g_attack_PID = j[PID];
            }
        }
        if (g_injected_PID == 0 && j[EVENT_ID] == 73) {
            if (j.contains("filepath") && j["filepath"] == injected_exe_path) {
                g_injected_PID = j[PID];
            }
        }

        // callstack
        try {
            j["stack_trace"] = json::array();
            auto stack_trace = e.schema.stack_trace();
            int idx = 0;
            for (auto& return_address : stack_trace)
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


std::vector<json> get_events() {
	std::cout << "[+] ETW: Got " << etw_events.size() << " events\n";
	return etw_events;
}


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


// this function(-chain) should be high performance or events get lost
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
            g_trace_running = true; // TODO invoke attack here?
        }

		// convert it to json NOW or lose the property values
        etw_events.push_back(krabs_etw_to_json(Event{ record, schema }));
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
