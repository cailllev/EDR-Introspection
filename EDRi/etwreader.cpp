#include <krabs.hpp>
#include <iostream>

#include "globals.h"
#include "utils.h"
#include "filter.h"
#include "profile.h"
#include "etwreader.h"
#include "etwparser.h"


krabs::user_trace trace_user(L"EDRi");

DWORD WINAPI t_start_etw_traces(LPVOID param) {
    try {
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
            12 TCPIPConnectionattempted
            15 TCPIPConnectionaccepted
            28 TCPIPConnectionattempted
            31 TCPIPConnectionaccepted
            42 UDPIPDatasentoverUDPprotocol
            43 UDPIPDatareceivedoverUDPprotocol
            58 UDPIPDatasentoverUDPprotocol
            59 UDPIPDatareceivedoverUDPprotocol
        */
        krabs::provider<> kernelnetwork_provider(L"Microsoft-Windows-Kernel-Network");
        std::vector<unsigned short> kernelnetwork_event_ids = { 12, 15, 28, 31, 42, 43, 58, 59 };
        krabs::event_filter kernelnetwork_filter(kernelnetwork_event_ids);
        kernelnetwork_provider.trace_flags(kernelnetwork_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        kernelnetwork_filter.add_on_event_callback(event_callback);
        kernelnetwork_provider.add_filter(kernelnetwork_filter);
        trace_user.enable(kernelnetwork_provider);
        std::cout << "[+] ETW: Microsoft-Windows-Kernel-Network: 12, 15, 28, 31, 42, 43, 58, 59\n";

        // my EDRi trace
        krabs::guid parser_guid(EDRi_PROVIDER_GUID_W);
        krabs::provider<> parser_provider(parser_guid);
        parser_provider.add_on_event_callback(my_event_callback);
        trace_user.enable(parser_provider);
        std::cout << "[+] ETW: EDRi (all)\n";

        // my attack trace
        krabs::guid attack_guid(L"{72248466-7166-4feb-a386-34d8f35bb637}");
        krabs::provider<> attack_provider(attack_guid);
        attack_provider.add_on_event_callback(my_event_callback);
        trace_user.enable(attack_provider);
        std::cout << "[+] ETW: Injector-Attack (all)\n";

        // Antimalware trace, start last!
        krabs::provider<> antimalwareengine_provider(ANTIMALWARE_PROVIDER_W);
        antimalwareengine_provider.add_on_event_callback(event_callback);
        trace_user.enable(antimalwareengine_provider);
        std::cout << "[+] ETW: " << ANTIMALWARE_PROVIDER << " (all)\n";

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

bool start_etw_traces(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_etw_traces, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start thread\n";
        return false;
    }
    std::cout << "[+] ETW: Started Thread (handle " << thread << ")\n";
    threads.push_back(thread);
    return true;
}

void stop_etw_traces() {
    trace_user.stop();
}