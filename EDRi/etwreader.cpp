#include <krabs.hpp>
#include <iostream>

#include "globals.h"
#include "utils.h"
#include "profile.h"
#include "etwreader.h"
#include "etwparser.h"


krabs::user_trace trace_etw(L"EDRi");
krabs::user_trace trace_etw_misc(L"EDRi-Misc");
krabs::user_trace trace_etw_ti(L"EDRi-TI");
krabs::user_trace trace_etw_hook(L"EDR-Hook");

DWORD WINAPI t_start_default_traces(LPVOID param) {
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
        krabs::provider<> process_provider(KERNEL_PROCESS_PROVIDER_W);
        std::vector<unsigned short> process_event_ids = { 1, 2, 3, 4, 5, 6, 11 };
        krabs::event_filter process_filter(process_event_ids);
        process_provider.trace_flags(process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        process_filter.add_on_event_callback(event_callback_std);
        process_provider.add_filter(process_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_PROCESS_PROVIDER << ": 1, 2, 3, 4, 5, 6, 11\n";
        trace_etw.enable(process_provider);

        // my attack trace
        krabs::guid attack_guid(ATTACK_GUID);
        krabs::provider<> attack_provider(attack_guid);
        attack_provider.add_on_event_callback(event_callback_std);
        std::cout << "[+] ETW: Enabling Injector-Attack: (all)\n";
        trace_etw.enable(attack_provider);

        // my EDRi trace, start last (start marker is consumed in this trace)
        krabs::guid parser_guid(EDRi_PROVIDER_GUID_W);
        krabs::provider<> parser_provider(parser_guid);
        parser_provider.add_on_event_callback(event_callback_std);
        std::cout << "[+] ETW: Enabling EDRi: (all)\n";
        trace_etw.enable(parser_provider);

        // trace_start is blocking, hence threaded
        std::cout << "[+] ETW: Default traces registered, starting...\n";
        trace_etw.start();
    }
    catch (const std::exception& e) {
        std::cout << "[!] ETW: Default traces exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cout << "[!] ETW: Default traces unknown exception\n";
    }

    std::cout << "[+] ETW: Kernel Proc trace thread finished\n";
    return 0;
}

DWORD WINAPI t_start_etw_misc_traces(LPVOID param) {
    try {
        // https://github.com/jdu2600/Etw-SyscallMonitor/tree/main/src/ETW
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
        krabs::provider<> auditapi_provider(KERNEL_API_PROVIDER_W);
        std::vector<unsigned short> auditapi_event_ids = { 3, 4, 5, 6 };
        krabs::event_filter auditapi_filter(auditapi_event_ids);
        auditapi_provider.trace_flags(auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        auditapi_filter.add_on_event_callback(event_callback_misc);
        auditapi_provider.add_filter(auditapi_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_API_PROVIDER << ": 3, 4, 5, 6\n";
        trace_etw_misc.enable(auditapi_provider);

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
        krabs::provider<> kernelfile_provider(KERNEL_FILE_PROVIDER_W);
        std::vector<unsigned short> kernelfile_event_ids = { 10, 30 };
        krabs::event_filter kernelfile_filter(kernelfile_event_ids);
        kernelfile_provider.trace_flags(kernelfile_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        kernelfile_filter.add_on_event_callback(event_callback_misc);
        kernelfile_provider.add_filter(kernelfile_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_FILE_PROVIDER << ": 10, 30\n";
        trace_etw_misc.enable(kernelfile_provider);

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
        krabs::provider<> kernelnetwork_provider(KERNEL_NETWORK_PROVIDER_W);
        std::vector<unsigned short> kernelnetwork_event_ids = { 12, 15, 28, 31, 42, 43, 58, 59 };
        krabs::event_filter kernelnetwork_filter(kernelnetwork_event_ids);
        kernelnetwork_provider.trace_flags(kernelnetwork_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        kernelnetwork_filter.add_on_event_callback(event_callback_misc);
        kernelnetwork_provider.add_filter(kernelnetwork_filter);
        std::cout << "[+] ETW: Enabling " << KERNEL_NETWORK_PROVIDER << ": 12, 15, 28, 31, 42, 43, 58, 59\n";
        trace_etw_misc.enable(kernelnetwork_provider);

        // Antimalware trace
        krabs::provider<> antimalwareengine_provider(ANTIMALWARE_PROVIDER_W);
        antimalwareengine_provider.add_on_event_callback(event_callback_misc);
        std::cout << "[+] ETW: Enabling " << ANTIMALWARE_PROVIDER << " (all)\n";
        trace_etw_misc.enable(antimalwareengine_provider);

        // trace_start is blocking, hence threaded
        std::cout << "[+] ETW: Misc trace registered, starting...\n";
        trace_etw_misc.start();
    }
    catch (const std::exception& e) {
        std::cout << "[!] ETW: Misc traces exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cout << "[!] ETW: Misc traces unknown exception\n";
    }

    std::cout << "[+] ETW: Misc traces thread finished\n";
    return 0;
}

DWORD WINAPI t_start_etw_ti_trace(LPVOID param) {
    try {
        krabs::provider<> ti_provider(THREAT_INTEL_PROVIDER_W); // "Microsoft-Windows-Threat-Intelligence"
        ti_provider.add_on_event_callback(event_callback_etw_ti);
        std::cout << "[+] ETW: Enabling ETW-TI: (all)\n";
        trace_etw_ti.enable(ti_provider);

        // trace_start is blocking, hence threaded
        std::cout << "[+] ETW: TI trace registered, starting...\n";
        trace_etw_ti.start();
    }
    catch (const std::exception& e) {
        std::cout << "[!] ETW: TI trace exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cout << "[!] ETW: TI trace unknown exception\n";
    }

    std::cout << "[+] ETW: TI trace thread finished\n";
    return 0;
}

DWORD WINAPI t_start_etw_hook_trace(LPVOID param) {
    try {
        krabs::guid hooks_guid(HOOKS_GUID);
        krabs::provider<> hooks_provider(hooks_guid);
        hooks_provider.add_on_event_callback(event_callback_hooks);
        std::cout << "[+] ETW: Enabling Hook-Provider: (all)\n";
        trace_etw_hook.enable(hooks_provider);

        // trace_start is blocking, hence threaded
        std::cout << "[+] ETW: NTDLL-Hook trace registered, starting...\n";
        trace_etw_hook.start();
    }
    catch (const std::exception& e) {
        std::cout << "[!] ETW: NTDLL-Hook trace exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cout << "[!] ETW: NTDLL-Hook trace unknown exception\n";
    }

    std::cout << "[+] ETW: NTDLL-Hook trace thread finished\n";
    return 0;
}

// always start the default traces
bool start_etw_default_traces(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_default_traces, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start ETW thread\n";
        return false;
    }
    threads.push_back(thread);
    return true;
}

bool start_etw_misc_traces(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_etw_misc_traces, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start ETW thread\n";
        return false;
    }
    threads.push_back(thread);
    return true;
}

bool start_etw_ti_trace(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_etw_ti_trace, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start ETW-TI thread\n";
        return false;
    }
    threads.push_back(thread);
    return true;
}

bool start_etw_hook_trace(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_etw_hook_trace, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start ETW-Hook thread\n";
        return false;
    }
    threads.push_back(thread);
    return true;
}

void stop_all_etw_traces() {
    try {
        trace_etw.stop();
		trace_etw_misc.stop();
        trace_etw_ti.stop();
        trace_etw_hook.stop();
    }
    catch (...) {
        std::cerr << "[!] ETW: Failed to stop traces\n";
    }
}