#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <detours/detours.h>
#include <iostream>
#include <chrono>

#include <TraceLoggingProvider.h>

// etw stuff
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Hook-Provider", // name in the ETW, cannot be a variable
    (0x72248411, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

UINT PID = 0;
const SIZE_T MSG_LEN = 1024;

UINT64 get_ns_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

void emit_etw_ok(std::string msg) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "HookTask", // the first event name is used for all events, unless using a manifest file
        TraceLoggingString(msg.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cout << "[+] Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "HookError",
        TraceLoggingString(error.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cerr << "[!] Hook-DLL: " << error << "\n";
};

void emit_etw_msg_ns(const char msg[], UINT64 tpid, UINT64 ns) {
    TraceLoggingWrite(
        g_hProvider,
        "HookTask",
        TraceLoggingString(msg, "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(tpid, "targetpid")
    );
};

using FnNtTerminateProcess = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
FnNtTerminateProcess TrueNtTerminateProcess = nullptr;

NTSTATUS NTAPI Hook_NtTerminateProcess(
    HANDLE   Handle,
    NTSTATUS ExitStatus
) {
    UINT64 ns = get_ns_time();
    char msg[MSG_LEN] = { 0 };

    int tpid = (int)GetProcessId(Handle); // can return garbage for non-process handles
	if (tpid >= 4 && tpid <= 0xFFFFFF) { // only log events for valid process handles
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
            "NtTerminateProcess with status 0x%lx",
            static_cast<LONG>(ExitStatus));
        emit_etw_msg_ns(msg, tpid, ns);
    }
    return TrueNtTerminateProcess(Handle, ExitStatus);
}

// local or remote trigger, but only valid when called from a thread current process
extern "C" __declspec(dllexport) void CALLBACK ActivateHook() {
    std::cout << "[*] Hook-DLL: ActivateHook called!\n";

    PID = GetCurrentProcessId();
    TraceLoggingRegister(g_hProvider);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return;
    }
    TrueNtTerminateProcess = (FnNtTerminateProcess)GetProcAddress(hNtdll, "NtTerminateProcess");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueNtTerminateProcess, Hook_NtTerminateProcess);
    DetourTransactionCommit();

    emit_etw_ok("Hooks installed");
}

// unload hooks
extern "C" __declspec(dllexport) void CALLBACK DeactivateHook() {
	std::cout << "[*] Hook-DLL: DeactivateHook called!\n";

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach(&(PVOID&)TrueNtTerminateProcess, Hook_NtTerminateProcess);
	DetourTransactionCommit();

	emit_etw_ok("Hooks removed");
    TraceLoggingUnregister(g_hProvider);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)ActivateHook, nullptr, 0, nullptr);
        break;
	case DLL_PROCESS_DETACH:
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)DeactivateHook, nullptr, 0, nullptr);
        break;
    default:
        break;
    }
    return TRUE;
}
