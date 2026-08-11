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
    "Test-Hook-Provider", // name in the ETW, cannot be a variable
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
        "TestHookTask", // the first event name is used for all events, unless using a manifest file
        TraceLoggingString(msg.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cout << "[+] Test-Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error) {
    UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "TestHookError",
        TraceLoggingString(error.c_str(), "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(PID, "targetpid")
    );
    std::cerr << "[!] Test-Hook-DLL: " << error << "\n";
};

void emit_etw_msg_ns(const char msg[], UINT64 tpid, UINT64 ns) {
    TraceLoggingWrite(
        g_hProvider,
        "TestHookTask",
        TraceLoggingString(msg, "message"),
        TraceLoggingUInt64(ns, "ns_since_epoch"),
        TraceLoggingUInt64(tpid, "targetpid")
    );
};

using FnNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
FnNtOpenProcess TrueNtOpenProcess = nullptr;

NTSTATUS NTAPI Hook_NtOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	CLIENT_ID*         ClientId
) {
	UINT64 ns = get_ns_time();
	char msg[MSG_LEN] = { 0 };
	int tpid = (int)(ClientId ? (ULONG_PTR)ClientId->UniqueProcess : 0);
	if (tpid >= 4 && tpid <= 0xFFFFFF) { // only log events for valid process handles
		_snprintf_s(msg, sizeof(msg), _TRUNCATE,
			"NtOpenProcess with access 0x%lx",
			static_cast<LONG>(DesiredAccess));
		emit_etw_msg_ns(msg, tpid, ns);
	}
	return TrueNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// local or remote trigger, but only valid when called from a thread current process
extern "C" __declspec(dllexport) void CALLBACK ActivateHook() {
    std::cout << "[*] Test-Hook-DLL: ActivateHook called!\n";

    PID = GetCurrentProcessId();
    TraceLoggingRegister(g_hProvider);

    int retry = 0;
    while (!TraceLoggingProviderEnabled(g_hProvider, 0, 0) && retry++ < 10) {
        Sleep(10);
    }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    TrueNtOpenProcess = (FnNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");
	DetourAttach(&(PVOID&)TrueNtOpenProcess, Hook_NtOpenProcess);

    DetourTransactionCommit();

    emit_etw_ok("Hooks installed");
}

// unload hooks
extern "C" __declspec(dllexport) void CALLBACK DeactivateHook() {
	std::cout << "[*] Test-Hook-DLL: DeactivateHook called!\n";

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourDetach(&(PVOID&)TrueNtOpenProcess, Hook_NtOpenProcess);

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
