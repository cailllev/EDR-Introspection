#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <atomic>

#include <MinHook.h>
#include <TraceLoggingProvider.h>

TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Hook-Provider", // name in the ETW, cannot be a variable
    (0x72248411, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

static std::atomic<bool> g_initialized(false);

// types
typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* PFN_NtOpenProcess)(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,   // POBJECT_ATTRIBUTES (opaque here)
    PVOID ClientId            // PCLIENT_ID (opaque here)
    );

typedef NTSTATUS(NTAPI* PFN_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
    );

// trampolines created by MinHook
static PFN_NtOpenProcess g_origNtOpenProcess = nullptr;
static PFN_NtReadVirtualMemory g_origNtReadVirtualMemory = nullptr;

void emit_etw_ok(std::string msg) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookEvent",
        TraceLoggingValue(msg.c_str(), "message")
    );
    std::cout << "[+] Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookEvent",
        TraceLoggingValue(error.c_str(), "message")
	);
	std::cerr << "[!] Hook-DLL: " << error << "\n";
};

void emit_open_etw_event(uint64_t target_pid, unsigned long d_access, void* caller) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookEvent",
        TraceLoggingValue("NtOpenProcess", "event"),
        TraceLoggingUInt64(target_pid, "target_pid"),
        TraceLoggingULong(d_access, "d_acces"),
        TraceLoggingPointer(caller, "caller")
    );
}

void emit_read_etw_event(uint64_t target_pid, void* base_address, uint64_t read_size, void* caller) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookEvent",
        TraceLoggingValue("NtReadVirtualMemory", "event"),
        TraceLoggingUInt64(target_pid, "target_pid"),
        TraceLoggingPointer(base_address, "base_address"),
        TraceLoggingUInt64(read_size, "read_size"),
        TraceLoggingPointer(caller, "caller")
    );
}

// helper to safely capture return address (caller RIP)
extern "C" void* GetReturnAddress() { return _ReturnAddress(); }

NTSTATUS NTAPI Hook_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
)
{
    // ClientId is a CLIENT_ID* in normal defs: { UniqueProcess (HANDLE), UniqueThread (HANDLE) }
    uint64_t pid = 0;
    if (ClientId) {
        // CLIENT_ID layout: two pointers. Read first pointer as pid (works in most cases).
        pid = *(uintptr_t*)ClientId;
    }
    void* caller = GetReturnAddress();
    emit_open_etw_event(pid, DesiredAccess, caller);

    // Call original
    return g_origNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS NTAPI Hook_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
)
{
    // Resolve target PID from handle (safe-ish)
    DWORD pid = 0;
    if (ProcessHandle && ProcessHandle != GetCurrentProcess()) {
        pid = GetProcessId(ProcessHandle);
    }
    else if (ProcessHandle == GetCurrentProcess()) {
        pid = GetCurrentProcessId();
    }

    void* caller = GetReturnAddress();
    emit_read_etw_event(pid, BaseAddress, NumberOfBytesToRead, caller);

    // Call original
    return g_origNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}


void InstallHooks()
{
    if (g_initialized.exchange(true)) return; // only once

    // MinHook init
    if (MH_Initialize() != MH_OK) {
        emit_etw_error("MinHook init failed");
        return;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        emit_etw_error("ntdll not loaded");
        return;
    }

    // Get addresses for raw ntdll functions
    FARPROC pNtOpenProcess = GetProcAddress(hNtdll, "NtOpenProcess");
    FARPROC pNtReadVirtualMemory = GetProcAddress(hNtdll, "NtReadVirtualMemory");
    if (pNtOpenProcess) {
        if (MH_CreateHook(pNtOpenProcess, &Hook_NtOpenProcess, reinterpret_cast<LPVOID*>(&g_origNtOpenProcess)) != MH_OK ||
            MH_EnableHook(pNtOpenProcess) != MH_OK) {
            emit_etw_error("Failed to hook NtOpenProcess");
        }
        else {
            emit_etw_ok("Hooked NtOpenProcess");
        }
    }
    else {
        emit_etw_error("NtOpenProcess not found");
    }

    if (pNtReadVirtualMemory) {
        if (MH_CreateHook(pNtReadVirtualMemory, &Hook_NtReadVirtualMemory, reinterpret_cast<LPVOID*>(&g_origNtReadVirtualMemory)) != MH_OK ||
            MH_EnableHook(pNtReadVirtualMemory) != MH_OK) {
            emit_etw_error("Failed to hook NtReadVirtualMemory");
        }
        else {
            emit_etw_ok("Hooked NtReadVirtualMemory");
        }
    }
    else {
        emit_etw_error("NtReadVirtualMemory not found");
    }
}

void RemoveHooks()
{
    if (!g_initialized.exchange(false)) return;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

DWORD WINAPI t_InitHooks(LPVOID)
{
    InstallHooks();
    return 0;
}

// DllMain: must be lightweight
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        TraceLoggingRegister(g_hProvider); // register ETW provider
        DisableThreadLibraryCalls(hinst); // more performant?
        CreateThread(nullptr, 0, t_InitHooks, nullptr, 0, nullptr);
        break;
    case DLL_PROCESS_DETACH:
        RemoveHooks();
        TraceLoggingUnregister(g_hProvider);
        break;
    }
    return TRUE;
}
