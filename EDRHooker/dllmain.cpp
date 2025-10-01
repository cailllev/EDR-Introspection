#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <map>
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
    PVOID ObjectAttributes,
    PVOID ClientId
    );

typedef NTSTATUS(NTAPI* PFN_NtReadVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
    );

typedef NTSTATUS(NTAPI* PFN_NtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
    );

typedef NTSTATUS(NTAPI* PFN_NtClose)(
    HANDLE ProcessHandle
    );

// trampolines created by MinHook
static PFN_NtOpenProcess g_origNtOpenProcess = nullptr;
static PFN_NtReadVirtualMemory g_origNtReadVirtualMemory = nullptr;
static PFN_NtWriteVirtualMemory g_origNtWriteVirtualMemory = nullptr;
static PFN_NtClose g_origNtClose = nullptr;


void emit_etw_ok(std::string msg) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookOk",
        TraceLoggingValue(msg.c_str(), "message")
    );
    std::cout << "[+] Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookError",
        TraceLoggingValue(error.c_str(), "message")
	);
	std::cerr << "[!] Hook-DLL: " << error << "\n";
};

void emit_open_etw_event(uint64_t target_pid, unsigned long d_access) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookOpenProc",
        TraceLoggingValue("NtOpenProcess", "message"),
        TraceLoggingUInt64(target_pid, "targetpid"),
        TraceLoggingULong(d_access, "d_acces")
    );
}

void emit_readvm_etw_event(uint64_t target_pid, void* base_address, uint64_t read_size) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookReadVM",
        TraceLoggingValue("NtReadVirtualMemory", "message"),
        TraceLoggingUInt64(target_pid, "targetpid"),
        TraceLoggingPointer(base_address, "base_address"),
        TraceLoggingUInt64(read_size, "read_size")
    );
}

void emit_writevm_etw_event(uint64_t target_pid, void* base_address, uint64_t read_size) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookWriteVM",
        TraceLoggingValue("NtWriteVirtualMemory", "message"),
        TraceLoggingUInt64(target_pid, "targetpid"),
        TraceLoggingPointer(base_address, "base_address"),
        TraceLoggingUInt64(read_size, "read_size")
    );
}

void emit_close_etw_event(uint64_t target_pid) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookCloseProc",
        TraceLoggingValue("NtCloseProcess", "message"),
        TraceLoggingUInt64(target_pid, "targetpid")
    );
}

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
    emit_open_etw_event(pid, DesiredAccess);

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

    emit_readvm_etw_event(pid, BaseAddress, NumberOfBytesToRead);

    // Call original
    return g_origNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS NTAPI Hook_NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
)
{
    DWORD pid = 0;
    if (ProcessHandle && ProcessHandle != GetCurrentProcess()) {
        pid = GetProcessId(ProcessHandle);
    }
    else if (ProcessHandle == GetCurrentProcess()) {
        pid = GetCurrentProcessId();
    }

    emit_writevm_etw_event(pid, BaseAddress, NumberOfBytesToWrite);

    // Call original
    return g_origNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NTAPI Hook_NtClose(HANDLE Handle)
{
    DWORD targetPid = 0;
    targetPid = GetProcessId(Handle);
    if (targetPid != 0) {
        emit_close_etw_event(targetPid);
	} // else it is not a process handle, ignore
    return g_origNtClose(Handle);
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

    // all functions to hook
    std::map<std::string, std::pair<void*, void**>> funcs = {
        {"NtOpenProcess", {(void*)Hook_NtOpenProcess, (void**)&g_origNtOpenProcess}},
        {"NtReadVirtualMemory", {(void*)Hook_NtReadVirtualMemory, (void**)&g_origNtReadVirtualMemory}},
        {"NtWriteVirtualMemory", {(void*)Hook_NtWriteVirtualMemory, (void**)&g_origNtWriteVirtualMemory}},
        {"NtClose", {(void*)Hook_NtClose, (void**)&g_origNtClose}}
    };

    for (auto& it : funcs) {
		std::string name = it.first;
		std::pair<void*, void**> fn = it.second;
        FARPROC target = GetProcAddress(hNtdll, name.c_str());
        if (!target) {
            emit_etw_error(name + " not found in ntdll");
            continue;
        }

        if (MH_CreateHook(target, fn.first, (LPVOID*)fn.second) != MH_OK || MH_EnableHook(target) != MH_OK) {
            emit_etw_error("Failed to hook " + name);
        }
        else {
            emit_etw_ok("Hooked " + name);
        }
    }
}

void RemoveHooks()
{
    if (!g_initialized.exchange(false)) return;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

DWORD WINAPI t_InitHooks(LPVOID param)
{
	InstallHooks();
    return 0;
}

DWORD WINAPI t_selfUnloadThread(LPVOID hinst) {
    Sleep(2000); // give the loader time to release the lock
    FreeLibraryAndExitThread((HMODULE)hinst, 0);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hinst);

        TCHAR processName[MAX_PATH] = { 0 };
        if (GetModuleBaseName(GetCurrentProcess(), nullptr, processName, MAX_PATH)) {
            bool allowed = false;
            for (auto& s : { _T("attack.exe"), _T("PowerShell.exe"), _T("MsMpEng.exe") }) {
                if (_tcsicmp(processName, s) == 0) {
                    allowed = true;
                    break;
                }
            }

            if (allowed) {
                TraceLoggingRegister(g_hProvider);
                CreateThread(nullptr, 0, t_InitHooks, nullptr, 0, nullptr);
            }
            else {
                // Only start the unload thread AFTER DllMain finishes
                HANDLE hThread = CreateThread(nullptr, 0, t_selfUnloadThread, (LPVOID)hinst, 0, nullptr);
                if (hThread) CloseHandle(hThread);
            }
        }
        break;
    }
    case DLL_PROCESS_DETACH:
        RemoveHooks();
        TraceLoggingUnregister(g_hProvider);
        break;
    }
    return TRUE;
}
