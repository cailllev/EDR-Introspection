#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <map>
#include <stdio.h>
#include <stdint.h>
#include <string>
#include <atomic>
#include <fstream>

#include <MinHook.h>
#include <TraceLoggingProvider.h>

TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Hook-Provider", // name in the ETW, cannot be a variable
    (0x72248411, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // this cannot be a variable
);

static std::atomic<bool> g_initialized(false);

// types
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


void write_file(std::string msg) {
    std::ofstream outfile("C:\\Users\\Public\\Downloads\\out.txt");
    if (outfile.is_open())
    {
        outfile << msg;
        outfile.close();
    }
}

void emit_etw_ok(std::string msg, bool print = false) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookOk2",
        TraceLoggingString(msg.c_str(), "message")
    );
	if (print)
        std::cout << "[+] Hook-DLL: " << msg << "\n";
};

void emit_etw_error(std::string error, bool print = false) {
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookError",
        TraceLoggingString(error.c_str(), "message")
	);
    if (print)
	    std::cerr << "[!] Hook-DLL: " << error << "\n";
};

NTSTATUS NTAPI Hook_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
)
{
	// ProcessHandle points to the current process, ClientId to the target TODO confirm
    uint64_t pid = 0;
    if (ClientId) {
        pid = *(uintptr_t*)ClientId;
    }
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookOpenProc",
        TraceLoggingString("NtOpenProcess", "message"),
        TraceLoggingUInt64(pid, "targetpid"),
        TraceLoggingULong(DesiredAccess, "d_acces")
    );

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
    DWORD pid = GetProcessId(ProcessHandle);
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookReadVM",
        TraceLoggingString("NtReadVirtualMemory", "message"),
        TraceLoggingUInt64(pid, "targetpid"),
        TraceLoggingPointer(BaseAddress, "base_address"),
        TraceLoggingUInt64(NumberOfBytesToRead, "read_size")
    );

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
    DWORD pid = GetProcessId(ProcessHandle);
    TraceLoggingWrite(
        g_hProvider,
        "EDRHookWriteVM",
        TraceLoggingString("NtWriteVirtualMemory", "message"),
        TraceLoggingUInt64(pid, "targetpid"),
        TraceLoggingPointer(BaseAddress, "base_address"),
        TraceLoggingUInt64(NumberOfBytesToWrite, "write_size")
    );

    // Call original
    return g_origNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS NTAPI Hook_NtClose(HANDLE Handle)
{
    DWORD targetPid = GetProcessId(Handle);
    if (targetPid != 0) { // too many closing events of non procs
        TraceLoggingWrite(
            g_hProvider,
            "EDRHookCloseProc",
            TraceLoggingString("NtCloseProcess", "message"),
            TraceLoggingUInt64(targetPid, "targetpid")
        );
    }
    return g_origNtClose(Handle);
}


void InstallHooks()
{
    if (g_initialized.exchange(true)) return; // only once

    write_file("3");
    bool print_stdout = true;

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
    write_file("4");

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
            emit_etw_error(name + " not found in ntdll", print_stdout);
            continue;
        }

        if (MH_CreateHook(target, fn.first, (LPVOID*)fn.second) != MH_OK || MH_EnableHook(target) != MH_OK) {
            emit_etw_error("Failed to hook " + name, print_stdout);
        }
        else {
            emit_etw_ok("Hooked " + name, print_stdout);
        }
    }
    write_file("5");
    emit_etw_ok("++ NTDLL-HOOKER STARTED ++");
}

void RemoveHooks()
{
    if (!g_initialized.exchange(false)) return;
    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
}

DWORD WINAPI t_InitHooks(LPVOID param)
{
    //DisableThreadLibraryCalls(hinst);
    TraceLoggingRegister(g_hProvider);
    write_file("2");
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
    case DLL_PROCESS_ATTACH: 
    {
        HANDLE hTread = CreateThread(nullptr, 0, t_InitHooks, nullptr, 0, nullptr);
        if (!hTread) {
			std::cerr << "[!] Hook-DLL: Failed to create init thread\n";
			return FALSE;
        }
        std::cout << "[+] Hook-DLL: Created init thread\n";
        break;
    }
	case DLL_THREAD_ATTACH:
        break;
	case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        //RemoveHooks();
        //TraceLoggingUnregister(g_hProvider);
        break;
    }
    return TRUE;
}
