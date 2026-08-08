#include "utils.h"
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

#define ProcessHandleInformation 51 // Information class 0x33

// Built-in structure for local handle snapshots
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );


HMODULE GetRemoteModuleHandle(DWORD pid, const std::wstring& moduleName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return NULL;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName.c_str()) == 0) {
                CloseHandle(snap);
                return me.hModule;  // remote addr 
            }
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return NULL;
}

int RemoteFreeLibrary(HANDLE hProcess, HMODULE remoteModule) {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel)
        return 1;

    LPVOID freeLibAddr = (LPVOID)GetProcAddress(hKernel, "FreeLibrary");

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        (LPTHREAD_START_ROUTINE)freeLibAddr,
        remoteModule, // must be remote addr of module handle
        0,
        nullptr
    );

    if (!hThread)
        return 1;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return 0;
}

typedef NTSTATUS(NTAPI* PFN_NtOpenEvent)(
    PHANDLE            EventHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef ULONG(WINAPI* PFN_RtlNtStatusToDosError)(
    NTSTATUS Status
    );

PFN_NtOpenEvent g_origNtOpenEvent = nullptr;
PFN_RtlNtStatusToDosError g_origRtlNtStatusToDosError = nullptr;

// unload via a global stop signal, else falls back to CreateRemoteThread(FreeLibrary)
// todo refactor into 2 functions
int Unload(int pid, std::string dllName) { // or just use a stopRequest.txt
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return 1;

    g_origNtOpenEvent = (PFN_NtOpenEvent)GetProcAddress(ntdll, "NtOpenEvent");
    g_origRtlNtStatusToDosError = (PFN_RtlNtStatusToDosError)GetProcAddress(ntdll, "RtlNtStatusToDosError");
    if (g_origNtOpenEvent == nullptr || g_origRtlNtStatusToDosError == nullptr) {
        std::wcerr << L"[!] InjectLoader: Failed to get NtOpenEvent or RtlNtStatusToDosError address.\n";
        return 1;
    }

    // build NT name
    wchar_t eventName[128];
    swprintf_s(eventName, _countof(eventName), L"\\BaseNamedObjects\\Hooks_Stop_%lu", (unsigned long)pid);

    // init UNICODE_STRING
    UNICODE_STRING us;
    RtlInitUnicodeString(&us, eventName);

    OBJECT_ATTRIBUTES oa = { 0 };
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hEvent = NULL;
    NTSTATUS st = g_origNtOpenEvent(&hEvent, EVENT_MODIFY_STATE | SYNCHRONIZE, &oa);

    if (!NT_SUCCESS(st)) {
        DWORD winerr = g_origRtlNtStatusToDosError(st);
        std::wcerr << "[!] InjectLoader: Failed to NtOpenEvent " << eventName << ", WinErr = " << winerr << L"\n";
        return 1;
    }
    else {
        std::wcout << "[-] InjectLoader: NtOpenEvent " << eventName << " ok, sending stop signal\n";
        SetEvent(hEvent);
        CloseHandle(hEvent);
    }

    Sleep(3000); // wait a bit for cleanup

    HMODULE hMod = GetRemoteModuleHandle(pid, std::wstring(dllName.begin(), dllName.end()));
    if (hMod != NULL) {
        HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        return RemoteFreeLibrary(hProc, hMod);
    }

    return 0;
}

HANDLE findProcHandle(int pid, BOOL debug) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll == 0) {
        printf("[!] InjectLoader: Failed to get handle to ntdll.dll\n");
        return 0;
    }
    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == 0) {
        printf("[!] InjectLoader: Failed to get address of NtQueryInformationProcess\n");
        return 0;
    }

    ULONG bufferSize = 0x4000; // Start with 16KB (plenty for a single local process)
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG returnLength = 0;

    // Query only OUR process handle table
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessHandleInformation,
        buffer,
        bufferSize,
        &returnLength
    );

    // Resize if needed
    if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        VirtualFree(buffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQueryInformationProcess(GetCurrentProcess(), ProcessHandleInformation, buffer, bufferSize, &returnLength);
    }

    if (status != 0) {
        printf("[!] InjectLoader: Unable to query handle information of current process.\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }


    PPROCESS_HANDLE_SNAPSHOT_INFORMATION localHandles = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer;
    if (localHandles == nullptr || localHandles->NumberOfHandles == 0) {
        printf("[!] InjectLoader: No handles found in the current process.\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    typedef DWORD(WINAPI* pfnGetProcessId)(HANDLE);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) {
        printf("[!] InjectLoader: Failed to get handle to kernel32.dll\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }
    pfnGetProcessId _GetProcessId = (pfnGetProcessId)GetProcAddress(hKernel32, "GetProcessId");
    if (!_GetProcessId) {
        printf("[!] InjectLoader: Failed to get address of GetProcessId\n");
        if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
        return 0;
    }

    PROCESS_HANDLE_TABLE_ENTRY_INFO potEntry{ 0 };
    for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
        PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[i];

        // Check if the handle is a process handle
        DWORD targetPid = _GetProcessId(entry.HandleValue);
        if (targetPid == pid) {
            if (debug) {
                printf("[+] InjectLoader: Proc handle found ID=0x%p, PID=%lu, Access=0x%08X\n", entry.HandleValue, targetPid, entry.GrantedAccess);
            }
            if (entry.GrantedAccess != PROCESS_ALL_ACCESS) {
				potEntry = entry; // safe as potential candidate, but not full access
            }
            if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
            return entry.HandleValue;
        }

        // check potential candidates
        if (potEntry.GrantedAccess != 0) {
            printf("[!] InjectLoader: Warning: Handle to pid=%i found but limited access 0x%08X\n", pid, entry.GrantedAccess);
            printf("[*] InjectLoader: Continue searching? Y/n");
            int c = getchar();
            if (c == 'n') {
                if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
                return entry.HandleValue;
            }
            else {
                // continue searching
            }
        }
    }
    printf("[!] InjectLoader: No process handles found in the current process.\n");
    if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}