#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#include "hooker.h"

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
        std::wcerr << "[!] InjectLoader: Fail to NtOpenEvent " << eventName << ", WinErr = " << winerr << L"\n";
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

    for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
        PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[i];

        // Check if the handle is a process handle
        DWORD targetPid = _GetProcessId(entry.HandleValue);
        if (targetPid == pid) {
            if (debug) {
                printf("[+] InjectLoader: Proc handle found ID=0x%p, PID=%lu, Access=0x%08X\n", entry.HandleValue, targetPid, entry.GrantedAccess);
            }
            if (entry.GrantedAccess != PROCESS_ALL_ACCESS) {
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
            if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
            return entry.HandleValue;
        }
    }
    printf("[!] InjectLoader: No process handles found in the current process.\n");
    if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
    return 0;
}

int main(int argc, char* argv[]) {
    int pid = 0;
    std::string dllPath;

    std::string exePath = argv[0];
    std::string exeName = exePath.substr(exePath.find_last_of("\\/") + 1);
    std::string usage = "";
    usage += "[*] InjectLoader: Usage: " + exeName + " <DLL Path> <PID> <(L)oadLibrary | (E)xternal | (R)eflective | (S)top> <Debug> <FindProcHandle> <HijackThread>\n";
    usage += "[*] InjectLoader: Usage: " + exeName + " C:\\path\\to\\dll.dll 1234 LoadLibrary 0 1\n";

    if (argc > 1 && strcmp(argv[1], "-h") == 0) {
        std::cout << usage;
        return 0;
    }

    if (argc < 7) {
        std::cout << usage;
        return 1;
    }

    dllPath = argv[1];
    try {
        pid = std::stoi(argv[2]);
    }
    catch (const std::exception&) {
        std::cerr << "[!] InjectLoader: Invalid PID: " << argv[2] << "\n";
        return 1;
    }

    Action a;
    if (_stricmp(argv[3], "S") == 0 || _stricmp(argv[3], "stop") == 0) {
        a = STOP_INJECTION;
    }
    else if (_stricmp(argv[3], "R") == 0 || _stricmp(argv[3], "reflective") == 0) {
        a = REFLECTIVE_INJECTION;
    }
    else if (_stricmp(argv[3], "E") == 0 || _stricmp(argv[3], "external") == 0) {
        a = EXTERNAL_INJECTION;
    }
    else {
        a = LOADLIBRARY_INJECTION;
    }

    if (pid <= 0) {
        std::cerr << "[!] InjectLoader: PID must be a positive integer.\n";
        return 1;
    }
    if (dllPath.empty()) {
        std::cerr << "[!] InjectLoader: DLL path cannot be empty.\n";
        return 1;
    }

    bool debug = false;
    if (argv[4][0] == '1') {
        std::cout << "[*] InjectLoader: Debug mode enabled.\n";
        debug = true;
    }

    HANDLE hProc = NULL;
    if (argv[5][0] == '1') {
        std::cout << "[*] InjectLoader: Process handle already opened, searching for it...\n";
        hProc = findProcHandle(pid, debug);
		if (hProc == NULL) {
			std::cerr << "[!] InjectLoader: Failed to find process handle for PID " << pid << ".\n";
			return 1;
		}
		else {
			std::cout << "[*] InjectLoader: Found process handle: " << hProc << "\n";
		}
    }

	bool hijackThread = false;
    std::string hijackStr = "creating remote thread";
	if (argv[6][0] == '1') {
		std::cout << "[*] InjectLoader: Thread hijacking enabled.\n";
		hijackThread = true;
        hijackStr = "hijacking thread";
	}

    std::string actionStr;
    switch (a) {
    case LOADLIBRARY_INJECTION:
        actionStr = "LoadLibrary"; // todo also support thread hijack
        break;
    case EXTERNAL_INJECTION:
        actionStr = "External and Create Remote Thread";
        break;
    case REFLECTIVE_INJECTION:
		actionStr = "Reflective"; // todo also support thread hijack
        break;
    case STOP_INJECTION:
        std::cout << "[*] InjectLoader: Unloading DLL in " << pid << "\n";
        std::string dllName = dllPath.substr(dllPath.find_last_of("\\/") + 1);
        return Unload(pid, dllName);
    }

    std::cout << "[*] InjectLoader: Attempting to inject DLL '" << dllPath << "' into PID=" << pid << " using " << actionStr << " injection method and " << hijackStr << ".\n";
    return InjectDll(pid, dllPath, debug, a, hProc, hijackThread);
}
