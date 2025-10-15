#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <cctype>

bool enable_debug_privilege()
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << "\n";
        return false;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;
    if (!LookupPrivilegeValueA(nullptr, "SeDebugPrivilege", &luid)) {
        std::cerr << "LookupPrivilegeValueA failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        std::cerr << "AdjustTokenPrivileges failed: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "SeDebugPrivilege not assigned to this token\n";
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

// Minimal OBJECT_BASIC_INFORMATION from winternl
typedef struct _OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];
} OBJECT_BASIC_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryObject(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

std::string get_proc_access_details(DWORD granted) {
    struct { DWORD mask; const char* name; } flags[] = {
        {0x0001, "PROCESS_TERMINATE"},
        {0x0002, "PROCESS_CREATE_THREAD"},
        {0x0004, "PROCESS_SET_SESSIONID"},
        {0x0008, "PROCESS_VM_OPERATION"},
        {0x0010, "PROCESS_VM_READ"},
        {0x0020, "PROCESS_VM_WRITE"},
        {0x0040, "PROCESS_DUP_HANDLE"},
        {0x0080, "PROCESS_CREATE_PROCESS"},
        {0x0100, "PROCESS_SET_QUOTA"},
        {0x0200, "PROCESS_SET_INFORMATION"},
        {0x0400, "PROCESS_QUERY_INFORMATION"},
        {0x0800, "PROCESS_SUSPEND_RESUME"},
        {0x1000, "PROCESS_QUERY_LIMITED_INFORMATION"},
        {0x2000, "PROCESS_SET_LIMITED_INFORMATION"}
    };

    std::string access = "";
    for (auto& f : flags) {
        if (granted & f.mask) {
            access += std::string(f.name) + " | ";
        }
    }
    if (!access.empty()) {
        access = access.substr(0, access.size() - 3); // remove last " | "
    }
    else {
		return "no access";
    }
    std::string no_access = "";
    for (auto& f : flags) {
        if (!(granted & f.mask)) {
            no_access += std::string(f.name) + " | ";
        }
    }
    if (!no_access.empty()) {
        no_access = no_access.substr(0, no_access.size() - 3); // remove last " | "
    }
    else {
        return "full access";
    }
    return access + ", not including: " + no_access;
}

void print_granted_access(HANDLE h, int pid) {
    OBJECT_BASIC_INFORMATION obi = {};
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(h, ObjectBasicInformation, &obi, sizeof(obi), &ret);
    if (st < 0) {
        std::cerr << "[!] Hooker: NtQueryObject failed at pid " << pid << ": 0x" << std::hex << st << "\n";
    }
    else {
		std::string details = get_proc_access_details(obi.GrantedAccess);
        std::cout << "[+] Hooker: GrantedAccess to pid " << pid << ": 0x" << std::hex << obi.GrantedAccess << std::dec << " -> " << details << "\n";
    }
}

// Inject DLL into target process
bool inject_dll(int pid, const std::string& dllPath, bool debug)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE, pid);

    if (!hProcess) {
        std::cerr << "[!] Hooker: Failed to open target process. Error: " << GetLastError() << "\n";
        return false;
    }
    BOOL isWow = FALSE;
    if (IsWow64Process(hProcess, &isWow)) {
        if (isWow) {
            std::cerr << "[!] Hooker: Target process is 32-bit, but this injector is 64-bit. Cannot inject.\n";
            CloseHandle(hProcess);
            return false;
        }
    }
    else {
        std::cerr << "[!] Hooker: IsWow64Process failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    print_granted_access(hProcess, pid);

    // Allocate memory for DLL path in target
    size_t size = dllPath.length() + 1;
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dllPathAddr) {
        std::cerr << "[!] Hooker: VirtualAllocEx failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
		std::cout << "[*] Hooker: Allocated memory in target process at " << dllPathAddr << "\n";
    }

    // Write DLL path into target
    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath.c_str(), size, nullptr)) {
        std::cerr << "[!] Hooker: WriteProcessMemory failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Wrote '" << dllPath << "' to target process memory\n";
	}

    // Get LoadLibraryA address
    HMODULE lpModuleHandle = GetModuleHandleA("kernel32.dll");
    if (!lpModuleHandle) {
        std::cerr << "[!] Hooker: GetModuleHandle failed\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    LPVOID loadLibAddr = (LPVOID)GetProcAddress(lpModuleHandle, "LoadLibraryA");
    if (!loadLibAddr) {
        std::cerr << "[!] Hooker: GetProcAddress of LoadLibrary failed\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread (start the DLL)
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibAddr, dllPathAddr, 0, nullptr);
    DWORD err = GetLastError();
    if (!hThread || err != 0) {
        std::cerr << "[!] Hooker: CreateRemoteThread failed. Error: " << err << "\n";
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    if (debug) {
        std::cout << "[*] Hooker: Created remote thread in target process\n";
	}
    
    DWORD wait = WaitForSingleObject(hThread, 10000); // 5 sec timeout for hooks to init
    if (wait == WAIT_TIMEOUT) {
        std::cerr << "[!] Hooker: remote thread did not finish within timeout\n";
		return false;
    }

    // Get exit code (for LoadLibrary, exit code == HMODULE returned)
    DWORD hModule = 0;
    if (!GetExitCodeThread(hThread, &hModule)) {
        std::cerr << "[!] Hooker: GetExitCodeThread failed. Error: " << GetLastError() << "\n";
        CloseHandle(hThread);
        return false;
    }
    CloseHandle(hThread);
    if (hModule == 0) {
        std::cerr << "[!] Hooker: remote routine (e.g. LoadLibrary) failed: " << GetLastError() << "\n";
        return false;
    }

    std::cout << "[*] Hooker: remote routine succeeded, module handle: " << std::hex << hModule << "\n";
    return true;
}

static HMODULE GetRemoteModuleBase(HANDLE hProcess, const std::wstring& moduleName) {
    DWORD pid = GetProcessId(hProcess);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    HMODULE base = nullptr;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, moduleName.c_str()) == 0) {
                base = (HMODULE)me.modBaseAddr;
                break;
            }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}

bool unload_dll(int pid, const std::string& dllName)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE, pid);

    if (!hProcess) {
        std::cerr << "[!] Hooker: Failed to open target process. Error: " << GetLastError() << "\n";
        return false;
    }

    // Ensure target bitness compatibility
    BOOL isWow = FALSE;
    if (!IsWow64Process(hProcess, &isWow)) {
        std::cerr << "[!] Hooker: IsWow64Process failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    if (isWow) {
        std::cerr << "[!] Hooker: Target process is 32-bit, but this injector is 64-bit. Cannot operate.\n";
        CloseHandle(hProcess);
        return false;
    }

    // Convert dllName (narrow) to wide for comparison with module names from Toolhelp
    std::wstring wDllName;
    {
        int req = MultiByteToWideChar(CP_UTF8, 0, dllName.c_str(), -1, nullptr, 0);
        if (req <= 0) {
            std::cerr << "[!] Hooker: Failed to convert dll name to wide string\n";
            CloseHandle(hProcess);
            return false;
        }
        wDllName.resize(req - 1);
        MultiByteToWideChar(CP_UTF8, 0, dllName.c_str(), -1, &wDllName[0], req);
    }

    // Find the remote module base (the injected DLL base in the target process)
    HMODULE remoteModuleBase = GetRemoteModuleBase(hProcess, wDllName);
    if (!remoteModuleBase) {
        std::cerr << "[!] Hooker: Could not find remote module '" << dllName << "' in target process.\n";
        CloseHandle(hProcess);
        return false;
    }
    std::cout << "[*] Hooker: Remote module base: " << std::hex << (uintptr_t)remoteModuleBase << std::dec << "\n";

    // Get local addresses for kernel32 and FreeLibraryAndExitThread
    HMODULE localKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!localKernel32) {
        std::cerr << "[!] Hooker: GetModuleHandle(kernel32) failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }
    FARPROC localFreeAndExit = GetProcAddress(localKernel32, "FreeLibraryAndExitThread");
    if (!localFreeAndExit) {
        std::cerr << "[!] Hooker: GetProcAddress(FreeLibraryAndExitThread) failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    // Compute offset of FreeLibraryAndExitThread within local kernel32
    uintptr_t offsetFree = (uintptr_t)localFreeAndExit - (uintptr_t)localKernel32;

    // Find remote kernel32 base
    HMODULE remoteKernel32 = GetRemoteModuleBase(hProcess, L"kernel32.dll");
    if (!remoteKernel32) {
        std::cerr << "[!] Hooker: Could not find kernel32.dll in target process\n";
        CloseHandle(hProcess);
        return false;
    }

    // Compute remote address of FreeLibraryAndExitThread
    LPTHREAD_START_ROUTINE remoteFreeAndExit = (LPTHREAD_START_ROUTINE)((uintptr_t)remoteKernel32 + offsetFree);

    std::cout << "[*] Hooker: remote FreeLibraryAndExitThread addr = " << std::hex << (uintptr_t)remoteFreeAndExit << std::dec << "\n";

    // Create remote thread that calls FreeLibraryAndExitThread(remoteModuleBase, 0)
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, remoteFreeAndExit, (LPVOID)remoteModuleBase, 0, nullptr);
    if (!hThread) {
        std::cerr << "[!] Hooker: CreateRemoteThread for FreeLibrary failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the thread to exit (reasonable timeout)
    DWORD wait = WaitForSingleObject(hThread, 10000); // 10s
    if (wait == WAIT_TIMEOUT) {
        std::cerr << "[!] Hooker: FreeLibrary thread timed out\n";
        // Optionally, try TerminateThread (not recommended). We'll continue to check state below.
    }

    // Optionally get exit code (FreeLibraryAndExitThread calls ExitThread with last parameter,
    // but we mainly want to verify module is gone)
    DWORD exitCode = 0;
    if (GetExitCodeThread(hThread, &exitCode)) {
        std::cout << "[*] Hooker: FreeLibrary thread exit code: " << exitCode << "\n";
    }

    CloseHandle(hThread);

    // Verify module is unloaded
    HMODULE stillThere = GetRemoteModuleBase(hProcess, wDllName);
    if (stillThere) {
        std::cerr << "[!] Hooker: Module still present after FreeLibrary: " << std::hex << (uintptr_t)stillThere << std::dec << "\n";
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Hooker: Successfully unloaded module '" << dllName << "'\n";
    CloseHandle(hProcess);
    return true;
}


