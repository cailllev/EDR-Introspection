#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

// Helper function to find a process ID by its executable name
DWORD GetProcessIdByName(const char* processName) {
	std::wstring wProcessName(processName, processName + strlen(processName));
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, wProcessName.c_str()) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

int main(int argc, char** argv) {
	if (argc == 2 && strcmp(argv[1], "-h") == 0) {
		std::cout << "Usage: " << argv[0] << " <target_process_name> <dll_path>\n";
        std::cout << "Experiment Setup: \n"
            "  1. open cmd, powershell and calc (only one of each)\n"
            "  2. run in cmd: ExternalHooker.exe powershell.exe \\path\\to\\InternalHooks.dll\n"
            "  3. run in powershell: Get-Process CalculatorApp\n"
            "Verification: There should be 2 lines in powershell stating 'MyNtOpenProcess called'\n";
		return 0;
	}

	if (argc < 3) {
		std::cout << "Usage: " << argv[0] << " <target_process_name> <dll_path>\n";
		return 1;
	}

	char* targetProcessName = argv[1];
    char* dllPath = argv[2];
	char* dllName = strrchr(dllPath, '\\') + 1;
	std::wstring wDllName(dllName, dllName + strlen(dllName));

    // 1. Find and open the target process
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0) {
        std::cout << "[-] Target process not found.\n";
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open target process. Error: " << GetLastError() << "\n";
        return 1;
    }

    // ==========================================
    // PHASE 1: Load the DLL into the target
    // ==========================================

    // Allocate space inside the target process to store the DLL path string
    void* remoteDllPathMemory = VirtualAllocEx(hProcess, nullptr, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteDllPathMemory == NULL) {
		std::cerr << "[-] Failed to allocate memory in target process. Error: " << GetLastError() << "\n";
        return 1;
    }
    WriteProcessMemory(hProcess, remoteDllPathMemory, dllPath, strlen(dllPath) + 1, nullptr);

    // Get the address of LoadLibraryA (it is at the same address across all Windows processes)
	HMODULE pKernel32 = GetModuleHandleA("kernel32.dll");
	if (pKernel32 == NULL) {
		std::cout << "[-] Failed to get handle for kernel32.dll.\n";
		CloseHandle(hProcess);
		return 1;
	}
    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(pKernel32, "LoadLibraryA");
	if (pLoadLibrary == NULL) {
		std::cout << "[-] Failed to get address of LoadLibraryA.\n";
		CloseHandle(hProcess);
		return 1;
	}

    // Fire the first CreateRemoteThread to load the DLL
    HANDLE hThread1 = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibrary, remoteDllPathMemory, 0, nullptr);
    if (!hThread1) {
        std::cout << "[-] Failed to create remote thread for LoadLibrary.\n";
        CloseHandle(hProcess);
        return 1;
    }

    // Wait for LoadLibrary to finish running inside the target
    WaitForSingleObject(hThread1, INFINITE);
    CloseHandle(hThread1);
    VirtualFreeEx(hProcess, remoteDllPathMemory, 0, MEM_RELEASE); // Clean up path memory

    std::cout << "[+] DLL successfully loaded into target process.\n";

    // ==========================================
    // PHASE 2: Trigger the Hook Activation
    // ==========================================

    // Load the DLL into OUR injector process temporarily just to calculate the function offset
    HMODULE hLocalDll = LoadLibraryA(dllPath);
    if (!hLocalDll) {
        std::cout << "[-] Injector couldn't load the DLL locally to read exports.\n";
        CloseHandle(hProcess);
        return 1;
    }

    void* pLocalFunc = (void*)GetProcAddress(hLocalDll, "ActivateHook");
    if (!pLocalFunc) {
        std::cout << "[-] Could not find 'ActivateHook' export in DLL.\n";
        FreeLibrary(hLocalDll);
        CloseHandle(hProcess);
        return 1;
    }

    // Calculate the offset: Where does ActivateHook live relative to the beginning of the DLL?
    DWORD_PTR functionOffset = (DWORD_PTR)pLocalFunc - (DWORD_PTR)hLocalDll;
    FreeLibrary(hLocalDll); // Done with our local copy

    // Find where the DLL was mapped inside the TARGET process (Remote Base Address)
    // Because Windows utilizes ASLR per-boot, system modules load identically across processes, 
    // but your custom DLL might shift. We dynamically grab the remote base address:
    DWORD_PTR remoteModuleBase = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32FirstW(snapshot, &modEntry)) {
            do {
                // Check if this module matches our DLL name
                if (wcsstr(modEntry.szModule, wDllName.c_str()) != nullptr) {
                    remoteModuleBase = (DWORD_PTR)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(snapshot, &modEntry));
        }
        CloseHandle(snapshot);
    }

    if (remoteModuleBase == 0) {
        std::cout << "[-] Failed to find the DLL base address in the target process.\n";
        CloseHandle(hProcess);
        return 1;
    }

    // Absolute pointer inside the target = Target's DLL Base + Our Pre-calculated Offset
    PTHREAD_START_ROUTINE pRemoteActivateHook = (PTHREAD_START_ROUTINE)(remoteModuleBase + functionOffset);

    // Fire the second CreateRemoteThread to execute ActivateHook() inside the target
    HANDLE hThread2 = CreateRemoteThread(hProcess, nullptr, 0, pRemoteActivateHook, nullptr, 0, nullptr);
    if (!hThread2) {
        std::cout << "[-] Failed to create remote thread for ActivateHook.\n";
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread2, INFINITE);
    CloseHandle(hThread2);

    std::cout << "[+] Hook successfully deployed remotely!\n";

    CloseHandle(hProcess);
    return 0;
}