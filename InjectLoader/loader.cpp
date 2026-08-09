#include <iostream>
#include <string>

#include "utils.h"
#include "hooker.h"

int main(int argc, char* argv[]) {
    int pid = 0;
    std::string dllPath;

    std::string exePath = argv[0];
    std::string exeName = exePath.substr(exePath.find_last_of("\\/") + 1);
    std::string usage = "";
    usage += "[*] InjectLoader: Usage: " + exeName + " <DLL Path> <PID> <(L)oadLibrary | (E)xternal | (R)eflective | (S)top> <Debug> <FindProcHandle> <(C)reateRemoteThread | (H)ijackThread | (Q)ueueUserAPC>\n";
    usage += "[*] InjectLoader: Usage: " + exeName + " C:\\path\\to\\dll.dll 1234 LoadLibrary 1 1 1\n";
    usage += "[*] InjectLoader: Limitations against EDRs: \n";
    usage += "      - all inject techniques VM_Operation and VM_Write (usually denied via KernelCallbacks)\n";
    usage += "      - LoadLibrary denied by CodeIntegrity (non signed DLLs)\n";
    usage += "      - External inject denied by ACG (RW->RX) and CET (shadow stacks)\n";
    usage += "      - External inject assumes LoadLibraryA, GetProcAddress and RtlAddFunctionTable are at same addr cross-process\n";
    usage += "      - External inject requires the DLL to be compiled with GS- (Buffer Security Check disabled) and with RTC1 (without Runtime Checks)\n";
    usage += "      - Reflective inject requires selfLoading() entrypoint in DLL and be self loading\n";
    usage += "      - injection via non-FindProcHandle needs OpenProcess(PROCESS_ALL_ACCESS) (EDR procs: denied by PPL)\n";
    usage += "      - injection via non-ThreadHijack needs CreateRemoteThread (EDR procs: denied via KernelCallbacks)\n";

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
    std::string actionStr;
    if (_stricmp(argv[3], "S") == 0 || _stricmp(argv[3], "stop") == 0) {
        std::cout << "[*] InjectLoader: Unloading DLL in " << pid << "\n";
        std::string dllName = dllPath.substr(dllPath.find_last_of("\\/") + 1);
        return UnloadViaThread(pid, dllName);
    }
    else if (_stricmp(argv[3], "R") == 0 || _stricmp(argv[3], "reflective") == 0) {
        a = REFLECTIVE_INJECTION;
		actionStr = "Reflective injection";
    }
    else if (_stricmp(argv[3], "E") == 0 || _stricmp(argv[3], "external") == 0) {
        a = EXTERNAL_INJECTION;
		actionStr = "External injection";
    }
    else if (_stricmp(argv[3], "H") == 0 || _stricmp(argv[3], "hijackthreadtest") == 0) {
        a = HIJACK_THREAD_TEST;
		actionStr = "HijackThread test";
    }
    else {
        a = LOADLIBRARY_INJECTION;
		actionStr = "LoadLibrary injection";
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

    Execution e;
    std::string execStr;
    if (_stricmp(argv[6], "H") == 0 || _stricmp(argv[6], "hijackthread") == 0) {
		e = HIJACK_THREAD;
		execStr = "HijackThread";
	}
	else if (_stricmp(argv[6], "Q") == 0 || _stricmp(argv[6], "queueuserapc") == 0) {
		e = QUEUE_USER_APC2;
		execStr = "QueueUserAPC2";
	}
	else {
		e = CREATE_REMOTE_THREAD;
		execStr = "CreateRemoteThread";
	}

    std::cout << "[*] InjectLoader: Attempting to inject DLL '" << dllPath << "' into PID=" << pid << " using " << actionStr << " injection method and " << execStr << " execution.\n";
    return InjectDll(pid, dllPath, debug, a, hProc, e);
}
