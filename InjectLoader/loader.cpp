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
    usage += "[*] InjectLoader: Usage: " + exeName + " <Target PID> <DLL Path> <(L)oadLibrary | (H)ostMapped | (R)eflective | (S)top> <(C)reateRemoteThread | (H)ijackThread | (Q)ueueUserAPC> [RiskInstability] [Debug]\n";
    usage += "[*] InjectLoader: Usage: " + exeName + " C:\\path\\to\\dll.dll 1234 LoadLibrary 1 1 1\n";
    usage += "[*] InjectLoader: Limitations against EDRs: \n";
    usage += "      - all inject techniques VM_Operation and VM_Write (usually denied via KernelCallbacks)\n";
    usage += "      - LoadLibrary denied by CodeIntegrity (non signed DLLs)\n";
    usage += "      - External inject denied by ACG (RW->RX) and CET (shadow stacks)\n";
    usage += "      - External inject assumes LoadLibraryA, GetProcAddress and RtlAddFunctionTable are at same addr cross-process\n";
    usage += "      - External inject requires the DLL to be compiled with GS- (Buffer Security Check disabled) and with RTC1 (without Runtime Checks)\n";
    usage += "      - Reflective inject requires selfLoading() entrypoint in DLL and be self loading\n";
    usage += "      - injection needs OpenProcess(PROCESS_ALL_ACCESS) (EDR procs: denied by PPL) or existing handles to the remote proc\n";
    usage += "      - injection via non-ThreadHijack needs CreateRemoteThread (EDR procs: denied via KernelCallbacks)\n";

    if (argc > 1 && strcmp(argv[1], "-h") == 0) {
        std::cout << usage;
        return 0;
    }
    if (argc < 7) {
        std::cout << usage;
        return 1;
    }

    try {
        pid = std::stoi(argv[1]);
        if (pid <= 0) {
            std::cerr << "[!] InjectLoader: PID must be a positive integer.\n";
            return 1;
        }
    }
    catch (const std::exception&) {
        std::cerr << "[!] InjectLoader: Invalid PID: " << argv[2] << "\n";
        return 1;
    }

    dllPath = argv[2];
    if (dllPath.empty()) {
        std::cerr << "[!] InjectLoader: DLL path cannot be empty.\n";
        return 1;
    }

    if (_stricmp(argv[3], "S") == 0 || _stricmp(argv[3], "stop") == 0) {
        std::cout << "[*] InjectLoader: Unloading DLL in " << pid << "\n";
        std::string dllName = dllPath.substr(dllPath.find_last_of("\\/") + 1);
        return UnloadViaThread(pid, dllName);
    }

    Injection injectType;
    if (_stricmp(argv[3], "L") == 0 || _stricmp(argv[3], "loadlibrary") == 0) {
        injectType = LOADLIBRARY_INJECTION;
    }
    else if (_stricmp(argv[3], "H") == 0 || _stricmp(argv[3], "hostmapped") == 0) {
        injectType = HOSTMAPPED_INJECTION;
    }
    else if (_stricmp(argv[3], "R") == 0 || _stricmp(argv[3], "reflective") == 0) {
        injectType = REFLECTIVE_INJECTION;
    }
    else {
        std::cerr << "[!] InjectLoader: InjectType '" << argv[3] << " 'not defined.\n";
        return 1;
    }

    Executor execType;
    if (_stricmp(argv[4], "C") == 0 || _stricmp(argv[4], "createremotethread") == 0) {
        execType = CREATE_REMOTE_THREAD;
    }
    else if (_stricmp(argv[4], "H") == 0 || _stricmp(argv[4], "hijackthread") == 0) {
		execType = HIJACK_THREAD;
	}
	else if (_stricmp(argv[4], "Q") == 0 || _stricmp(argv[4], "queueuserapc") == 0) {
		execType = QUEUE_USER_APC2;
	}
    else {
        std::cerr << "[!] InjectLoader: ExecType '" << argv[5] << " 'not defined.\n";
        return 1;
    }

    bool yoloMode = false;
    if (argc > 5 && argv[5][0] == '1') {
        std::cout << "[$] InjectLoader: Yolo mode activated, using any thread and ignore missing imports.\n";
        yoloMode = true;
    }

    bool debug = false;
    if (argc > 6 && argv[6][0] == '1') {
        std::cout << "[*] InjectLoader: Debug mode enabled.\n";
        debug = true;
    }

    HANDLE hProc = NULL;
    hProc = FindProcHandle(pid, debug);
    if (hProc) {
        std::cout << "[*] InjectLoader: Found existing process handle to remote process: " << hProc << "\n";
    }

    std::string actionStr = GetInjectTypeStr(injectType);
    std::string execStr = GetExecutorTypeStr(execType);
    std::cout << 
        "[*] InjectLoader: Attempting to \n"
        "           inject '" << dllPath << "'\n"
        "         into PID " << pid << "\n"
        "            using " << actionStr << "\n"
        "              and " << execStr << "\n";
    return InjectDll(pid, dllPath, hProc, injectType, execType, yoloMode, debug);
}
