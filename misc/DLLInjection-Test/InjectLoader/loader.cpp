#include <windows.h>
#include <iostream>
#include <string>

#include "hooker.h"

enum Action {
    LOADLIBRARY_INJECTION,
    REFLECTIVE_INJECTION,
	STOP_INJECTION
};

int main(int argc, char* argv[]) {
    int pid = 0;
    std::string dllPath;

	std::string exePath = argv[0];
	std::string exeName = exePath.substr(exePath.find_last_of("\\/") + 1);

    if (argc > 1 && strcmp(argv[1], "-h") == 0) {
        std::cout << "[*] InjectLoader: Usage: " << exeName << " <DLL Path> <PID> [(L)oadLibrary | (R)eflective | (S)top]\n";
        return 0;
	}

    if (argc < 4) {
        std::cout << "[*] InjectLoader: Usage: " << exeName << " <DLL Path> <PID> [(L)oadLibrary | (R)eflective | (S)top]\n";
        return 1;
    }

    dllPath = argv[1];
    try {
        pid = std::stoi(argv[2]);
    } catch (const std::exception&) {
        std::cerr << "[!] InjectLoader: Invalid PID: " << argv[1] << "\n";
        return 1;
	}

    Action a;
    if (_stricmp(argv[3], "S") == 0 || _stricmp(argv[3], "stop") == 0) {
        a = STOP_INJECTION;
    } 
    else if (_stricmp(argv[3], "R") == 0 || _stricmp(argv[3], "reflective") == 0) {
        a = REFLECTIVE_INJECTION;
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


    switch(a) {
        case LOADLIBRARY_INJECTION:
            std::cout << "[*] InjectLoader: Attempting to inject DLL '" << dllPath << "' into PID=" << pid << " using LoadLibrary injection method.\n";
			inject_dll(pid, dllPath, false, false);
            break;
        case REFLECTIVE_INJECTION:
            std::cout << "[*] InjectLoader: Attempting to inject DLL '" << dllPath << "' into PID=" << pid << " using Reflective injection method.\n";
            inject_dll(pid, dllPath, false, true);
            break;
        case STOP_INJECTION:
            std::cout << "[*] InjectLoader: Unloading DLL in " << pid << "\n";
            char eventName[64];
            sprintf_s(eventName, "Global\\DLL_Stop_%lu", pid);
            HANDLE evt = OpenEventA(EVENT_MODIFY_STATE, FALSE, eventName);
            if (!evt) {
                std::cerr << "[!] InjectLoader: Failed to open stop event " << eventName << ": " << GetLastError() << "\n";
                return 1;
            }
            SetEvent(evt);
            return 0;
	}

    return 0;
}
