#include <windows.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    std::cout << "[+] TestEXE: Started with PID: " << GetCurrentProcessId() << std::endl;

    if (argc < 2) {
        std::cout << "[:] TestEXE: No Pid provided, just waiting...\n";
        while (true) Sleep(1000);
        return 0;
    }

    int targetPid = std::stoi(argv[1]);
	if (targetPid <= 0) {
		std::cerr << "[!] TestEXE: Invalid PID provided: " << argv[1] << "\n";
		return 1;
	}


    // Open event handles created by TestProcess
    std::string triggerSignalName = "Local\\TestEXE_OpenProc_" + std::to_string(targetPid);
    HANDLE hTrigger = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, triggerSignalName.c_str());

    if (hTrigger) {
        std::cout << "[+] TestEXE: Waiting for trigger signal: " << triggerSignalName << "...\n";
        WaitForSingleObject(hTrigger, INFINITE);
        CloseHandle(hTrigger);
    }
    else {
		std::cerr << "[!] TestEXE: Failed to open trigger event: " << triggerSignalName << ". Error: " << GetLastError() << "\n";
        return 1;
    }

    // Execute OpenProcess on extracted PID
    if (targetPid != 0) {
        std::cout << "[+] TestEXE: Opening handle to PID: " << targetPid << "...\n";
        HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
		// this should fire a TestHookTask ETW event in the TestHook DLL if the DLL is active (injected)

        if (hTarget != NULL) {
            std::cout << "[+] TestEXE: Successfully opened PROCESS_ALL_ACCESS handle!\n";
        }
        else {
            std::cerr << "[!] TestEXE: OpenProcess failed! Error: " << GetLastError() << "\n";
            return 1;
        }
    }

    // Keep process alive until killed by parent's TerminateProcess
    while (true) {
        Sleep(1000);
    }

    return 0;
}