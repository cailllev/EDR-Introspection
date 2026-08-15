#include <windows.h>
#include <iostream>
#include <string>


// waits for trigger to do a OpenProcess syscall
int WaitForOpenProcessTrigger(HANDLE hTrigger, DWORD targetPid) {

    WaitForSingleObject(hTrigger, INFINITE); // hangs until received
    std::cout << "[*] TestEXE: Got signal, do OpenProcess()\n";
    CloseHandle(hTrigger); // close handle after trigger received

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    // this should fire a TestHookTask ETW event in the TestHook DLL if the DLL is active (injected)

    if (hTarget == NULL) {
        std::cerr << "[!] TestEXE: OpenProcess failed! Error: " << GetLastError() << "\n";
        return 1;
    }
    std::cout << "[+] TestEXE: Successfully opened PROCESS_ALL_ACCESS handle!\n";
    CloseHandle(hTarget);
    return 0;
}

// dedicated worker thread to be hijacked
DWORD WINAPI HijackableWorkerThread(LPVOID lpParam) {
    std::cout << "[+] TestEXE: Hijackable worker thread (tid=" << GetCurrentThreadId() << ") started...\n";
    while (true) { Sleep(1000); } // results in KWAIT_REASON::DelayExecution -> safe to hijack
    return 0;
}

// dedicated worker thread designed to receive and execute queued APCs immediately
DWORD WINAPI QueueableWorkerThread(LPVOID lpParam) {
    std::cout << "[+] TestEXE: APC-queueable worker thread (tid=" << GetCurrentThreadId() << ") started...\n";
    while (true) { SleepEx(INFINITE, TRUE); } // TRUE == aleartable wait state
    return 0;
}

int main(int argc, char* argv[]) {
    std::cout << "[+] TestEXE: Started with PID: " << GetCurrentProcessId() << std::endl;

    HANDLE hHijackableWorker = NULL;
    HANDLE hQueueableWorker = NULL;
    if (argc >= 3) {
        hHijackableWorker = CreateThread(NULL, 0, HijackableWorkerThread, NULL, 0, NULL);
        hQueueableWorker = CreateThread(NULL, 0, QueueableWorkerThread, NULL, 0, NULL);
    }

    if (argc >= 2) {
        int targetPid = std::stoi(argv[1]);
        if (targetPid <= 0) {
            std::cerr << "[!] TestEXE: Invalid PID provided: " << targetPid << "\n";
        }
        else {
            std::string triggerSignalName = "Local\\TestEXE_OpenProc_" + std::to_string(targetPid);
            HANDLE hTrigger = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, triggerSignalName.c_str());
            if (hTrigger) {
                std::cout << "[+] TestEXE: Waiting for trigger signal: " << triggerSignalName << "...\n";
                WaitForOpenProcessTrigger(hTrigger, targetPid); // hangs
            }
            else {
                std::cerr << "[!] TestEXE: Failed to open trigger event: " << triggerSignalName << ". Error: " << GetLastError() << "\n";
            }
        }
    }

    if (hHijackableWorker) CloseHandle(hHijackableWorker);
    if (hQueueableWorker) CloseHandle(hQueueableWorker);

    std::cout << "[+] TestEXE: Keep running until terminated...\n";
    while (true) { Sleep(1000); }
    return 0;
}