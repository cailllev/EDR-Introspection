#include <windows.h>
#include <string>


// waits for trigger to do a OpenProcess syscall
int WaitForOpenProcessTrigger(HANDLE hTrigger, DWORD targetPid) {

    WaitForSingleObject(hTrigger, INFINITE); // hangs until received
    printf("[*] TestEXE: Got signal, do OpenProcess()\n");
    CloseHandle(hTrigger); // close handle after trigger received

    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    // this should fire a TestHookTask ETW event in the TestHook DLL if the DLL is active (injected)

    if (hTarget == NULL) {
        printf("[!] TestEXE: OpenProcess failed! Error: %i\n", GetLastError());
        return 1;
    }
    printf("[+] TestEXE: Successfully opened PROCESS_ALL_ACCESS handle!\n");
    CloseHandle(hTarget);
    return 0;
}

// dedicated worker thread to be hijacked
DWORD WINAPI HijackableWorkerThread(LPVOID lpParam) {
    printf("[+] TestEXE: Hijackable worker thread tid=%i started...\n", GetCurrentThreadId());
    while (true) { Sleep(1000); } // results in KWAIT_REASON::DelayExecution -> safe to hijack
    return 0;
}

// a busy wait, this is intentionally shitty
int GetLargestPrimeBelow(int m) {
    int maxP = 0;
    bool isPrime;
    for (int candidate = 0; candidate < m; candidate++) {
        isPrime = true; // reset for each candidate at start
        for (int possibleFactor = 2; possibleFactor * possibleFactor < m; possibleFactor++) {
            if ((candidate % possibleFactor) == 0) {
                isPrime = false;
                break;
            }
        }
        if (isPrime) {
            maxP = candidate;
        }
    }
    return maxP;
}

// dedicated and mostly busy thread to get high score and cross usermode kernelmode often 
DWORD WINAPI BusyWorkerThread(LPVOID lpParam) {
    printf("[+] TestEXE: APC-queueable worker thread tid=%i started...\n", GetCurrentThreadId());
    volatile int p = 0;
    while (true) { Sleep(50); p = GetLargestPrimeBelow(1000000); }
    return 0;
}

int main(int argc, char* argv[]) {
    printf("[+] TestEXE: Started with pid=%i\n", GetCurrentProcessId());

    HANDLE hHijackableWorker = NULL;
    HANDLE hQueueableWorker = NULL;

    // this starts 2 workers that are hijackable and special_queueable (busy) respectively
    if (argc >= 3 && argv[2][0] == '1') {
        hHijackableWorker = CreateThread(NULL, 0, HijackableWorkerThread, NULL, 0, NULL);
        hQueueableWorker = CreateThread(NULL, 0, BusyWorkerThread, NULL, 0, NULL);
    }

    // this let's the main thread wait for a signal to then OpenProcess(Explorer)
    if (argc >= 2 && argv[1][0] != '0') {
        int targetPid = std::stoi(argv[1]);
        if (targetPid < 4) { // min PID is 4
            printf("[!] TestEXE: Invalid PID provided: %i\n", targetPid);;
        }
        else {
            std::string triggerSignalName = "Local\\TestEXE_OpenProc_" + std::to_string(targetPid);
            HANDLE hTrigger = OpenEventA(EVENT_MODIFY_STATE | SYNCHRONIZE, FALSE, triggerSignalName.c_str());
            if (hTrigger) {
                printf("[+] TestEXE: Waiting for trigger signal: %s\n", triggerSignalName.c_str());
                WaitForOpenProcessTrigger(hTrigger, targetPid); // hangs
            }
            else {
                printf("[!] TestEXE: Failed to open trigger event: %s. Error: %i\n", triggerSignalName.c_str(), GetLastError());
            }
        }
    }

    if (hHijackableWorker) CloseHandle(hHijackableWorker);
    if (hQueueableWorker) CloseHandle(hQueueableWorker);

    printf("[+] TestEXE: Keep running until terminated...\n");
    while (true) { Sleep(1000); }
    return 0;
}