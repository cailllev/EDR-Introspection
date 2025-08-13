#include <windows.h>
#include <iostream>

int main() {
    // start Notepad
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(L"C:\\Windows\\System32\\notepad.exe", nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        std::cerr << "Failed to start Notepad: " << GetLastError() << "\n";
        return 1;
    }

    std::cout << "Notepad started. PID: " << pi.dwProcessId << "\n";

    // open process with read/write access
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pi.dwProcessId);
    if (!hProcess) {
        std::cerr << "Failed to open process: " << GetLastError() << "\n";
        return 1;
    }

    // allocate memory in Notepad
    int valueToWrite = 0xdeadbeaf;
    LPVOID remoteAddr = VirtualAllocEx(hProcess, nullptr, sizeof(valueToWrite), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteAddr) {
		std::cout << "Memory allocated at address: " << remoteAddr << "\n";
    } else {
        std::cerr << "Failed to allocate memory: " << GetLastError() << "\n";
        return 1;
    }

	// read before writing
    SIZE_T bytesRead;
    int valueRead = 0;
    if (ReadProcessMemory(hProcess, remoteAddr, &valueRead, sizeof(valueRead), &bytesRead)) {
        std::cout << "Value before write: 0x" << std::hex << valueRead << std::dec << "\n";
    }
    else {
        std::cerr << "Failed to read memory. Error: " << GetLastError() << "\n";
        return 1;
    }

    // write value into Notepad's memory
    SIZE_T bytesWritten;
    if (WriteProcessMemory(hProcess, remoteAddr, &valueToWrite, sizeof(valueToWrite), &bytesWritten)) {
        std::cout << "Value written to address: " << remoteAddr << "\n";
    }
    else {
        std::cerr << "Failed to write memory: " << GetLastError() << "\n";
        return 1;
    }


    // and read it
    if (ReadProcessMemory(hProcess, remoteAddr, &valueRead, sizeof(valueRead), &bytesRead)) {
        std::cout << "Value after write: 0x" << std::hex << valueRead << std::dec << "\n";
    }
    else {
        std::cerr << "Failed to read memory. Error: " << GetLastError() << "\n";
    }

    // cleanup
    VirtualFreeEx(hProcess, remoteAddr, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    if (TerminateProcess(pi.hProcess, 0)) {
        std::cout << "Notepad terminated.\n";
    }
    else {
        std::cerr << "Failed to terminate Notepad: " << GetLastError() << "\n";
	}
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
