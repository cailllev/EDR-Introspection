#include <iostream>
#include <string>

#include "hooker.h"

int main(int argc, char* argv[]) {
    int pid = 0;
    std::string dllPath;

    if (argc == 3) {
        try {
            pid = std::stoi(argv[1]);
        }
        catch (...) {
            std::cerr << "[!] HookTester: Invalid PID provided on the command line: " << argv[1] << "\n";
            return 1;
        }
        dllPath = argv[2];
    }
    else {
        // Interactive fallback
        std::cout << "[+] HookTester: Enter PID: ";
        std::string pidLine;
        if (!std::getline(std::cin, pidLine)) return 1;
        try {
            pid = std::stoi(pidLine);
        }
        catch (...) {
            std::cerr << "[!] HookTester: Invalid PID input.\n";
            return 1;
        }

        std::cout << "[+] HookTester: Enter DLL path: ";
        if (!std::getline(std::cin, dllPath)) return 1;
    }

    if (pid <= 0) {
        std::cerr << "[!] HookTester: PID must be a positive integer.\n";
        return 1;
    }
    if (dllPath.empty()) {
        std::cerr << "[!] HookTester: DLL path cannot be empty.\n";
        return 1;
    }

    if (inject_dll(pid, dllPath, true)) {
        std::cout << "[*] HookTester: DLL injection succeeded.\n";
    }
    else {
        std::cerr << "[!] HookTester: DLL injection failed.\n";
    }

    return 0;
}
