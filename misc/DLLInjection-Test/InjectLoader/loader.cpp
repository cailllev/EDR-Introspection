#include <iostream>
#include <string>

#include "hooker.h"

int main(int argc, char* argv[]) {
    int pid = 0;
    std::string dllPath;

	std::string exePath = argv[0];
	std::string exeName = exePath.substr(exePath.find_last_of("\\/") + 1);

    if (argc > 1 && strcmp(argv[1], "-h") == 0) {
        std::cout << "[*] InjectLoader: Usage: " << exeName << " <DLL Path> <PID> [0 (loadlibrary) | 1 (reflective)]\n";
        return 0;
	}

    if (argc < 4) {
        std::cout << "[*] InjectLoader: Usage: " << exeName << " <DLL Path> <PID> [0 (loadlibrary) | 1 (reflective)]\n";
        return 1;
    }

    dllPath = argv[1];
    try {
        pid = std::stoi(argv[2]);
    } catch (const std::exception& e) {
        std::cerr << "[!] InjectLoader: Invalid PID: " << argv[1] << "\n";
        return 1;
	}
	bool reflective_inject = false;
    if (strcmp(argv[3], "1") == 0 || strcmp(argv[3], "reflective") == 0) {
        reflective_inject = true;
	}

    if (pid <= 0) {
        std::cerr << "[!] InjectLoader: PID must be a positive integer.\n";
        return 1;
    }
    if (dllPath.empty()) {
        std::cerr << "[!] InjectLoader: DLL path cannot be empty.\n";
        return 1;
    }

    std::cout << "[*] InjectLoader: Attempting to inject DLL '" << dllPath << "' into PID=" << pid << " using " 
		<< (reflective_inject ? "Reflective" : "LoadLibrary") << " Injection\n";

    if (inject_dll(pid, dllPath, true, reflective_inject)) {
        std::cout << "[*] InjectLoader: DLL injection succeeded.\n";
    }
    else {
        std::cerr << "[!] InjectLoader: DLL injection failed.\n";
    }

    return 0;
}
