#include <windows.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <shared_mutex>
#include <tlhelp32.h> // import after windows.h, else all breaks, that's crazy, yo

#include "utils.h"
#include "globals.h"


static const std::string encrypt_password = "much signature bypass, such wow";

// thread-safe storing PID:EXE to global variable
void snapshot_procs(bool allow_overwrite) {
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &pe)) {
        std::unique_lock<std::shared_mutex> lock(g_procs_mutex); // one lock for entire update
        do {
            std::string exe = wchar2string(pe.szExeFile);
            int pid = pe.th32ProcessID;
            if (allow_overwrite) {
                g_running_procs[pid] = exe;
            }
            else if (g_running_procs.find(pid) == g_running_procs.end()) {
                g_running_procs[pid] = exe;
            }
        } while (Process32Next(snapshot, &pe));
    }
}

// thread-safe retrieving the PID of the first match, ignores other same-named processes
int get_PID_by_name(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(g_procs_mutex); // reader lock (multiple allowed when no writers)
    for (auto it = g_running_procs.begin(); it != g_running_procs.end(); ++it) {
        if (it->second == name) {
            return it->first;
        }
    }
    return 0; // not found
}

// thread-safe adding a proc (can overwrite old procs)
void add_proc(int pid, const std::string& exe) {
    std::unique_lock<std::shared_mutex> lock(g_procs_mutex); // writer lock (one allowed, no readers)
    g_running_procs[pid] = exe;
    if (g_debug) {
        std::cout << "[+] Utils: New proc started at runtime (" << g_running_procs.size() << " procs now): " << pid << ":" << exe << "\n";
    }
}

// thread-safe retrieving a proc
std::string get_proc_name(int pid) {
    std::shared_lock<std::shared_mutex> lock(g_procs_mutex); // reader lock (multiple allowed when no writers)
    auto it = g_running_procs.find(pid);
    return (it != g_running_procs.end()) ? it->second : PROC_NOT_FOUND;
}

// encrypt/decrypt a file with a static password
bool xor_file(std::string in_path, std::string out_path) {
    // open input file in binary mode
    std::ifstream infile(in_path, std::ios::binary);
    if (!infile) {
        std::cerr << "[!] Utils: Failed to open input file: " << in_path << "\n";
        return false;
    }

    // read file into buffer
    std::vector<char> buffer((std::istreambuf_iterator<char>(infile)),
        std::istreambuf_iterator<char>());
    infile.close();

    // xor encrypt with password
    for (size_t i = 0; i < buffer.size(); ++i) {
        buffer[i] ^= encrypt_password[i % encrypt_password.size()];
    }

    // write encrypted data to output file
    std::ofstream outfile(out_path, std::ios::binary);
    if (!outfile) {
        std::cerr << "[!] Utils: Failed to open output file: " << out_path << "\n";
        return false;
    }
    outfile.write(buffer.data(), buffer.size());
    outfile.close();
    return true;
}


// all stolen from https://github.com/dobin/RedEdr
std::string wchar2string(const wchar_t* wideString) {
    if (!wideString) {
        return "";
    }
    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wideString, -1, nullptr, 0, nullptr, nullptr);
    if (sizeNeeded <= 0) {
        return "";
    }
    std::string ret(sizeNeeded - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wideString, -1, &ret[0], sizeNeeded, nullptr, nullptr);
    return ret;
}

std::string wstring2string(std::wstring& wide_string) {
    if (wide_string.empty()) {
        return "";
    }

    // Determine the size needed for the UTF-8 buffer
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, nullptr, 0, nullptr, nullptr);

    // Allocate the buffer and perform the conversion
    std::string utf8_string(size_needed - 1, '\0'); // Exclude the null terminator
    WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, &utf8_string[0], size_needed, nullptr, nullptr);

    return utf8_string;
}

bool wstring_starts_with(const std::wstring& str, const std::wstring& prefix) {
	if (str.size() < prefix.size()) {
		return false;
	}
	return str.compare(0, prefix.size(), prefix) == 0;
}

std::string filetime_to_iso8601(__int64 timestamp) {
    // convert to FILETIME
    FILETIME ft;
    ft.dwLowDateTime = static_cast<DWORD>(timestamp & 0xFFFFFFFF);
    ft.dwHighDateTime = static_cast<DWORD>(timestamp >> 32);

    SYSTEMTIME stUTC;
    if (!FileTimeToSystemTime(&ft, &stUTC)) {
        return "";
    }

    // extract the fractional part
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;

    const unsigned long long TICKS_PER_SEC = 10000000ULL; // 10M * 100ns
    unsigned long long frac_ticks = uli.QuadPart % TICKS_PER_SEC;
    double fractional = static_cast<double>(frac_ticks) / TICKS_PER_SEC;

    // convert to fractional seconds and format
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(4) << stUTC.wYear << "-"
        << std::setw(2) << stUTC.wMonth << "-"
        << std::setw(2) << stUTC.wDay << " "
        << std::setw(2) << stUTC.wHour << ":"
        << std::setw(2) << stUTC.wMinute << ":"
        << std::setw(2) << stUTC.wSecond << "."
        << std::setw(7) << std::setfill('0') << static_cast<int>(fractional * 10000000ULL)
        << "Z";

    return oss.str();
}

char* get_memory_region_protect(DWORD protect) {
    const char* memoryProtect;
    switch (protect) {
	case PAGE_EXECUTE:
		memoryProtect = "--X";
		break;
	case PAGE_EXECUTE_READ:
		memoryProtect = "R-X";
		break;
	case PAGE_EXECUTE_READWRITE:
		memoryProtect = "RWX";
		break;
	case PAGE_EXECUTE_WRITECOPY:
		memoryProtect = "EXECUTE_WRITECOPY";
		break;
	case PAGE_NOACCESS:
		memoryProtect = "NOACCESS";
		break;
	case PAGE_READONLY:
		memoryProtect = "R--";
		break;
	case PAGE_READWRITE:
		memoryProtect = "RW-";
		break;
	case PAGE_WRITECOPY:
		memoryProtect = "WRITECOPY";
		break;
    case PAGE_GUARD:
        memoryProtect = "GUARD";
		break;
    case PAGE_NOCACHE:
		memoryProtect = "NOCACHE";
        break;
	case PAGE_WRITECOMBINE:
        memoryProtect = "WRITECOMBINE";
        break;
	default:
		memoryProtect = "Unknown";
		break;
	}
	return (char*) memoryProtect;
}