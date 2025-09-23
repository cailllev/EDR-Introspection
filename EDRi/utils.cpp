#include <windows.h>
#include <shellapi.h>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <regex>
#include <vector>
#include <shared_mutex>
#include <tlhelp32.h> // import after windows.h, else all breaks, that's crazy, yo

#include "utils.h"
#include "globals.h"


static const std::string encrypt_password = "much signature bypass, such wow";
static std::unordered_map<std::string, std::string> g_deviceMap;
static std::wstring attacks_subfolder = L"attacks\\";
static std::string attack_suffix = ".exe.enc";

static bool initialized = false;

// thread-safe storing PID:EXE to global variable
void snapshot_procs() {
	initialized = true;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &pe)) {
        std::unique_lock<std::shared_mutex> lock(g_procs_mutex); // one lock for entire update
        do {
            std::string exe = wchar2string(pe.szExeFile);
            int pid = pe.th32ProcessID;
            g_running_procs[pid] = exe;
        } while (Process32Next(snapshot, &pe));
    }
}

// thread-safe retrieving the PID of the first case-insensitive match, ignores other same-named processes
int get_PID_by_name(const std::string& name) {
    if (!initialized) {
		std::cerr << "[!] Utils: Cannot use get_PID_by_name() before snapshot_procs()\n";
        return -1;
    }
    std::shared_lock<std::shared_mutex> lock(g_procs_mutex); // reader lock (multiple allowed when no writers)
    for (auto it = g_running_procs.begin(); it != g_running_procs.end(); ++it) {
        if (_stricmp(it->second.c_str(), name.c_str()) == 0) {
            return it->first;
        }
    }
    return -1; // not found
}

// thread-safe adding a proc (can overwrite old procs)
void add_proc(int pid, const std::string& exe) {
    std::unique_lock<std::shared_mutex> lock(g_procs_mutex); // writer lock (one allowed, no readers)
    if (g_running_procs.find(pid) != g_running_procs.end()) {
        return; // already added (else the text below is printed twice)
    }
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

// get the EDRi.exe's path  
std::wstring get_executable_path() {
    wchar_t buffer[MAX_PATH];
    // Get the full path of the executable
    DWORD length = GetModuleFileNameW(NULL, buffer, MAX_PATH);
    if (length == 0) {
        return L"";
    }

    std::wstring exePath(buffer);
    size_t pos = exePath.find_last_of(L"\\/");

    // Return the directory part of the executable path
    return exePath.substr(0, pos + 1);
}

// returns the files from /EDRi/attacks
std::string get_available_attacks() {
    std::ostringstream oss;
    WIN32_FIND_DATA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    std::wstring searchPath = get_executable_path() + attacks_subfolder + L"*";
    hFind = FindFirstFile(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return ""; // Directory not found or empty
    }

    bool first = true;
    do {
        // Skip directories like "." and ".."
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if (!first) {
                oss << " ";
            }
			std::string f = wchar2string(findData.cFileName);
			f = f.substr(0, f.find(attack_suffix)); // remove .exe.enc
            oss << f;
            first = false;
        }
    } while (FindNextFile(hFind, &findData) != 0);

    FindClose(hFind);
    return oss.str();
}


bool is_attack_available(const std::string& attack) {
    std::string attacks = get_available_attacks();
    std::istringstream iss(attacks);
    std::string token;
    while (iss >> token) {
        if (_stricmp(token.c_str(), attack.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

std::string get_attack_enc_path(const std::string& attack) {
    return wstring2string(attacks_subfolder) + attack + attack_suffix;
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

bool filepath_match(std::string path1, std::string path2) {
    auto normalize = [](const std::string& path) -> std::string {
        std::string p = path;

        // if it starts with "\Device\HarddiskVolumeX", remove it
        const std::string device_prefix = "\\Device\\HarddiskVolume";
        if (p.compare(0, device_prefix.size(), device_prefix) == 0) {
            // find first backslash after volume number
            size_t pos = p.find('\\', device_prefix.size());
            if (pos != std::string::npos) {
                p = p.substr(pos); // keep from first backslash
            }
            else {
                p.clear(); // malformed path
            }
        }
        // if it starts with "C:\" or other drive letter, remove it
        else if (p.size() >= 3 && std::isalpha(p[0]) && p[1] == ':' && p[2] == '\\') {
            p = p.substr(2); // keep from "\..." 
        }
        // and lowercase all
        std::transform(p.begin(), p.end(), p.begin(), [](unsigned char c) { return std::tolower(c); });
        return p;
        };
    std::string norm1 = normalize(path1);
    std::string norm2 = normalize(path2);
    return norm1 == norm2;
}

bool launch_as_child(const std::string& path) {
    std::wstring wpath(path.begin(), path.end());

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_DEFAULT;
    sei.hwnd = NULL;
    sei.lpVerb = L"open";
    sei.lpFile = wpath.c_str();
    sei.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&sei)) {
        DWORD err = GetLastError();
        std::cerr << "[!] Utils: ShellExecuteEx failed: " << err << "\n";
        return false;
    }
    return true;
}

bool launch_with_logon(const std::string& path) {
    // Replace these with the user credentials you know
    LPCWSTR domain = L"."; // local machine
    LPCWSTR username = L"hacker";
    LPCWSTR password = L"hacker";
	std::string command = "explorer.exe '" + path + "'";
    std::wstring wcommand(path.begin(), path.end());

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessWithLogonW(
        username,
        domain,
        password,
        LOGON_WITH_PROFILE,
        wcommand.c_str(),
        NULL,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    );
    if (!ok) {
        std::cerr << "[!] Utils: CreateProcessWithLogonW failed: " << GetLastError() << "\n";
        return 1;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::cout << "[+] Utils: Executing \"" << command << "\" as " << username << "\n";
    return 0;
}

bool enable_privilege(const wchar_t* name) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "[!] Utils: OpenProcessToken at enable_privilege failed\n";
        return false;
    }

    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(hToken);
        std::cerr << "[!] Utils: LookupPrivilegeValueW at enable_privilege failed\n";
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    bool ok = (err == ERROR_SUCCESS);
    if (!ok) {
        std::cerr << "[!] Utils: AdjustTokenPrivileges at enable_privilege failed: " << err << "\n";
    }
    CloseHandle(hToken);
    return ok;
}

bool launch_with_explorer_impersonate_token(const std::string& path) {
    // Enable required privileges
    if (!enable_privilege(SE_ASSIGNPRIMARYTOKEN_NAME)) {
        std::cerr << "[!] Utils: Failed to enable SE_ASSIGNPRIMARYTOKEN_NAME privilege\n";
		return false;
    }
    if (!enable_privilege(SE_INCREASE_QUOTA_NAME)) {
		std::cerr << "[!] Utils: Failed to enable SE_INCREASE_QUOTA_NAME privilege\n";
        return false;
    }
    if (!enable_privilege(SE_IMPERSONATE_NAME)) {
		std::cerr << "[!] Utils: Failed to enable SE_IMPERSONATE_NAME privilege\n";
		return false;
    }

	int explorer_pid = get_PID_by_name("explorer.exe");
	if (explorer_pid == -1) {
        std::cerr << "[!] Utils: explorer.exe process not found, is a user logged in?\n";
        return false;
	}

    // open explorer process and get its token
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, explorer_pid);
    if (!hProc) {
		std::cerr << "[!] Utils: Failed to open explorer.exe process\n";
        return false;
    }

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken)) {
        CloseHandle(hProc);
        std::cerr << "[!] Utils: Failed to get token\n";
        return false;
    }
    CloseHandle(hProc);

    // duplicate the token for CreateProcessAsUser
    HANDLE hUserToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hUserToken)) {
        CloseHandle(hToken);
        std::cerr << "[!] Utils: Failed to duplicate token\n";
        return false;
    }
    CloseHandle(hToken);

    // launch process with explorer's token
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
	std::wstring wpath(path.begin(), path.end());
    BOOL ok = CreateProcessAsUserW(
        hUserToken,
        wpath.c_str(),
        NULL,
        NULL, NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL, NULL,
        &si, &pi
    );

    if (ok) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        DWORD err = GetLastError();
        std::cerr << "[!] Utils: CreateProcessAsUser failed: " << err << "\n";
    }
    CloseHandle(hUserToken);
    return ok == TRUE;
}

void build_device_map() {
    if (!g_deviceMap.empty()) return; // build only once

    WCHAR drives[512];
    DWORD len = GetLogicalDriveStringsW(512, drives);
    if (!len) return;

    for (WCHAR* d = drives; *d; d += wcslen(d) + 1) {
        // drive like L"C:\\"
        std::wstring driveW(d, 2); // just "C:"
        WCHAR target[MAX_PATH];
        if (QueryDosDeviceW(driveW.c_str(), target, MAX_PATH)) {
            std::wstring targetW(target);
            // store as UTF-8
            std::string drive = wstring2string(driveW); // "C:"
            std::string ntpath = wstring2string(targetW); // "\Device\HarddiskVolume3"
            g_deviceMap[ntpath] = drive + "\\"; // "C:\"
        }
    }
}

std::string translate_if_path(const std::string& s) {
    std::string s2 = s;

    // replace any \Device\HarddiskVolumeX\ with its actual drive letter
    for (const auto& m : g_deviceMap) {
		const std::string& nt = m.first;
		const std::string& drive = m.second;
        // build escaped regex like "\Device\HarddiskVolume3\"
        std::string pattern;
        for (char c : nt) {
            if (c == '\\') pattern += "\\\\";
            else pattern += c;
        }
        pattern += "\\\\"; // must end with slash

        std::regex r(pattern, std::regex_constants::icase);
        s2 = std::regex_replace(s2, r, drive);
    }

    // replace "\\?\X:\"  (any drive letter) with "X:\"
    static const std::regex extendedPrefix(R"(\\\\\?\\([A-Za-z]:)\\)",
    std::regex_constants::icase);
    s2 = std::regex_replace(s2, extendedPrefix, "$1\\\\");

    if (g_super_debug && s2 != s) {
        std::cout << "[~] EDRi: Translated path " << s << " to " << s2 << "\n";
    }

    return s2;
}