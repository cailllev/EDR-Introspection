#include <windows.h>
#include <shellapi.h>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <shared_mutex>
#include <shlwapi.h>
#include <tlhelp32.h> // import after windows.h, else all breaks, that's crazy, yo

#include "globals.h"
#include "utils.h"

#pragma comment(lib, "Shlwapi.lib")


static const std::string encrypt_password = "much signature bypass, such wow";
static std::wstring attacks_subfolder = L"attacks\\";
static std::string enc_attack_suffix = ".exe.enc";

static std::string dumps_relative_path = "..\\..\\EDRi\\dumps\\";
static std::string defender2yara_relative_path = "..\\..\\EDRi\\defender2yara\\";
static std::string defender2yara_sigs_url = "https://github.com/t-tani/defender2yara/tree/yara-rules";

// TODO detect system reboot -> clear PIDs from hooked.txt
const std::string hooked_procs_file = "C:\\Users\\Public\\Downloads\\hooked.txt"; // should match the path in EDRReflectiveHooker (dllmain.cpp)

static bool initialized_snapshot = false;

// get unix epoch time in nanoseconds (100 ns resolution)
UINT64 get_ns_time() {
    /*
    ChronoVsFiletime.exe:
    [*] Timing 1000000000 calls each...
    5.59516 ns per call - GetSystemTimeAsFileTime
    26.9772 ns per call - GetSystemTimePreciseAsFileTime
    23.9806 ns per call - chrono::system_clock::now()
    */
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

// thread-safe storing ProcInfo to global variable, processes found here are assumed to be running since t=0
void snapshot_procs() {
	initialized_snapshot = true;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &pe)) {
        std::unique_lock<std::shared_mutex> lock(g_procs_mutex); // writer lock (one allowed, no readers)
        do {
            std::string exe = wchar2string(pe.szExeFile);
            int pid = pe.th32ProcessID;
            bool to_track = false; // check if this is a process to be tracked
            for (auto& e : g_exes_to_track) {
                if (_stricmp(exe.c_str(), e.c_str()) == 0) {
                    to_track = true;
                }
            }
            ProcInfo pi = { pid, MIN_PROC_START, MAX_PROC_END, exe, to_track };
			g_running_procs.push_back(pi);
        } while (Process32Next(snapshot, &pe));
    }
}

// thread-safe retrieving the PID of the first case-insensitive match, ignores other same-named processes
std::vector<int> get_PID_by_name(const std::string& name, UINT64 timestamp_ns) {
    if (!initialized_snapshot) {
		std::cerr << "[!] Utils: Cannot use get_PID_by_name() before snapshot_procs()\n";
        return {};
    }
    std::vector<int> procs = {};
    std::shared_lock<std::shared_mutex> lock(g_procs_mutex); // reader lock (multiple allowed when no writers)
    for (auto it = g_running_procs.begin(); it != g_running_procs.end(); ++it) {
        if (_stricmp(it->name.c_str(), name.c_str()) == 0) { // check if name matches
            if (it->start_time < timestamp_ns && it->end_time > timestamp_ns) { // check if timestamp is inside start and end
                procs.push_back(it->PID);
            }
        }
    }
    return procs;
}

// thread-safe adding a proc
void add_proc(int pid, const std::string& name, UINT64 timestamp_ns, bool to_track) {
    if (!initialized_snapshot) {
        if (g_debug) {
            std::cout << "[~] Utils: New proc " << pid << ":" << name << " started before snapshot was taken";
            std::cout << ", will be ignored here and just added in the snapshot_procs()\n";
        }
        return;
    }
    std::unique_lock<std::shared_mutex> lock(g_procs_mutex); // writer lock (one allowed, no readers)
    ProcInfo pi = { pid, timestamp_ns, MAX_PROC_END, name, to_track };
    g_running_procs.push_back(pi);
    if (g_debug) {
        std::cout << "[+] Utils: New proc started at runtime: " << pid << ":" << name << "\n";
    }
}

// thread-safe marking the proc termination
void mark_termination(int pid, UINT64 timestamp_ns) {
    std::unique_lock<std::shared_mutex> lock(g_procs_mutex); // writer lock (one allowed, no readers)
    ProcInfo* latest_proc = nullptr;
    for (auto it = g_running_procs.begin(); it != g_running_procs.end(); ++it) {
        if (it->PID == pid) {
            if (latest_proc == nullptr || it->start_time > latest_proc->start_time) {
                latest_proc = &(*it);
            }
        }
    }
    if (latest_proc != nullptr) {
        latest_proc->end_time = timestamp_ns;
    }
    else if (g_debug) {
        std::cout << "[~] Utils: Cannot add termination for unregistered proc " << pid << " at " << unix_epoch_ns_to_iso8601(timestamp_ns) << "\n";
    }
}

// retrieving a proc
std::string get_proc_name(int pid, UINT64 timestamp_ns, UINT64 buffer_ns) {
    if (buffer_ns > MAX_BUFFER_NS) {
        return PROC_NOT_FOUND;
    }

    std::vector<ProcInfo> potential_matches = {};
    for (auto it = g_running_procs.begin(); it != g_running_procs.end(); ++it) {
        if (it->PID == pid) { // check if pid matches
            if (it->start_time <= timestamp_ns + buffer_ns && it->end_time >= timestamp_ns - buffer_ns) { // check if timestamp is inside start and end (with buffer)
                potential_matches.push_back(*it);
            }
        }
    }

    // handle 0,1,>1 potential matches
    if (potential_matches.size() == 0) { // no procs found --> search again with more buffer, 0.1ms, 1ms, ... MAX_BUFFER_NS, +1 --> not found
        if (buffer_ns == 0) {
            buffer_ns = RESERVE_NS; // ensure that the buffer grows
        }
        return get_proc_name(pid, timestamp_ns, buffer_ns*10);
    }
    if (potential_matches.size() == 1) { // one proc found --> return it
        return potential_matches.at(0).name;
    }
    if (potential_matches.size() > 1) { // X procs found --> return the process with the closest start / end time to the given timestamp_ns
        UINT64 smallest_diff = MAX_PROC_END;
        ProcInfo closest_proc = {0, 0, 0, PROC_NOT_FOUND, false};
        for (auto it = potential_matches.begin(); it != potential_matches.end(); ++it) {
            UINT64 diff_s = (it->start_time > timestamp_ns) ? it->start_time - timestamp_ns : timestamp_ns - it->start_time;
            UINT64 diff_e = (it->end_time > timestamp_ns) ? it->end_time - timestamp_ns : timestamp_ns - it->end_time;
            UINT64 diff = (diff_s < diff_e) ? diff_s : diff_e;
            if (diff < smallest_diff) {
                smallest_diff = diff;
                closest_proc = *it;
            }
        }
        return closest_proc.name;
    }
    return PROC_NOT_FOUND; // comfort the compiler: "not all control paths return a value"
}

// thread-safe retrieving all processes that were tracked
std::vector<ProcInfo> get_tracked_procs() {
    std::shared_lock<std::shared_mutex> lock(g_procs_mutex); // reader lock (multiple allowed when no writers)
    std::vector<ProcInfo> tracked = {};
    for (auto it = g_running_procs.begin(); it != g_running_procs.end(); ++it) {
        if (it->to_track) {
            tracked.push_back(*it);
        }
    }
    return tracked;
}

// check if unnecessary tools are running --> these inflate the output
std::string unnecessary_tools_running() {
    UINT64 ns = get_ns_time();
    std::string r = "";
	if (!initialized_snapshot) {
        std::cerr << "[!] Utils: Cannot use unnecessary_tools_running() before snapshot_procs()\n";
        return r;
	}
    std::vector<std::string> procs = { "procexp64.exe", "taskmgr.exe" };
    for (auto& p : procs) {
        if (!get_PID_by_name(p, ns).empty()) {
            r += p + " ";
        }
    }
    return r;
}

// dump all recorded procs
void dump_proc_map() {
    std::cout << "[+] ------------------------ Running procs during the tests ------------------------\n";
    // sort procs by PID
    std::sort(g_running_procs.begin(), g_running_procs.end(), [](const ProcInfo& a, const ProcInfo& b) {
        return a.PID < b.PID;
        });
    for (auto& p : g_running_procs) {
        std::cout << std::setfill(' ') << std::setw(5) << p.PID << " : ";
        std::cout << unix_epoch_ns_to_iso8601(p.start_time) << " - " << unix_epoch_ns_to_iso8601(p.end_time);
        std::cout << " : " << p.to_track << "," << p.name << "\n";
    }
    std::cout << "[+] ------------------------ ------------------------------ ------------------------\n";
}

// get random number between 100...999
std::string get_random_3digit_num() {
    static std::mt19937 rng(std::random_device{}()); // initialize once
    std::uniform_int_distribution<int> dist(100, 999);
    return std::to_string(dist(rng));
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

bool remove_file(const std::string& path) {
    if (DeleteFileA(path.c_str()) == 0) {
        std::cerr << "[!] Utils: Failed to delete file: " << path << ", error: " << GetLastError() << "\n";
        return false;
    }
    return true;
}

// get the EDRi.exe's base path  
std::wstring get_base_path() {
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

std::string get_hook_dll_path() {
    std::wstring base_path = get_base_path();
    return wstring2string(base_path) + "EDRReflectiveHooker.dll";
}

std::string resolve_path(std::string relative_path) {
    std::wstring base_path = get_base_path();
	std::string raw = wstring2string(base_path) + relative_path;
    char out[MAX_PATH];
    if (PathCanonicalizeA(out, raw.c_str())) {
        return std::string(out);
    }
    return raw; // fallback if canonicalization fails
}

// calculates the absolute output path for a given name and the static dumps_relative_path
std::string get_output_path(std::string name) {
	return resolve_path(dumps_relative_path + name);
}

// returns the files from /EDRi/attacks
std::string get_available_attacks() {
    std::ostringstream oss;
    WIN32_FIND_DATA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;

    std::wstring searchPath = get_base_path() + attacks_subfolder + L"*";
    hFind = FindFirstFile(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return ""; // Directory not found or empty
    }

    do {
        // Skip directories like "." and ".."
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
			std::string f = wchar2string(findData.cFileName);
            // check if file ends with correct suffix
            if (f.size() > enc_attack_suffix.size() && std::equal(enc_attack_suffix.rbegin(), enc_attack_suffix.rend(), f.rbegin())) {
                f = f.substr(0, f.find(enc_attack_suffix)); // remove .exe.enc
                oss << "\n" << f;
            }
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
	std::wstring exe_path = get_base_path();
    return wstring2string(exe_path) + wstring2string(attacks_subfolder) + attack + enc_attack_suffix;
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

UINT64 filetime_to_unix_epoch_ns(__int64 timestamp) {
    if (timestamp < WINDOWS_TICKS_TO_UNIX_EPOCH) {
        return 0; // before Unix epoch
    }
    uint64_t unix_ticks_100ns = static_cast<uint64_t>(timestamp) - WINDOWS_TICKS_TO_UNIX_EPOCH;
    uint64_t unix_ns = unix_ticks_100ns * NS_PER_WINDOWS_TICK;
    return unix_ns;
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

std::string unix_epoch_ns_to_iso8601(uint64_t ns_since_epoch)
{
    using namespace std::chrono;
    system_clock::duration duration = duration_cast<system_clock::duration>(nanoseconds(ns_since_epoch));
    system_clock::time_point time_point(duration);
    auto in_time_t = system_clock::to_time_t(time_point);
    auto fractional = duration_cast<nanoseconds>(time_point.time_since_epoch()) % 1'000'000'000;

    // Convert to UTC
    std::tm tm_buf;
    gmtime_s(&tm_buf, &in_time_t);

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
        << "." << std::setw(9) << std::setfill('0') << fractional.count()
        << "Z"; // UTC

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

// removes the hooked_procs_file if its out of date (last write time is before the last system boot time -> procs have changed)
void remove_if_out_of_date() {
    if (GetFileAttributesA(hooked_procs_file.c_str()) == INVALID_FILE_ATTRIBUTES) {
        if (g_debug)
            std::cerr << "[-] Utils: " << hooked_procs_file << " not found\n";
        return;
    }

    // system uptime -> last boot FILETIME
    ULONGLONG uptimeFt = GetTickCount64() * 10000ULL;
    FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
    ULONGLONG now = ((ULONGLONG)nowFt.dwHighDateTime << 32) | nowFt.dwLowDateTime;
    ULONGLONG boot = now - uptimeFt;

    // get file write time
    HANDLE h = CreateFileA(hooked_procs_file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) {
        if (g_debug)
            std::cerr << "[!] Utils: Could not open " << hooked_procs_file << "\n";
        return;
    }
    FILETIME writeFt;
    if (!GetFileTime(h, nullptr, nullptr, &writeFt)) {
        CloseHandle(h);
        if (g_debug)
            std::cerr << "[!] Utils: GetFileTime failed on " << hooked_procs_file << "\n";
        return;
    }
    CloseHandle(h);

    ULONGLONG write = ((ULONGLONG)writeFt.dwHighDateTime << 32) | writeFt.dwLowDateTime;

    // compare & delete
    if (write < boot) {
        std::ofstream ofs(hooked_procs_file, std::ios::trunc);
		if (ofs.is_open()) {
            if (g_debug)
                std::cout << "[-] Utils: Hooked procs in " << hooked_procs_file << " out of date, deleted the file\n";
            return;
        }
        else {
            if (g_debug)
                std::cerr << "[!] Utils: Failed to delete out of date " << hooked_procs_file << "\n";
        }
    }
    else {
        if (g_debug)
		    std::cout << "[+] Utils: Hooked procs in " << hooked_procs_file << " up to date, keeping the file\n";
    }
}

std::vector<int> get_hooked_procs() {
    remove_if_out_of_date();
    std::vector<int> hooked_procs;
    std::ifstream ifs(hooked_procs_file);
    if (!ifs.is_open()) {
        std::cerr << "[!] Utils: Failed to open file for reading: " << hooked_procs_file << "\n";
        return hooked_procs;
    }
    int pid;
    while (ifs >> pid) {
        hooked_procs.push_back(pid);
    }
    ifs.close();
    return hooked_procs;
}

void save_hooked_procs(const std::vector<int> hooked_procs) {
    std::ofstream ofs(hooked_procs_file, std::ios::app);
    if (!ofs.is_open()) {
        std::cerr << "[!] Utils: Failed to open file for writing: " << hooked_procs_file << "\n";
        return;
    }
    for (int pid : hooked_procs) {
        ofs << pid << "\n";
    }
    ofs.close();
}

// execute powershell command to download zip and extract
void update_defender2yara_sigs() {
	std::string full_path = resolve_path(defender2yara_relative_path);
	std::string zip_output_path = full_path + "defender2yara-yara-rules.zip";
    std::string ps_command = "powershell -Command \""
		"$ProgressPreference = 'SilentlyContinue'; " // do not show progress bar
		"$url = 'https://github.com/t-tani/defender2yara/archive/refs/heads/yara-rules.zip'; "
		"$output = '" + zip_output_path + "'; "
		"Invoke-WebRequest -Uri $url -OutFile $output; "
		"Expand-Archive -Path $output -DestinationPath '" + full_path + "' -Force; "
		"Remove-Item $output; "
		"Move-Item -Path '" + full_path + "defender2yara-yara-rules\\*' -Destination '" + full_path + "' -Force; " // move all files up one level
        "Remove-Item -Path '" + full_path + "defender2yara-yara-rules' -Recurse -Force;\"";
	std::cout << "[*] Utils: Updating defender2yara signatures with command: " << ps_command << "\n";
	system(ps_command.c_str());    
}

bool read_file(const std::string& path, std::string& output) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    if (!file) return false;
    std::ostringstream ss;
    ss << file.rdbuf();
    output = ss.str();
    return true;
}

bool extract_rule(const std::string& file_content, const std::string& rule_name, std::string& rule_out) {
    std::string key = "rule " + rule_name;
    size_t pos = file_content.find(key);
    if (pos == std::string::npos) return false;

    // find opening brace
    size_t brace_open = file_content.find("{", pos);
    if (brace_open == std::string::npos) return false;

    int brace_count = 0;
    size_t i = brace_open;
    for (; i < file_content.size(); ++i) {
        if (file_content[i] == '{') brace_count++;
        else if (file_content[i] == '}') brace_count--;
        if (brace_count == 0) {
            // include final closing brace
            rule_out = file_content.substr(pos, i - pos + 1);
            return true;
        }
    }
    return false;
}

bool find_rule_in_dir(const std::string& dir, const std::string& rule_name, std::string& result) {
    std::string search = dir + "\\*";
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(search.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;

    do {
        std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;

        std::string fullpath = dir + "\\" + name;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (find_rule_in_dir(fullpath, rule_name, result)) return true;
        }
        else {
            // check extension
            if (name.size() > 4) {
                std::string ext = name.substr(name.find_last_of('.') + 1);
                if (ext == "yar" || ext == "yara") {
                    std::string content;
                    if (read_file(fullpath, content)) {
                        if (extract_rule(content, rule_name, result)) {
                            return true;
                        }
                    }
                }
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return false;
}

// traverse the defender2yara yara-rules directory and get the complete rule for a given signature name
std::string get_yara_rule(const std::string rule_name) {
    std::string yara_rules_path = resolve_path(defender2yara_relative_path);
    std::string rule_text = "";
    find_rule_in_dir(yara_rules_path, rule_name, rule_text);
    return rule_text;
}

