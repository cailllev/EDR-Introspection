#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <iostream>
#include <iomanip>

#pragma comment(lib, "ntdll.lib")

#define ProcessHandleInformation 51 // Information class 0x33
#define ThreadQuerySetWin32StartAddress 9
#define ObjectBasicInformation 0

// Built-in structure for local handle snapshots
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
    );

typedef struct my_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union
    {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} my_LDR_DATA_TABLE_ENTRY, * my_PLDR_DATA_TABLE_ENTRY;

typedef struct my_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} my_PEB_LDR_DATA, * my_PPEB_LDR_DATA;

typedef struct my_PEB {
    BYTE Reserved1[16];
    PVOID ImageBaseAddress;
    my_PPEB_LDR_DATA Ldr;
} my_PEB, * my_PPEB;

typedef NTSTATUS(NTAPI* fnNtQueryInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtQueryObject)(
    HANDLE Handle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef struct my_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG PagedPoolUsage;
    ULONG NonPagedPoolUsage;
    ULONG Reserved[3];
    ULONG NameInformationLength;
    ULONG TypeInformationLength;
    ULONG SecurityDescriptorLength;
    LARGE_INTEGER CreationTime;
} my_OBJECT_BASIC_INFORMATION, * my_POBJECT_BASIC_INFORMATION;


// traverses the PEB and prints all loaded DLLs and their base addrs
void print_bases(HANDLE hProcess) {
	printf("[*] Traversing PEB for loaded DLLs...\n");

    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);

    my_PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr)) {
        printf("[!] Cannot read PEB base addr\n");
        CloseHandle(hProcess);
        return;
    }

    my_PEB_LDR_DATA ldr{};
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(ldr), nullptr)) {
        printf("[-] Failed to read PEB_LDR_DATA. Error: %lu", GetLastError());
        CloseHandle(hProcess);
        return;
    }

    PVOID headAddr = (PBYTE)peb.Ldr + offsetof(my_PEB_LDR_DATA, InMemoryOrderModuleList);

    LIST_ENTRY head{};
    ReadProcessMemory(hProcess, headAddr, &head, sizeof(head), nullptr);
    PVOID current = head.Flink;

    std::cout << std::left
        << std::setw(19) << "Base Address"
        << std::setw(100) << "DLL Name" << "\n";
    std::cout << std::string(48, '-') << "\n";

    while (current && current != headAddr) {
        my_LDR_DATA_TABLE_ENTRY entry{};
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, my_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(entry), nullptr)) {
            printf("[-] Failed to read LDR_DATA_TABLE_ENTRY. Error: %lu", GetLastError());
            CloseHandle(hProcess);
            return;
        }
        if (entry.FullDllName.Buffer) {
            wchar_t dll_name[MAX_PATH];
            std::cout << "0x" << std::hex << std::setw(17) << entry.DllBase;
            if (ReadProcessMemory(hProcess, entry.FullDllName.Buffer, dll_name, entry.FullDllName.Length, nullptr)) {
                dll_name[entry.FullDllName.Length / sizeof(wchar_t)] = L'\0'; // null-terminate
				std::wcout << std::left << std::setw(100) << dll_name << "\n";
            }
            else {
				std::cout << std::setw(100) << "FAILED to read module name: " << GetLastError() << "\n";
            }
        }
        current = entry.InMemoryOrderLinks.Flink;
    }

    CloseHandle(hProcess);
}

// opens all threads with all access by a given pid, checks the actual acess rights and prints them plus threadID and base address of the thread
void check_threads(DWORD processId) {
	printf("[*] Checking threads for given process\n");

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    auto NtQueryInformationThread = (fnNtQueryInformationThread)GetProcAddress(hNtdll, "NtQueryInformationThread");
    auto NtQueryObject = (fnNtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");

    if (!NtQueryInformationThread || !NtQueryObject) {
        std::cerr << "[-] Failed to resolve Native APIs.\n";
        return;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "[-] Failed to create thread snapshot.\n";
        return;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    std::cout << std::left
        << std::setw(10) << "Thread ID"
        << std::setw(18) << "Granted Access"
        << std::setw(18) << "Base Address" << "\n";
    std::cout << std::string(48, '-') << "\n";

    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == processId) {

                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                //HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

                if (hThread != NULL) {
                    my_OBJECT_BASIC_INFORMATION objInfo = { 0 };
                    PVOID pStartAddress = nullptr;
                    ULONG returnLength = 0;

					// query actual granted access rights for the thread handle
                    NTSTATUS statusObj = NtQueryObject(hThread, ObjectBasicInformation, &objInfo, sizeof(objInfo), &returnLength);

					// get the base address of the thread (start address)
                    NTSTATUS statusThread = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &pStartAddress, sizeof(pStartAddress), NULL);

                    std::cout << std::left << std::setw(10) << te.th32ThreadID;

                    if (statusObj == 0) { // STATUS_SUCCESS
                        std::cout << "0x" << std::hex << std::setw(16) << objInfo.GrantedAccess;
                    }
                    else {
                        std::cout << std::setw(18) << "Access Unknown";
                    }

                    if (statusThread == 0) { // STATUS_SUCCESS
                        std::cout << "0x" << std::hex << pStartAddress << "\n";
                    }
                    else {
                        std::cout << "Address Unknown\n";
                    }

                    CloseHandle(hThread);
                }
                else {
                    // Handled if OpenThread fails entirely (e.g., Access Denied)
                    std::cout << std::left << std::setw(10) << te.th32ThreadID
                        << std::setw(18) << "OPEN_FAILED"
                        << "N/A\n";
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
}

int main() {
	printf("[*] Process Handle Inspector started\n");

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	if (hNtdll == 0) {
		printf("[-] Failed to get handle to ntdll.dll\n");
		return 1;
    }
    pfnNtQueryInformationProcess NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (NtQueryInformationProcess == 0) {
		printf("[-] Failed to get address of NtQueryInformationProcess\n");
		return 1;
	}

    ULONG bufferSize = 0x4000; // Start with 16KB (plenty for a single local process)
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ULONG returnLength = 0;

    // Query only OUR process handle table
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),
        ProcessHandleInformation,
        buffer,
        bufferSize,
        &returnLength
    );

    // Resize if needed
    if (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        VirtualFree(buffer, 0, MEM_RELEASE);
        bufferSize = returnLength;
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        status = NtQueryInformationProcess(GetCurrentProcess(), ProcessHandleInformation, buffer, bufferSize, &returnLength);
    }

    if (status == 0) {
        PPROCESS_HANDLE_SNAPSHOT_INFORMATION localHandles = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer;
        if (localHandles == nullptr || localHandles->NumberOfHandles == 0) {
            printf("[*] No handles found in the current process.\n");
            if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
            return 0;
		}
        printf("[*] Got %llu handles of all types owned by Process Handle Inspector...\n", localHandles->NumberOfHandles);

        typedef DWORD(WINAPI* pfnGetProcessId)(HANDLE);
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            printf("[-] Failed to get handle to kernel32.dll\n");
            if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
            return 1;
		}
        pfnGetProcessId _GetProcessId = (pfnGetProcessId)GetProcAddress(hKernel32, "GetProcessId");
        if (!_GetProcessId) {
            printf("[-] Failed to get address of GetProcessId\n");
            if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);
            return 1;
		}

		BOOL procHandleFound = FALSE;
        for (ULONG_PTR i = 0; i < localHandles->NumberOfHandles; i++) {
            PROCESS_HANDLE_TABLE_ENTRY_INFO entry = localHandles->Handles[i];

            // Check if the handle is a process handle
            DWORD targetPid = _GetProcessId(entry.HandleValue);
            if (targetPid != 0) {
                printf("[+] Proc handle found: ID=0x%p, PID=%lu, Access=0x%08X\n",
                    entry.HandleValue, targetPid, entry.GrantedAccess);
				procHandleFound = TRUE;
                print_bases(entry.HandleValue);
                check_threads(targetPid);
            }
        }
		if (!procHandleFound) {
			printf("[+] No process handles found in the current process.\n");
		}
    }

    if (buffer != 0) VirtualFree(buffer, 0, MEM_RELEASE);

    printf("[*] Print ENTER to exit...\n");
    (void)getchar();

    return 0;
}