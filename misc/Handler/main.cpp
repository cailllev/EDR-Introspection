#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winternl.h>
#include <iostream>

#pragma comment(lib, "ntdll.lib")

#define ProcessHandleInformation 51 // Information class 0x33

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


// traverses the PEB and prints all loaded DLLs and their base addrs
void print_bases(HANDLE hProcess) {
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

    while (current && current != headAddr) {
        my_LDR_DATA_TABLE_ENTRY entry{};
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, my_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(entry), nullptr)) {
            printf("[-] Failed to read LDR_DATA_TABLE_ENTRY. Error: %lu", GetLastError());
            CloseHandle(hProcess);
            return;
        }
        if (entry.FullDllName.Buffer) {
            wchar_t dll_name[MAX_PATH];
            if (ReadProcessMemory(hProcess, entry.FullDllName.Buffer, dll_name, entry.FullDllName.Length, nullptr)) {
                dll_name[entry.FullDllName.Length / sizeof(wchar_t)] = L'\0'; // null-terminate
                printf("[:] Found module: %p:%ls\n", entry.DllBase, dll_name);
            }
            else {
                printf("[-] Failed to read module name. Error: %lu", GetLastError());
            }
        }
        current = entry.InMemoryOrderLinks.Flink;
    }

    CloseHandle(hProcess);
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