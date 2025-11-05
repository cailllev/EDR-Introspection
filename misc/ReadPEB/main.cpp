#include <Windows.h>
#include <winternl.h>
#include <cstdlib>
#include <iostream>


// NtQueryInformationProcess definition (only in ntdll.dll defined)
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationProcess)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength);
PFN_NtQueryInformationProcess pNtQueryInfoProcess = nullptr;


int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("[!] Usage %s <process ID to read PEB from>\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);
    if (pid == 0) {
        printf("[!] Invalid PID: %i\n", pid);
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[!] ntdll not loaded\n");
        return 1;
    }

    // helper functions to resolve in ntdll.dll
    pNtQueryInfoProcess = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (pNtQueryInfoProcess == nullptr) {
        printf("[!] NtQueryInformationProcess not found in ntdll\n");
        return 1;
    }

    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG returnLength;

    HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (!hProcess) {
        printf("[!] Failed to open proc %i\n", pid);
    }

    // PBI
    NTSTATUS status = pNtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        printf("Could not NtQueryInformationProcess for %lu, error: %lu\n", static_cast<unsigned long>(status), GetLastError());
        return 1;
    }

    // PEB
    PEB peb = {};
    // needs to call original ReadVirtualMemory, else recursion!
    if (pbi.PebBaseAddress != 0 && !ReadProcessMemory(hProcess, reinterpret_cast<void*>(pbi.PebBaseAddress), &peb, static_cast<ULONG>(sizeof(peb)), 0)) {
        printf("[!] Could not ReadProcessMemory, error: %lu\n", GetLastError());
        return 1;
    }

    if (!peb.Ldr) {
        printf("[!] PEB.Ldr is NULL");
        return 1;
    }

    // PEB_LDR_DATA
    PEB_LDR_DATA ldr = {};
    // needs to call original ReadVirtualMemory, else recursion!
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, (ULONG)sizeof(PEB_LDR_DATA), 0)) {
        printf("[!] ReadProcessMemory failed for PEB_LDR_DATA, error: %lu\n", GetLastError());
        return 1;
    }
    
    // InMemoryOrderModuleList
    LIST_ENTRY* head = &ldr.InMemoryOrderModuleList;
    LIST_ENTRY* current = ldr.InMemoryOrderModuleList.Flink;

    int maxIterations = 1000;
    int iteration = 0;

    while (current != head && iteration < maxIterations) {
        _LDR_DATA_TABLE_ENTRY entry = {};
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry, sizeof(_LDR_DATA_TABLE_ENTRY), NULL)) {
            printf("[!] ReadProcessMemory failed for LDR_DATA_TABLE_ENTRY. Error: %lu\n", GetLastError());
            break;
        }

        if (entry.DllBase == 0) { // all zero is last one for some reason
            break;
        }

        // Validate pointers before using them
        UNICODE_STRING name = entry.FullDllName;
        if (!name.Buffer || name.Length == 0 || name.Length > 2048 || IsBadReadPtr(name.Buffer, name.Length)) {
            printf("[!] Invalid FullDllName in LDR_DATA_TABLE_ENTRY, length=%i\n", name.Length);
            current = entry.InMemoryOrderLinks.Flink;
            iteration++;
            continue;
        }

        char nameBuf[MAX_PATH] = { 0 };
        int wcharCount = name.Length / sizeof(WCHAR);
        WideCharToMultiByte(CP_ACP, 0, name.Buffer, wcharCount, nameBuf, MAX_PATH - 1, NULL, NULL);
        nameBuf[MAX_PATH - 1] = '\0'; // ensure termination

        printf("[+] Found entry: name=%s, base=%p, size=%p", nameBuf, entry.DllBase, entry.Reserved3[1]);

        // Move to the next module in the list
        current = entry.InMemoryOrderLinks.Flink;
        iteration++;
    }

    if (iteration >= maxIterations) {
        printf("[!] Hit maximum iteration limit\n");
    }

    return 0;
}
