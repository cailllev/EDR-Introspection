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
    bool debug = false;
    int pid = 0;
    if (argc < 2) {
        pid = GetCurrentProcessId();
        printf("[*] Reading PEB from current process, pid=%i\n", pid);
    }
    else {
        pid = atoi(argv[1]);
        if (pid == 0) {
            printf("[!] Invalid PID: %i\n", pid);
        }
        printf("[*] Reading PEB from process pid=%i\n", pid);
        if (argc == 3) {
            debug = true;
        }
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
        return 1;
    }

    // PBI
    NTSTATUS status = pNtQueryInfoProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        printf("Could not NtQueryInformationProcess for %i, status=%lu error: %lu\n", pid, static_cast<unsigned long>(status), GetLastError());
        return 1;
    }
    if (pbi.PebBaseAddress == 0) {
        printf("[!] pbi.PebBaseAddress is NULL\n");
        return 1;
    }
    printf("[*] Got PBI.PebBaseAddress = 0x%p\n", reinterpret_cast<void*>(pbi.PebBaseAddress));

    // PEB, read into local PEB
    SIZE_T bytesRead = 0;
    PEB peb = { 0 };
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        printf("[!] Could not ReadProcessMemory(PEB), error: %lu\n", GetLastError());
        return 1;
    }
    if (debug) {
        printf("[+] Read %llu bytes for PEB\n", (unsigned long long)bytesRead);
    }
    if (!peb.Ldr) {
        printf("[!] PEB.Ldr is NULL\n"); 
        return 1; 
    }
    // remote pointer to PEB_LDR_DATA
    PBYTE remoteLdrAddr = (PBYTE)peb.Ldr;
    printf("[*] Got remote PEB.LDR     = 0x%p\n", remoteLdrAddr);

    // read remote PEB_LDR_DATA into local ldr
    PEB_LDR_DATA ldr = { 0 };
    if (!ReadProcessMemory(hProcess, remoteLdrAddr, &ldr, sizeof(ldr), &bytesRead)) {
        printf("[!] ReadProcessMemory failed for PEB_LDR_DATA, error: %lu\n", GetLastError());
        return 1;
    }
    if (debug) {
        printf("[+] Read %llu bytes for PEB_LDR_DATA\n", (unsigned long long)bytesRead);
    }

    // compute remote head address (remote address of the LIST_ENTRY inside the remote PEB_LDR_DATA)
    PBYTE remoteHead = remoteLdrAddr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
    printf("[*] Got remote remoteHead  = 0x%p\n", remoteHead);

    // start with the remote Flink (this is a remote pointer)
    LIST_ENTRY remoteList = ldr.InMemoryOrderModuleList;
    PVOID current = remoteList.Flink; // remote address

    int maxIterations = 1000;
    int iter = 0;

    while (current && (PBYTE)current != remoteHead && iter < maxIterations) {
        // remote address of the containing LDR_DATA_TABLE_ENTRY
        PBYTE remoteEntryAddr = (PBYTE)current - offsetof(_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        _LDR_DATA_TABLE_ENTRY entry;
        ZeroMemory(&entry, sizeof(entry));
        if (!ReadProcessMemory(hProcess, remoteEntryAddr, &entry, sizeof(entry), &bytesRead)) {
            printf("[!] RPM failed for LDR entry at %p. Error: %lu\n", remoteEntryAddr, GetLastError());
            break;
        }
        if (debug) {
            printf("[+] Read %llu bytes for LDR entry\n", (unsigned long long)bytesRead);
        }

        if (entry.DllBase == NULL) {
            // end marker (or corrupted)
            break;
        }

        // Read the remote FullDllName.Buffer into a local wchar buffer
        USHORT nameLen = entry.FullDllName.Length;
        if (nameLen > 0 && nameLen < 0x2000) { // sanity cap
            size_t wcharCount = (nameLen / sizeof(WCHAR));
            WCHAR* localNameW = (WCHAR*)malloc((wcharCount + 1) * sizeof(WCHAR));
            if (localNameW) {
                ZeroMemory(localNameW, (wcharCount + 1)*sizeof(WCHAR));
                if (entry.FullDllName.Buffer && 
                    ReadProcessMemory(hProcess, entry.FullDllName.Buffer, localNameW, nameLen, &bytesRead)) {
                    localNameW[wcharCount] = L'\0';
                    char nameBuf[MAX_PATH];
                    WideCharToMultiByte(CP_ACP, 0, localNameW, -1, nameBuf, sizeof(nameBuf), NULL, NULL);
                    printf("[+] Found entry: base=0x%p, size=0x%p, name=%s\n", entry.DllBase, (PVOID)entry.Reserved3[1], nameBuf);
                } else {
                    printf("[!] Could not read remote name buffer at %p (len=%u). Error: %lu\n", entry.FullDllName.Buffer, nameLen, GetLastError());
                }
                free(localNameW);
            }
        } else {
            printf("[!] Invalid name length: %u\n", nameLen);
        }

        // advance to next remote entry
        current = entry.InMemoryOrderLinks.Flink; // this is a remote pointer read from the entry we just copied locally
        iter++;
    }

    if (iter >= maxIterations) {
        printf("[!] Hit maximum iteration limit\n");
    }

    return 0;
}
