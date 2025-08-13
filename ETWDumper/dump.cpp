// etw_dumper.cpp
// Minimal ETW provider dumper: find PID by process name, enumerate providers, show instances that match PID.
//
// Compile with: cl /EHsc etw_dumper.cpp advapi32.lib

#include <windows.h>
#include <tlhelp32.h>
#include <evntrace.h>
#include <stdio.h>
#include <vector>
#include <string>

DWORD FindPidByName(const wchar_t* targetName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, targetName) == 0) {
                pid = pe.th32ProcessID;
                break; // return first match; change if you want all matches
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) {
        wprintf(L"Usage: %s <processname.exe>\n", argv[0]);
        return 1;
    }

    const wchar_t* procName = argv[1];
    DWORD targetPid = FindPidByName(procName);
    if (targetPid == 0) {
        wprintf(L"[!] Process '%s' not found.\n", procName);
        return 2;
    }

    wprintf(L"[+] Found PID %u for '%s'\n", targetPid, procName);

    ULONG status = ERROR_SUCCESS;
    ULONG required = 0;
    GUID* guidBuffer = nullptr;
    ULONG guidBufSize = 0;

    // First ask for required size for TraceGuidQueryList
    status = EnumerateTraceGuidsEx(TraceGuidQueryList, nullptr, 0, nullptr, 0, &required);
    if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS) {
        wprintf(L"EnumerateTraceGuidsEx(TraceGuidQueryList) failed (code %lu)\n", status);
        return 3;
    }

    // allocate
    guidBuffer = (GUID*)malloc(required);
    if (!guidBuffer) {
        wprintf(L"[!] Allocation failed\n");
        return 4;
    }
    ZeroMemory(guidBuffer, required);
    guidBufSize = required;

    status = EnumerateTraceGuidsEx(TraceGuidQueryList, nullptr, 0, guidBuffer, guidBufSize, &required);
    if (status != ERROR_SUCCESS) {
        wprintf(L"[!] EnumerateTraceGuidsEx(TraceGuidQueryList) failed (code %lu)\n", status);
        free(guidBuffer);
        return 5;
    }

    ULONG guidCount = guidBufSize / sizeof(GUID);
    wprintf(L"[+] Total providers enumerated: %lu\n", guidCount);

    // For each GUID, request the provider info (TraceGuidQueryInfo) which returns TRACE_GUID_INFO
    for (ULONG i = 0; i < guidCount; ++i) {
        GUID provider = guidBuffer[i];
        wchar_t guidStr[64] = { 0 };
        StringFromGUID2(provider, guidStr, ARRAYSIZE(guidStr));
        wprintf(L"Provider GUID: %s\n", guidStr);

        PTRACE_GUID_INFO info = nullptr;
        ULONG infoSize = 0;
        status = EnumerateTraceGuidsEx(TraceGuidQueryInfo, &provider, sizeof(provider), nullptr, 0, &infoSize);

        if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS) {
            wprintf(L"  EnumerateTraceGuidsEx(TraceGuidQueryInfo) failed (code %lu)\n\n", status);
            continue;
        }

        info = (PTRACE_GUID_INFO)malloc(infoSize);
        if (!info) {
            wprintf(L"  Allocation failed for provider info\n\n");
            continue;
        }
        ZeroMemory(info, infoSize);

        status = EnumerateTraceGuidsEx(TraceGuidQueryInfo, &provider, sizeof(provider), info, infoSize, &infoSize);
        if (status != ERROR_SUCCESS) {
            wprintf(L"  EnumerateTraceGuidsEx(TraceGuidQueryInfo) failed (code %lu)\n\n", status);
            free(info);
            continue;
        }

        // TRACE_GUID_INFO header is followed by TRACE_PROVIDER_INSTANCE_INFO blocks
        PTRACE_PROVIDER_INSTANCE_INFO pInstance = (PTRACE_PROVIDER_INSTANCE_INFO)((BYTE*)info + sizeof(TRACE_GUID_INFO));
        if (info->InstanceCount == 0) {
            wprintf(L"  No instances\n\n");
            free(info);
            continue;
        }

        for (DWORD j = 0; j < info->InstanceCount; ++j) {
            if (pInstance->Pid == targetPid) {
                wprintf(L"  >>> Instance for PID %u <<<\n", pInstance->Pid);
                if (pInstance->Flags & TRACE_PROVIDER_FLAG_LEGACY) {
                    wprintf(L"    Registration method: RegisterTraceGuids (legacy)\n");
                }
                else {
                    wprintf(L"    Registration method: EventRegister\n");
                }

                wprintf(L"    EnableCount: %u\n", pInstance->EnableCount);
                // if enabled by sessions, print enable info blocks
                PTRACE_ENABLE_INFO pEnable = (PTRACE_ENABLE_INFO)((BYTE*)pInstance + sizeof(TRACE_PROVIDER_INSTANCE_INFO));
                for (DWORD k = 0; k < pInstance->EnableCount; ++k) {
                    wprintf(L"      SessionId: %hu Level: %hu MatchAny: %llu MatchAll: %llu EnableProperty: %u\n",
                        pEnable->LoggerId, pEnable->Level,
                        (unsigned long long)pEnable->MatchAnyKeyword,
                        (unsigned long long)pEnable->MatchAllKeyword,
                        pEnable->EnableProperty);
                    pEnable++;
                }
                wprintf(L"\n");
            }
            // move to next instance (NextOffset bytes ahead)
            if (pInstance->NextOffset == 0) break;
            pInstance = (PTRACE_PROVIDER_INSTANCE_INFO)((BYTE*)pInstance + pInstance->NextOffset);
        }

        free(info);
    }

    free(guidBuffer);
    return 0;
}
