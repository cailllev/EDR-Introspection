#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

static int remote_exit_by_pid(DWORD pid, UINT exit_code, DWORD timeout_ms) {
    HANDLE hProc = NULL;
    HANDLE hThread = NULL;
    int result = 0;

    // Open target process with required rights
    hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc) {
        fprintf(stderr, "OpenProcess(%u) failed: %u\n", (unsigned)pid, GetLastError());
        if (hThread) CloseHandle(hThread);
        if (hProc) CloseHandle(hProc);
        return result;
    }

    // Get address of ExitProcess in our own process' kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        fprintf(stderr, "GetModuleHandleA(kernel32.dll) failed: %u\n", GetLastError());
        if (hThread) CloseHandle(hThread);
        if (hProc) CloseHandle(hProc);
        return result;
    }

    FARPROC pExitProc = GetProcAddress(hKernel32, "ExitProcess");
    if (!pExitProc) {
        fprintf(stderr, "GetProcAddress(ExitProcess) failed: %u\n", GetLastError());
        if (hThread) CloseHandle(hThread);
        if (hProc) CloseHandle(hProc);
        return result;
    }

    // Create a remote thread in the target process to call ExitProcess(exit_code)
    hThread = CreateRemoteThread(
        hProc,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pExitProc,
        (LPVOID)(uintptr_t)exit_code,
        0,
        NULL);
    if (!hThread) {
        fprintf(stderr, "CreateRemoteThread failed: %u\n", GetLastError());
        if (hThread) CloseHandle(hThread);
        if (hProc) CloseHandle(hProc);
        return result;
    }

    // Optionally wait for the remote thread (which should cause the process to begin exit)
    DWORD wait = WaitForSingleObject(hThread, timeout_ms);
    if (wait == WAIT_OBJECT_0) {
        printf("Remote thread executed; target PID %u should be exiting.\n", (unsigned)pid);
        result = 1;
    }
    else if (wait == WAIT_TIMEOUT) {
        fprintf(stderr, "Timed out waiting for remote thread (thread still running). The process may still exit asynchronously.\n");
        // still success in creating the remote thread; mark as success (return value 1)
        result = 1;
    }
    else {
        fprintf(stderr, "WaitForSingleObject failed: %u\n", GetLastError());
    }
}

static void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s <pid> [exit_code]\n", prog);
    fprintf(stderr, "  pid        - PID of the target process to request ExitProcess in\n");
    fprintf(stderr, "  exit_code  - optional exit code (default: 1)\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    char* endptr = NULL;
    unsigned long pid_ul = strtoul(argv[1], &endptr, 0);
    if (endptr == argv[1] || pid_ul == 0) {
        fprintf(stderr, "Invalid PID: %s\n", argv[1]);
        return 1;
    }
    DWORD pid = (DWORD)pid_ul;

    UINT exit_code = 1;
    if (argc >= 3) {
        exit_code = (UINT)strtoul(argv[2], NULL, 0);
    }

    printf("Requesting ExitProcess(%u) in PID %u\n", exit_code, (unsigned)pid);
    int ok = remote_exit_by_pid(pid, exit_code, 5000 /* ms wait */);
    if (!ok) {
        fprintf(stderr, "Failed to request remote exit for PID %u\n", (unsigned)pid);
        return 2;
    }

    printf("Done.\n");
    return 0;
}