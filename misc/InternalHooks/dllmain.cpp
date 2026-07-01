#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <detours/detours.h>
#include <iostream>

// Standard setup...
using FnNtOpenProcess = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
FnNtOpenProcess TrueNtOpenProcess = nullptr;

NTSTATUS NTAPI MyNtOpenProcess(PHANDLE PH, ACCESS_MASK AM, PVOID OA, PVOID CI) {
	std::cout << "[*] MyNtOpenProcess called! PH=" << PH << ", AM=" << AM << ", OA=" << OA << ", CI=" << CI << "\n";
    return TrueNtOpenProcess(PH, AM, OA, CI);
}

// EXPORT THIS FUNCTION: This is your remote trigger
extern "C" __declspec(dllexport) void CALLBACK ActivateHook() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return;
    }
    TrueNtOpenProcess = (FnNtOpenProcess)GetProcAddress(hNtdll, "NtOpenProcess");

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)TrueNtOpenProcess, MyNtOpenProcess);
    DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    return TRUE; // Do nothing here!
}

