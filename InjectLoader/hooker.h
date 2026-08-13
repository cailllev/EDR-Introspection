#pragma once

#include <string>

#ifndef HANDLE
typedef void* HANDLE;
#endif

enum Action {
    LOADLIBRARY_INJECTION,
    EXTERNAL_INJECTION,
    REFLECTIVE_INJECTION,
    HIJACK_THREAD_TEST,
    STOP_INJECTION
};

enum Execution {
	CREATE_REMOTE_THREAD,
    HIJACK_THREAD,
    QUEUE_USER_APC2
};

bool InjectDll(DWORD pid, const std::string& dllPath, BOOL debug, Action injectionType, HANDLE hProcess, Execution execType);
std::string GetActionStr(Action a);
std::string GetExecutionStr(Execution e);