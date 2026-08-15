#pragma once

#include <string>

#ifndef HANDLE
typedef void* HANDLE;
#endif

#ifndef DWORD
typedef unsigned long DWORD;
#endif

enum Injection {
    LOADLIBRARY_INJECTION,
    HOSTMAPPED_INJECTION,
    REFLECTIVE_INJECTION,
    STOP_INJECTION
};

enum Executor {
	CREATE_REMOTE_THREAD,
    HIJACK_THREAD,
    QUEUE_USER_APC2
};

bool InjectDll(DWORD pid, const std::string& dllPath, HANDLE hProcess, Injection injectionType, Executor execType, bool debug);
std::string GetInjectTypeStr(Injection injectType);
std::string GetExecutorTypeStr(Executor execType);