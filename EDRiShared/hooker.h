#pragma once

#include <string>

typedef void* HANDLE;

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

bool InjectDll(int, const std::string&, bool, Action, HANDLE, Execution);