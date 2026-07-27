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

bool InjectDll(int, const std::string&, bool, Action, HANDLE, bool);