#pragma once

#include <string>

enum Action {
    LOADLIBRARY_INJECTION,
    EXTERNAL_INJECTION,
    REFLECTIVE_INJECTION,
    STOP_INJECTION
};

bool InjectDll(int, const std::string&, bool, Action, HANDLE, bool);