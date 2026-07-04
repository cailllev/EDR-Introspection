#pragma once

#include <string>

enum Action {
    LOADLIBRARY_INJECTION,
    EXTERNAL_INJECTION,
    REFLECTIVE_INJECTION,
    STOP_INJECTION
};

bool inject_dll(int, const std::string&, bool, Action, HANDLE);