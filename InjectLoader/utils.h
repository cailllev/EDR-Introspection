#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <string>

int Unload(int, const std::string);
HANDLE findProcHandle(int, BOOL);