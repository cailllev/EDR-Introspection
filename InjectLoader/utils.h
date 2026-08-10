#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <string>

HMODULE GetRemoteManualMappedModule(HANDLE, const std::string&);
HMODULE GetRemoteModuleHandle(DWORD, const std::string&);
BOOL UnloadViaThread(DWORD, const std::string);
BOOL UnloadViaEvent(DWORD, const std::string);
HANDLE findProcHandle(DWORD, BOOL);