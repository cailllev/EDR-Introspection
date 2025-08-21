#pragma once

#include <string>

// all stolen from https://github.com/dobin/RedEdr

std::string wstring2string(std::wstring& wide_string);
std::string wchar2string(const wchar_t* wstr);
bool wstring_starts_with(const std::wstring& str, const std::wstring& prefix);

char* get_memory_region_protect(DWORD protect);