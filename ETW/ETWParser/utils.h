#pragma once

#include <string>

// all stolen from https://github.com/dobin/RedEdr

std::string wchar2string(const wchar_t* wstr);
std::string wstring2string(std::wstring& wide_string);
bool wstring_starts_with(const std::wstring& str, const std::wstring& prefix);
std::string filetime_to_iso8601(__int64 timestamp);

char* get_memory_region_protect(DWORD protect);

LONGLONG get_usn(std::string filepath);
int get_PID_by_name(std::string);