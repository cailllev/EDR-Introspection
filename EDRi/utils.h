#pragma once

#include <map>
#include <string>

#include "globals.h"

static const std::string PROC_NOT_FOUND = "<not found>";

// all stolen from https://github.com/dobin/RedEdr
std::string wchar2string(const wchar_t* wstr);
std::string wstring2string(std::wstring& wide_string);
bool wstring_starts_with(const std::wstring& str, const std::wstring& prefix);
std::string filetime_to_iso8601(__int64 timestamp);
char* get_memory_region_protect(DWORD protect);

// own cacophony
void snapshot_procs();
int get_PID_by_name(const std::string& name);
void add_proc(int, const std::string&);
std::string get_proc_name(int);

bool filepath_match(std::string, std::string);
bool launch_as_child(const std::string& path);

bool xor_file(std::string, std::string);

void build_device_map();
std::string translate_if_path(const std::string&);