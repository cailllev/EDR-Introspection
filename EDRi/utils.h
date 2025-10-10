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
std::string unnecessary_tools_running();

bool filepath_match(std::string, std::string);
bool launch_as_child(const std::string& path);

std::wstring get_base_path();
std::string get_hook_dll_path();
bool xor_file(std::string, std::string);
std::string get_available_attacks();
bool is_attack_available(const std::string&);
std::string get_attack_enc_path(const std::string&);

void build_device_map();
std::string translate_if_path(const std::string&);

// custom key for technicolor in timeline explorer TODO enable disable flag
static const std::string COLOR_HEADER = "Source Name,Long Description,Timestamp";
static const std::string FAKE_TIMESTAMP = "2020-20-20 20:20:20";
static const std::string COLOR_GREEN = "FILE,Name:," + FAKE_TIMESTAMP;
static const std::string COLOR_RED = "PREFETCH,was executed," + FAKE_TIMESTAMP;
static const std::string COLOR_BLUE = "REG,Computer\\HKEY_LOCAL_MACHINE\\SYSTEM\\DUMMY," + FAKE_TIMESTAMP;
static const std::string COLOR_PURPLE = "ETW,," + FAKE_TIMESTAMP;
static const std::string COLOR_YELLOW = "LNK,," + FAKE_TIMESTAMP;
static const std::string COLOR_GRAY = "UNKNOWN,," + FAKE_TIMESTAMP;
std::string add_color_info(const json&);
void write_events_to_file(const std::string&);
std::string create_timeline_csv(const std::vector<json>&, std::vector<std::string>);