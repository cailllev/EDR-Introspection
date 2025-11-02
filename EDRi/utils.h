#pragma once

#include <map>
#include <string>

#include "globals.h"

static const std::string PROC_NOT_FOUND = "<not found>";

// all stolen from https://github.com/dobin/RedEdr
std::string wchar2string(const wchar_t* wstr);
std::string wstring2string(std::wstring& wide_string);
bool wstring_starts_with(const std::wstring& str, const std::wstring& prefix);
char* get_memory_region_protect(DWORD protect);

// TIME CONVERSION, https://stackoverflow.com/questions/6161776/convert-windows-filetime-to-second-in-unix-linux#answer-6161842
const UINT64 WINDOWS_TICKS_PER_SECOND = 10'000'000ULL; // 100ns intervals
const UINT64 NS_PER_WINDOWS_TICK = 100ULL;             // 1 tick per 100ns
const UINT64 SECS_TO_UNIX_EPOCH = 11644473600ULL;      // seconds between 1601 and 1970
const UINT64 WINDOWS_TICKS_TO_UNIX_EPOCH = SECS_TO_UNIX_EPOCH * WINDOWS_TICKS_PER_SECOND;

// own cacophony
static const UINT64 MIN_PROC_START = 0;
static const UINT64 MAX_PROC_END = MAXUINT64;
static const UINT64 RESERVE_NS = 100'000; // 0,1 ms padding to minimize race conditions between etw logs // TODO: when event not between start-end, check if other start-end exists, and which of the ranges is closer
UINT64 get_ns_time();
void snapshot_procs();
std::vector<int> get_PID_by_name(const std::string& name, UINT64 timestamp);
void add_proc(int, const std::string&, UINT64, bool);
void mark_termination(int, UINT64);
std::string get_proc_name(int, UINT64);
std::vector<ProcInfo> get_tracked_procs();
std::string unnecessary_tools_running();
std::string get_random_3digit_num();

bool filepath_match(std::string, std::string);
bool launch_as_child(const std::string& path);

void save_hooked_procs(std::vector<int>);
std::vector<int> get_hooked_procs();

std::wstring get_base_path();
std::string get_hook_dll_path();
bool xor_file(std::string, std::string);
bool remove_file(const std::string&);
std::string get_available_attacks();
bool is_attack_available(const std::string&);
std::string get_attack_enc_path(const std::string&);

UINT64 filetime_to_unix_epoch_ns(__int64 timestamp);
std::string filetime_to_iso8601(__int64 timestamp);
std::string unix_epoch_ns_to_iso8601(uint64_t);