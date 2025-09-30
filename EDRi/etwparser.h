#pragma once

#include <krabs.hpp>
#include <vector>
#include <string>

#include "globals.h"
#include "utils.h"

// do not add stacktrace to final results
static const bool include_stacktrace = false;

// magic numbers
static const int KERNEL_PROC_START_EVENT_ID = 1;
static const int KERNEL_PROC_STOP_EVENT_ID = 2;
static const int ANTIMALWARE_PROC_START_STOP_EVENT_ID = 73;
static const std::string ANTIMALWARE_PROC_START_MSG = "SyncStart";
static const std::string ANTIMALWARE_PROC_STOP_MSG = "Termination";

// my message field name (custom ETW events)
static const std::string MY_MESSAGE = "message"; // this name must not be contained in the event header, else parsing of own emitted events breaks
static const std::wstring MY_MESSAGE_W = std::wstring(MY_MESSAGE.begin(), MY_MESSAGE.end());

// the names of the providers to track
static const std::string KERNEL_PROCESS_PROVIDER = "Microsoft-Windows-Kernel-Process";
static const std::wstring KERNEL_PROCESS_PROVIDER_W = std::wstring(KERNEL_PROCESS_PROVIDER.begin(), KERNEL_PROCESS_PROVIDER.end());
static const std::string KERNEL_API_PROVIDER = "Microsoft-Windows-Kernel-Audit-API-Calls";
static const std::wstring KERNEL_API_PROVIDER_W = std::wstring(KERNEL_API_PROVIDER.begin(), KERNEL_API_PROVIDER.end());
static const std::string KERNEL_FILE_PROVIDER = "Microsoft-Windows-Kernel-File";
static const std::wstring KERNEL_FILE_PROVIDER_W = std::wstring(KERNEL_FILE_PROVIDER.begin(), KERNEL_FILE_PROVIDER.end());
static const std::string KERNEL_NETWORK_PROVIDER = "Microsoft-Windows-Kernel-Network";
static const std::wstring KERNEL_NETWORK_PROVIDER_W = std::wstring(KERNEL_NETWORK_PROVIDER.begin(), KERNEL_NETWORK_PROVIDER.end());
static const std::string ANTIMALWARE_PROVIDER = "Microsoft-Antimalware-Engine";
static const std::wstring ANTIMALWARE_PROVIDER_W = std::wstring(ANTIMALWARE_PROVIDER.begin(), ANTIMALWARE_PROVIDER.end());
static const std::string THREAT_INTEL_PROVIDER = "Microsoft-Windows-Threat-Intelligence";
static const std::wstring THREAT_INTEL_PROVIDER_W = std::wstring(THREAT_INTEL_PROVIDER.begin(), THREAT_INTEL_PROVIDER.end());

// the struct that is passed from function to function (or as a json after parsing)
struct Event {
    const EVENT_RECORD& record;
    const krabs::schema schema;
};

// fixed attributes inside the header and schema --> string can be chosen "freely", but must be unique over all properties!
// most properties do not use _, it's safe to use _ for these fixed attributes here
static const std::string TIMESTAMP = "timestamp";
static const std::string TYPE = "src_type";
static const std::string PROVIDER_NAME = "provider_name";
static const std::string EVENT_ID = "event_id";
static const std::string TASK = "task_info"; // task_name + opcode_name
static const std::string PID = "process_id";
static const std::string TID = "thread_id";

// properties from the actual events --> values cannot be changed!
static const std::string PPID = "ppid";
static const std::string TARGET_PID = "targetpid";
static const std::string TARGET_TID = "targettid";
static const std::string KERNEL_PID = "processid"; // TARGET_PID for kernel-traces, DO NOT USE FURTHER, THIS IS MERGED INTO TARGET_PID! USE TARGET_PID INSTEAD!
static const std::string ORIGINATING_PID = "pid"; // antimalware-traces
static const std::string FILEPATH = "filepath";
static const std::string MESSAGE = "message";
static const std::string SIGSEQ = "sigseq";
static const std::string SIGSHA = "sigsha";
static const std::string FIRST_PARAM = "firstparam";
static const std::string SECOND_PARAM = "secondparam";
static const std::string CLASSIFICATION = "classification";
static const std::string DETERMINATION = "determination";
static const std::string RESOURCESCHEMA = "resourceschema";
static const std::string REALPATH = "realpath";
static const std::string THREATNAME = "threatname";
static const std::string DATA = "data";
static const std::string SOURCE = "source";

// executables used for the attack
static const std::string injected_exe = "notepad.exe"; // TODO add whole path? But must be Windows independent (is ...\WindowsApps\Microsoft.WindowsNotepad_8wekyb3d8bbwe\...) in the logs

// executables to track for kernel event filtering, i.e. their PIDs at runtime
static const std::vector<std::string> exes_to_track = {
    // attack_PID and injected_PID are added to g_tracking_PIDs at runtime, not as exes here (they are not running at startup)
    "smartscreen.exe", "System"
};


// keys that get merged together
struct MergeCategory {
    std::string merged_key;
    std::vector<std::string> keys_to_merge;
};
extern MergeCategory ppid_keys, tpid_keys, ttid_keys, filepath_keys;

// processing the events
enum Classifier;
std::map<Classifier, std::vector<json>> get_cleaned_events();
std::string get_classifier_name(Classifier);
void print_etw_counts();
void dump_signatures();

// internal functions
void my_event_callback(const EVENT_RECORD&, const krabs::trace_context&);
void event_callback(const EVENT_RECORD&, const krabs::trace_context&);
json parse_my_etw_event(Event);
json parse_etw_event(Event);
void parse_all_properties(krabs::parser&, json&);
std::string get_val(const json&, std::string);
void post_my_parsing_checks(json&);
void post_parsing_checks(json&);
void add_exe_information(json& j);
int check_new_proc(json&);
bool check_traces_started(json&);
Classifier filter(json&);
Classifier classify_to(json&, std::string, std::vector<int>);
Classifier filter_kernel_process(json&);
Classifier filter_threat_intel(json&);
Classifier filter_kernel_api_call(json&);
Classifier filter_kernel_file(json&);
Classifier filter_kernel_network(json&);
Classifier filter_antimalware(json&);
void count_event(json, bool);
void clean_events();