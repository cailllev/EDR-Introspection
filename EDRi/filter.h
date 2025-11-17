#pragma once

#include <vector>

#include "helpers/json.hpp"

#include "globals.h"
#include "etwparser.h"

enum Classifier { All, Relevant, Minimal };
extern std::map<Classifier, std::string> classifier_names;

// -------------------- FILTERING LISTS -------------------- //
// Antimalware Trace
static const std::vector<int> am_event_ids_to_remove = { 7, 44, 62 };
static const std::vector<int> am_event_ids_with_opid = { 5, 6, 11, 15, 16, 26, 29, 104, 105, 109, 110, 111, 112, 60, 70, 71, 72, 73 };
static const std::vector<int> am_event_ids_with_pid_but_noisy = { 11, 111, 112 };
static const std::vector<int> am_event_ids_with_opid_and_tpid = { 53 };
static const std::vector<int> am_event_ids_with_pid_in_data = { 43, 67 };
static const std::vector<int> am_event_ids_with_message = { 3 };
static const std::vector<int> am_event_ids_with_filepath = { 30, 31, 35, 36, 37, 38 };
static const std::vector<int> am_event_ids_with_pipe = { 32, 33 };
static const std::vector<int> am_event_ids_with_signatures = { 59 }; 
// event 59 just logs all Behaviour tracking tasks, but has no identifier tied to actual files / events / procs, etc.
// -> sigseq and sigsha only identify the tracking task, NOT the file / event / proc --> put event 59 in Relevant

// Kernel Process Trace
static const std::vector<int> kproc_event_ids_with_attack_pid_tpid = { 3, 4 };
static const std::vector<int> kproc_event_ids_with_pid_or_tpid_minimal = { 1, 2, 11 };
static const std::vector<int> kproc_event_ids_with_tpid_relevant = { 5, 6 };

// Kernel API Calls Trace
static const std::vector<int> kapi_event_ids_with_pid = { 3 };
static const std::vector<int> kapi_event_ids_with_tpid = { 5, 6 };

// Kernel File Trace
static const std::vector<int> kfile_event_ids_with_pid = { 10, 30 };

// Kernel Network Trace
static const std::vector<int> knet_event_ids_with_pid_or_opid = { 12, 15, 28, 31, 42, 43, 58, 59 };

// ETW-TI trace
static const std::vector<int> ti_events_with_pid_or_tpid = { 2, 6, 12, 14, 16 };


// -------------------- POST EXE FILTERING LISTS -------------------- //
static const std::vector<std::pair<std::string, std::string>> kapi_irrelevant_exe = { { "VBoxService.exe", PID } };


// -------------------- FILTERING FUNCTIONS -------------------- //
std::map<Classifier, std::vector<json>> filter_all_events(std::vector<json>);
void add_exe_information(json&, Classifier c);

// pid fields that should have the exe name added at print time
static const std::vector<std::string> fields_to_add_exe_name = { PID, PPID, TARGET_PID, ORIGINATING_PID };

// internal functions
Classifier filter(json&);
Classifier filter_post_exe(json&, Classifier);
Classifier classify_to(json&, std::string, std::vector<int>);
Classifier filter_kernel_process(json&);
Classifier filter_threat_intel(json&);
Classifier filter_kernel_api_call(json&);
Classifier filter_kernel_file(json&);
Classifier filter_kernel_network(json&);
Classifier filter_antimalware(json&);
Classifier filter_hooks(json&);
