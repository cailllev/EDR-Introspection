#pragma once

#include <vector>

// event ids with X to filter for
static const std::vector<int> event_ids_with_pid = { 104, 109, 11, 111, 112, 15, 16, 26, 29, 5, 6, 60, 71, 72, 73 };
static const std::vector<int> event_ids_with_pid_or_tpid = { 53, 70 };
static const std::vector<int> event_ids_with_pid_in_data = { 43, 67 };
static const std::vector<int> event_ids_to_remove = { 44, 62, 7 };

// TODO as func?


/* TODO
# FILTERS #
PID filter (field PID): 104, 109, 11, 111, 112, 15, 16, 26, 29, 5, 6, 60, 70, 71, 72, 73
PID filder (field Data): 43, 67
53, 70: filter (PID || PPID) in (injector.exe, notepad.exe)
60, 104: filter (PID) in (injector.exe, notepad.exe) ???
3: Message.lowercase() contains (Injector.exe, microsoft.windowscalculator, microsoft.windowsnotepad)
31, 35, 36:
fsutil usn readdata "C:\Windows\System32\calc.exe" --> usn: 0x...
37 Cache MOACLookup: File ID=618283, File USN=1722074104
31 scan file task stop: File Path=...\Injector.exe,...ETWParser.exe
35 Cache MOACAdd: File ID=618283, File USN=1722074104, Info=Unfriendly, Result=0x0
--> 31 if File Path Contains Injector.exe, ETWParser.exe
--> 35,36 if File USN = usn(Injector.exe) || usn(ETWParser.exe)

# NO FILTERS #
59 only sig seq and sig sha?, time based?

# COMPLETELY REMOVE #
44, 62, 7? (no information)
*/