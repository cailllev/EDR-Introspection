#pragma once

#include <string>

struct TestETWEvent {
    std::string message;
    uint64_t NsSinceEpoch;
    uint64_t targetPid;
};

extern TestETWEvent g_lastEvent;
extern HANDLE g_hEtwEvent;

void StartETWCapture();
void StopETWCapture();
DWORD GetProcessIdByName(const std::wstring& processName);

BOOL WaitForEtwEvent(DWORD timeoutMs, DWORD expectedTargetPid, std::string expectedMessage);