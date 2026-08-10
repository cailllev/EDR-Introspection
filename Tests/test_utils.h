#pragma once

#include <string>
#include <vector>

struct TestETWEvent {
    std::string message;
    uint64_t ns_since_epoch;
    uint64_t targetpid;
};

extern std::vector<TestETWEvent> capturedEvents;

void StartETWCapture();
void StopETWCapture();