#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#include "test_utils.h"

struct ETWTestEventListener : Catch::TestEventListenerBase {
    using TestEventListenerBase::TestEventListenerBase;

    // Called ONCE before the very first test case starts
    void testRunStarting(Catch::TestRunInfo const& testRunInfo) override {
        StartETWCapture();
		Sleep(2000); // give time for ETW to start capturing events
    }

    // Called ONCE after all test cases finish
    void testRunEnded(Catch::TestRunStats const& testRunStats) override {
        StopETWCapture();
    }
};

// Register the custom listener with Catch2
CATCH_REGISTER_LISTENER(ETWTestEventListener)