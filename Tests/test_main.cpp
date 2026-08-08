#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_EXTERNAL_INTERFACES
#include "catch.hpp"
#include <iostream>
#include <string>

struct DetailedTestListener : Catch::TestEventListenerBase {
    using TestEventListenerBase::TestEventListenerBase;

    std::string m_currentTestName;

    // 1. Called when a TEST_CASE starts
    void testCaseStarting(Catch::TestCaseInfo const& testInfo) override {
        m_currentTestName = testInfo.name;
        std::cout << "\n========================================\n"
            << "[TEST CASE]: " << testInfo.name << "\n"
            << "========================================\n";
    }

    // 2. Called when a SECTION starts
    void sectionStarting(Catch::SectionInfo const& sectionInfo) override {
        // Filter out the implicit root section (which shares the test case name in Catch2 v2)
        if (sectionInfo.name != m_currentTestName) {
            std::cout << "  [SECTION]: " << sectionInfo.name << "\n";
        }
    }

    // 3. Called BEFORE a REQUIRE/CHECK evaluates
    void assertionStarting(Catch::AssertionInfo const& assertionInfo) override {
        std::cout << "    [ASSERTION]: " << assertionInfo.macroName
            << "(" << assertionInfo.capturedExpression << ")\n";
    }

    // 4. Called AFTER a REQUIRE/CHECK completes
    bool assertionEnded(Catch::AssertionStats const& assertionStats) override {
        auto const& result = assertionStats.assertionResult;
        if (result.isOk()) {
            std::cout << "      -> PASSED\n";
        }
        else {
            std::cout << "      -> FAILED: " << result.getExpression() << "\n";
        }
        return result.isOk();
    }
};

CATCH_REGISTER_LISTENER(DetailedTestListener)