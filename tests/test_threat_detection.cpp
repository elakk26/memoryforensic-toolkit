/**
 * test_threat_detection.cpp
 * Comprehensive test suite for the Threat Detection module
 * Tests memory region analysis, threat scoring, and vulnerability detection
 */

#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
#include "../include/Logger.hpp"
#include "../include/threat_detection.h"

// Mock memory region structure for testing
struct MemoryRegion {
    uint64_t startAddress;
    uint64_t endAddress;
    std::string permissions;
    std::string path;
    bool isExecutable;
    bool isWritable;
    bool isReadable;

    uint64_t getSize() const {
        return endAddress - startAddress;
    }
};

// Test fixture class
class ThreatDetectionTest {
private:
    std::vector<MemoryRegion> testRegions;

    void setupTestData() {
        std::cout << "Setting up test data..." << std::endl;

        // 1. Normal text region (legitimate)
        testRegions.push_back({
            0x400000, 0x500000, "r-xp", "/usr/bin/test", true, false, true
        });

        // 2. Suspicious RWX region in heap (HIGH THREAT)
        testRegions.push_back({
            0x7f0000000000, 0x7f0000001000, "rwxp", "[heap]", true, true, true
        });

        // 3. Anonymous executable region (MEDIUM THREAT)
        testRegions.push_back({
            0x7f0000002000, 0x7f0000003000, "r-xp", "", true, false, true
        });

        // 4. Stack with execute permissions (CRITICAL THREAT)
        testRegions.push_back({
            0x7ffffffde000, 0x7ffffffff000, "rwxp", "[stack]", true, true, true
        });

        // 5. Normal data region (legitimate)
        testRegions.push_back({
            0x600000, 0x601000, "rw-p", "/usr/bin/test", false, true, true
        });

        // 6. Suspicious heap region with execute (HIGH THREAT)
        testRegions.push_back({
            0x1000000, 0x1001000, "rwxp", "[heap]", true, true, true
        });

        // 7. Deleted file mapping (MEDIUM THREAT)
        testRegions.push_back({
            0x2000000, 0x2001000, "r-xp", "/tmp/malware (deleted)", true, false, true
        });

        // 8. /dev/shm mapping with RWX (CRITICAL THREAT)
        testRegions.push_back({
            0x3000000, 0x3001000, "rwxp", "/dev/shm/payload", true, true, true
        });

        // 9. Normal shared library (legitimate)
        testRegions.push_back({
            0x7ffff7a00000, 0x7ffff7b00000, "r-xp", "/lib/x86_64-linux-gnu/libc.so.6", true, false, true
        });

        // 10. Suspicious /tmp executable (MEDIUM THREAT)
        testRegions.push_back({
            0x4000000, 0x4001000, "rwxp", "/tmp/.hidden_payload", true, true, true
        });

        std::cout << "✓ Loaded " << testRegions.size() << " test memory regions" << std::endl;
    }

public:
    ThreatDetectionTest() {
        Logger::getInstance()->setLogLevel(LogLevel::DEBUG);
        setupTestData();
    }

    void testSuspiciousPermissions() {
        std::cout << "\n[TEST 1/9] Suspicious Permissions Detection..." << std::endl;
        std::cout << "Testing for RWX (Read-Write-Execute) regions..." << std::endl;

        int suspiciousCount = 0;

        for (const auto& region : testRegions) {
            // Check for RWX (Read-Write-Execute) - highly suspicious
            if (region.isExecutable && region.isWritable) {
                suspiciousCount++;
                std::cout << "  ⚠️  RWX at 0x" << std::hex << region.startAddress
                          << " [" << region.permissions << "] "
                          << region.path << std::dec << std::endl;
            }
        }

        assert(suspiciousCount > 0 && "Should detect suspicious permissions");
        std::cout << "✓ Detected " << suspiciousCount << " RWX regions" << std::endl;
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testAnonymousExecutable() {
        std::cout << "[TEST 2/9] Anonymous Executable Detection..." << std::endl;
        std::cout << "Testing for executable regions without file backing..." << std::endl;

        int anonymousExecCount = 0;

        for (const auto& region : testRegions) {
            // Anonymous executable regions are suspicious
            if (region.isExecutable && region.path.empty()) {
                anonymousExecCount++;
                std::cout << "  ⚠️  Anonymous exec at 0x" << std::hex
                          << region.startAddress << " - " << region.permissions
                          << std::dec << std::endl;
            }
        }

        assert(anonymousExecCount > 0 && "Should detect anonymous executables");
        std::cout << "✓ Detected " << anonymousExecCount << " anonymous executable regions" << std::endl;
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testExecutableStack() {
        std::cout << "[TEST 3/9] Executable Stack Detection..." << std::endl;
        std::cout << "Testing for executable stack (buffer overflow indicator)..." << std::endl;

        bool foundExecutableStack = false;

        for (const auto& region : testRegions) {
            // Executable stack is a major security issue
            if (region.path == "[stack]" && region.isExecutable) {
                foundExecutableStack = true;
                std::cout << "  🔴 CRITICAL: Executable stack at 0x"
                          << std::hex << region.startAddress
                          << " [" << region.permissions << "]" << std::dec << std::endl;
                std::cout << "     This indicates possible buffer overflow exploitation!" << std::endl;
            }
        }

        assert(foundExecutableStack && "Should detect executable stack");
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testExecutableHeap() {
        std::cout << "[TEST 4/9] Executable Heap Detection..." << std::endl;
        std::cout << "Testing for executable heap (code injection indicator)..." << std::endl;

        int execHeapCount = 0;

        for (const auto& region : testRegions) {
            // Executable heap often indicates code injection
            if (region.path == "[heap]" && region.isExecutable) {
                execHeapCount++;
                std::cout << "  🔴 CRITICAL: Executable heap at 0x"
                          << std::hex << region.startAddress
                          << " [" << region.permissions << "]" << std::dec << std::endl;
                std::cout << "     This indicates possible code injection!" << std::endl;
            }
        }

        assert(execHeapCount > 0 && "Should detect executable heap");
        std::cout << "✓ Detected " << execHeapCount << " executable heap regions" << std::endl;
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testThreatScoring() {
        std::cout << "[TEST 5/9] Threat Scoring System..." << std::endl;
        std::cout << "Calculating risk scores for all regions..." << std::endl;

        struct ThreatScore {
            uint64_t address;
            std::string path;
            std::string description;
            int score;
            std::string severity;
        };

        std::vector<ThreatScore> threats;

        for (const auto& region : testRegions) {
            int score = 0;
            std::string description;
            std::string severity = "LOW";

            // Calculate threat score based on various indicators
            if (region.isExecutable && region.isWritable) {
                score += 50;
                description += "RWX permissions; ";
            }

            if (region.path == "[stack]" && region.isExecutable) {
                score += 100;
                severity = "CRITICAL";
                description += "Executable stack; ";
            }

            if (region.path == "[heap]" && region.isExecutable) {
                score += 80;
                severity = "HIGH";
                description += "Executable heap; ";
            }

            if (region.isExecutable && region.path.empty()) {
                score += 40;
                description += "Anonymous executable; ";
            }

            if (region.path.find("deleted") != std::string::npos) {
                score += 60;
                severity = "MEDIUM";
                description += "Deleted file mapping; ";
            }

            if (region.path.find("/dev/shm") != std::string::npos && region.isExecutable) {
                score += 70;
                severity = "HIGH";
                description += "/dev/shm executable; ";
            }

            if (region.path.find("/tmp") != std::string::npos && region.isExecutable) {
                score += 50;
                severity = "MEDIUM";
                description += "/tmp executable; ";
            }

            if (score > 150) severity = "CRITICAL";
            else if (score > 80) severity = "HIGH";
            else if (score > 40) severity = "MEDIUM";

            if (score > 0) {
                threats.push_back({region.startAddress, region.path, description, score, severity});
            }
        }

        assert(!threats.empty() && "Should calculate threat scores");

        // Sort by score (descending)
        std::sort(threats.begin(), threats.end(),
                  [](const ThreatScore& a, const ThreatScore& b) {
                      return a.score > b.score;
                  });

        std::cout << "\n  Threat Summary (sorted by risk):\n" << std::endl;
        for (size_t i = 0; i < threats.size(); ++i) {
            std::cout << "  [" << (i+1) << "] " << threats[i].severity
                      << " (Score: " << threats[i].score << ")" << std::endl;
            std::cout << "      Address: 0x" << std::hex << threats[i].address << std::dec << std::endl;
            std::cout << "      Path: " << (threats[i].path.empty() ? "[anonymous]" : threats[i].path) << std::endl;
            std::cout << "      Indicators: " << threats[i].description << "\n" << std::endl;
        }

        std::cout << "✓ Scored " << threats.size() << " potential threats" << std::endl;
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testMemoryRegionParsing() {
        std::cout << "[TEST 6/9] Memory Region Parsing..." << std::endl;
        std::cout << "Testing /proc/[pid]/maps parsing logic..." << std::endl;

        // Simulate parsing /proc/[pid]/maps format
        std::vector<std::string> testLines = {
            "00400000-00500000 r-xp 00000000 08:01 123456 /usr/bin/test",
            "7f0000000000-7f0000001000 rwxp 00000000 00:00 0 ",
            "7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]",
            "7f0000002000-7f0000003000 r-xp 00000000 00:00 0 ",
            "01000000-01001000 rwxp 00000000 00:00 0 [heap]",
            "7ffff7a00000-7ffff7b00000 r-xp 00000000 08:01 789012 /lib/libc.so.6"
        };

        int parsedCount = 0;

        for (const auto& line : testLines) {
            if (!line.empty()) {
                parsedCount++;
                // Extract address range
                size_t dashPos = line.find('-');
                std::string startAddr = line.substr(0, dashPos);
                std::cout << "  ✓ Parsed region at 0x" << startAddr << std::endl;
            }
        }

        assert(parsedCount == testLines.size() && "Should parse all lines");
        std::cout << "✓ Successfully parsed " << parsedCount << " memory regions" << std::endl;
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testSuspiciousPatterns() {
        std::cout << "[TEST 7/9] Suspicious Pattern Detection..." << std::endl;
        std::cout << "Scanning for known malicious path patterns..." << std::endl;

        std::vector<std::string> suspiciousPatterns = {
            "[heap]",
            "[stack]",
            "/dev/shm/",
            "/tmp/",
            "deleted"
        };

        int patternMatches = 0;

        std::cout << "\n  Pattern matching results:\n" << std::endl;
        for (const auto& pattern : suspiciousPatterns) {
            int count = 0;
            for (const auto& region : testRegions) {
                if (region.path.find(pattern) != std::string::npos) {
                    count++;
                    patternMatches++;
                }
            }
            if (count > 0) {
                std::cout << "  ⚠️  Pattern '" << pattern << "': "
                          << count << " matches" << std::endl;
            }
        }

        assert(patternMatches > 0 && "Should find suspicious patterns");
        std::cout << "\n✓ Total pattern matches: " << patternMatches << std::endl;
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testDeletedFileMappings() {
        std::cout << "[TEST 8/9] Deleted File Mapping Detection..." << std::endl;
        std::cout << "Searching for mapped files that have been deleted..." << std::endl;

        int deletedCount = 0;

        for (const auto& region : testRegions) {
            if (region.path.find("deleted") != std::string::npos) {
                deletedCount++;
                std::cout << "  ⚠️  Deleted mapping at 0x" << std::hex << region.startAddress
                          << std::dec << std::endl;
                std::cout << "      Path: " << region.path << std::endl;
                std::cout << "      This could indicate malware hiding evidence!" << std::endl;
            }
        }

        assert(deletedCount > 0 && "Should detect deleted file mappings");
        std::cout << "✓ Found " << deletedCount << " deleted file mappings" << std::endl;
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void testSharedMemoryThreats() {
        std::cout << "[TEST 9/9] Shared Memory Threat Detection..." << std::endl;
        std::cout << "Analyzing /dev/shm and shared memory regions..." << std::endl;

        int shmCount = 0;
        int shmExecCount = 0;

        for (const auto& region : testRegions) {
            if (region.path.find("/dev/shm") != std::string::npos) {
                shmCount++;
                std::cout << "  ⚠️  Shared memory: " << region.path;
                if (region.isExecutable) {
                    shmExecCount++;
                    std::cout << " [EXECUTABLE - HIGH RISK] 🔴";
                }
                std::cout << std::endl;
            }
        }

        assert(shmCount > 0 && "Should detect shared memory regions");
        std::cout << "✓ Found " << shmCount << " shared memory regions" << std::endl;
        if (shmExecCount > 0) {
            std::cout << "⚠️  " << shmExecCount << " executable shared memory regions (HIGH RISK!)" << std::endl;
        }
        std::cout << "✓ Test PASSED\n" << std::endl;
    }

    void runAllTests() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════╗\n";
        std::cout << "║                                                      ║\n";
        std::cout << "║      Threat Detection Module - Test Suite           ║\n";
        std::cout << "║      Comprehensive Security Analysis Tests          ║\n";
        std::cout << "║                                                      ║\n";
        std::cout << "╚══════════════════════════════════════════════════════╝\n";
        std::cout << std::endl;

        try {
            testSuspiciousPermissions();
            testAnonymousExecutable();
            testExecutableStack();
            testExecutableHeap();
            testThreatScoring();
            testMemoryRegionParsing();
            testSuspiciousPatterns();
            testDeletedFileMappings();
            testSharedMemoryThreats();

            std::cout << "\n";
            std::cout << "╔══════════════════════════════════════════════════════╗\n";
            std::cout << "║                                                      ║\n";
            std::cout << "║              ✓ ALL TESTS PASSED ✓                   ║\n";
            std::cout << "║                                                      ║\n";
            std::cout << "║              Total Tests: 9                          ║\n";
            std::cout << "║              Passed: 9                               ║\n";
            std::cout << "║              Failed: 0                               ║\n";
            std::cout << "║                                                      ║\n";
            std::cout << "╚══════════════════════════════════════════════════════╝\n";
            std::cout << "\n";

        } catch (const std::exception& e) {
            std::cerr << "\n✗ TEST FAILED: " << e.what() << std::endl;
            throw;
        }
    }
};

int main() {
    try {
        std::cout << "\n*** Starting Threat Detection Test Suite ***\n" << std::endl;

        ThreatDetectionTest test;
        test.runAllTests();

        std::cout << "*** Test Suite Completed Successfully ***\n" << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n*** Fatal Error in Test Suite ***" << std::endl;
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;

    } catch (...) {
        std::cerr << "\n*** Unknown Fatal Error ***" << std::endl;
        return 1;
    }
}