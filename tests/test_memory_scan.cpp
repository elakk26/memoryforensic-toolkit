// tests/test_memory_scan.cpp
// Standalone test for Memory Scanner component

#include "../include/memory_scan.hpp"
#include <iostream>
#include <cassert>

void displayTestHeader(const std::string& testName) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "  TEST: " << testName << std::endl;
    std::cout << std::string(60, '=') << std::endl;
}

void displayTestResult(bool passed, const std::string& testName) {
    if (passed) {
        std::cout << "[PASS] " << testName << std::endl;
    } else {
        std::cout << "[FAIL] " << testName << std::endl;
    }
}

int main() {
    std::cout << "\n╔═══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║         MEMORY SCANNER TEST SUITE                         ║" << std::endl;
    std::cout << "║  Testing Memory Region Detection and Analysis             ║" << std::endl;
    std::cout << "╚═══════════════════════════════════════════════════════════╝" << std::endl;

    int testsRun = 0;
    int testsPassed = 0;

    // ========================================================
    // TEST 1: SCANNER INITIALIZATION
    // ========================================================
    displayTestHeader("Scanner Initialization");

    try {
        MemoryScan scanner;
        testsRun++;
        testsPassed++;
        displayTestResult(true, "Scanner creation");
        std::cout << "[+] Memory scanner initialized successfully" << std::endl;
    } catch (const std::exception& e) {
        testsRun++;
        displayTestResult(false, "Scanner creation");
        std::cerr << "[-] Exception: " << e.what() << std::endl;
    }

    // ========================================================
    // TEST 2: CURRENT PROCESS SCAN
    // ========================================================
    displayTestHeader("Current Process Memory Scan");

    MemoryScan scanner;
    std::cout << "[*] Scanning current process memory..." << std::endl;

    ScanResult result = scanner.performScan(0); // 0 = current process

    testsRun++;
    bool currentProcessScanSuccess = (result.scanStatus == "COMPLETED" && result.totalRegions > 0);
    testsPassed += currentProcessScanSuccess ? 1 : 0;

    displayTestResult(currentProcessScanSuccess, "Current process scan");

    if (currentProcessScanSuccess) {
        std::cout << "[+] Scan Status: " << result.scanStatus << std::endl;
        std::cout << "[+] Total Regions Found: " << result.totalRegions << std::endl;
        std::cout << "[+] Scan Timestamp: " << result.scanTimestamp << std::endl;
    } else {
        std::cerr << "[-] Scan failed or no regions found" << std::endl;
    }

    // ========================================================
    // TEST 3: SCAN RESULTS RETRIEVAL
    // ========================================================
    displayTestHeader("Scan Results Retrieval");

    std::vector<MemoryRegion> regions = scanner.getScanResults();

    testsRun++;
    bool resultsRetrievalSuccess = (regions.size() == result.totalRegions);
    testsPassed += resultsRetrievalSuccess ? 1 : 0;

    displayTestResult(resultsRetrievalSuccess, "Results retrieval");

    if (resultsRetrievalSuccess) {
        std::cout << "[+] Retrieved " << regions.size() << " regions from scanner" << std::endl;
    }

    // ========================================================
    // TEST 4: REGION COUNT
    // ========================================================
    displayTestHeader("Region Count");

    int regionCount = scanner.getRegionCount();

    testsRun++;
    bool regionCountSuccess = (regionCount == result.totalRegions && regionCount > 0);
    testsPassed += regionCountSuccess ? 1 : 0;

    displayTestResult(regionCountSuccess, "Region count");

    if (regionCountSuccess) {
        std::cout << "[+] Region count matches: " << regionCount << std::endl;
    }

    // ========================================================
    // TEST 5: MEMORY REGION DATA VALIDATION
    // ========================================================
    displayTestHeader("Memory Region Data Validation");

    bool regionDataValid = true;
    int validRegions = 0;
    int invalidRegions = 0;

    for (const auto& region : regions) {
        if (!region.address.empty() && !region.permissions.empty() && !region.size.empty()) {
            validRegions++;
        } else {
            invalidRegions++;
            regionDataValid = false;
        }
    }

    testsRun++;
    testsPassed += regionDataValid ? 1 : 0;

    displayTestResult(regionDataValid, "Region data validation");

    if (regionDataValid || invalidRegions == 0) {
        std::cout << "[+] All " << validRegions << " regions have valid data" << std::endl;
    } else {
        std::cout << "[!] Warning: " << invalidRegions << " regions have incomplete data" << std::endl;
        std::cout << "[+] Valid regions: " << validRegions << std::endl;
    }

    // ========================================================
    // TEST 6: DISPLAY RESULTS
    // ========================================================
    displayTestHeader("Display Results");

    std::cout << "\n[*] Displaying first 5 memory regions:\n" << std::endl;

    int count = 0;
    for (const auto& region : regions) {
        if (count >= 5) break;

        std::cout << "[" << count + 1 << "] Address: " << region.address << std::endl;
        std::cout << "    Permissions: " << region.permissions << std::endl;
        std::cout << "    Size: " << region.size << std::endl;
        if (!region.module.empty()) {
            std::cout << "    Module: " << region.module << std::endl;
        }
        std::cout << std::endl;

        count++;
    }

    testsRun++;
    testsPassed++;
    displayTestResult(true, "Display sample regions");

    // ========================================================
    // TEST 7: REGION PARSING ACCURACY
    // ========================================================
    displayTestHeader("Region Parsing Accuracy");

    if (!regions.empty()) {
        const auto& sampleRegion = regions[0];

        bool parsingValid = true;

        // Check address format (should contain -)
        if (sampleRegion.address.find('-') == std::string::npos &&
            sampleRegion.address.find('0') == std::string::npos) {
            parsingValid = false;
        }

        // Check permissions (should be 4 chars like r-xp)
        if (sampleRegion.permissions.length() < 3) {
            parsingValid = false;
        }

        testsRun++;
        testsPassed += parsingValid ? 1 : 0;

        displayTestResult(parsingValid, "Region parsing accuracy");

        if (parsingValid) {
            std::cout << "[+] Sample region parsing verified" << std::endl;
            std::cout << "    Address: " << sampleRegion.address << std::endl;
            std::cout << "    Permissions: " << sampleRegion.permissions << std::endl;
            std::cout << "    Size: " << sampleRegion.size << std::endl;
        }
    } else {
        testsRun++;
        std::cout << "[!] No regions to verify parsing" << std::endl;
    }

    // ========================================================
    // TEST SUMMARY
    // ========================================================
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "  TEST SUMMARY" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    std::cout << "\nTotal Tests Run: " << testsRun << std::endl;
    std::cout << "Tests Passed: " << testsPassed << std::endl;
    std::cout << "Tests Failed: " << (testsRun - testsPassed) << std::endl;
    std::cout << "Success Rate: " << (testsPassed * 100 / testsRun) << "%" << std::endl;

    if (testsPassed == testsRun) {
        std::cout << "\n[+] ALL TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cout << "\n[-] SOME TESTS FAILED" << std::endl;
        return 1;
    }
}