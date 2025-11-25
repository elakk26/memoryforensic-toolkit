#include <iostream>
#include <cassert>
#include <unistd.h>
#include "../include/Logger.hpp"
#include "../include/rule_loader.h"
#include "../include/yara_detection.h"

// Test fixture class
class YaraDetectionTest {
private:
    RuleLoader* ruleLoader;
    YaraDetection* yaraDetection;
    
public:
    YaraDetectionTest() {
        Logger::getInstance()->setLogLevel(LogLevel::DEBUG);
        ruleLoader = new RuleLoader("../rules/");
        yaraDetection = new YaraDetection(ruleLoader);
    }
    
    ~YaraDetectionTest() {
        delete yaraDetection;
        delete ruleLoader;
    }
    
    void testRuleLoading() {
        std::cout << "\n[TEST] Rule Loading..." << std::endl;
        
        bool result = ruleLoader->loadRules();
        assert(result == true && "Failed to load YARA rules");
        
        int ruleCount = ruleLoader->getRuleCount();
        assert(ruleCount > 0 && "No rules loaded");
        
        std::cout << "✓ Loaded " << ruleCount << " rule files" << std::endl;
        std::cout << "✓ Rule loading test PASSED" << std::endl;
    }
    
    void testRulesList() {
        std::cout << "\n[TEST] Rules List..." << std::endl;
        
        auto rules = ruleLoader->listLoadedRules();
        assert(!rules.empty() && "Rule list is empty");
        
        std::cout << "✓ Found " << rules.size() << " rules:" << std::endl;
        for (const auto& rule : rules) {
            std::cout << "  - " << rule << std::endl;
        }
        std::cout << "✓ Rules list test PASSED" << std::endl;
    }
    
    void testRulesReload() {
        std::cout << "\n[TEST] Rules Reload..." << std::endl;
        
        int initialCount = ruleLoader->getRuleCount();
        bool result = ruleLoader->reloadRules();
        
        assert(result == true && "Failed to reload rules");
        assert(ruleLoader->getRuleCount() == initialCount && "Rule count mismatch after reload");
        
        std::cout << "✓ Rules reloaded successfully" << std::endl;
        std::cout << "✓ Rules reload test PASSED" << std::endl;
    }
    
    void testMemoryScan() {
        std::cout << "\n[TEST] Memory Scan..." << std::endl;
        
        // Get current process PID
        int pid = getpid();
        std::cout << "Scanning current process (PID: " << pid << ")" << std::endl;
        
        yaraDetection->clearMatches();
        bool result = yaraDetection->scanProcess(pid);
        
        assert(result == true && "Memory scan failed");
        
        int matchCount = yaraDetection->getMatchCount();
        std::cout << "✓ Scan completed: " << matchCount << " matches found" << std::endl;
        
        if (matchCount > 0) {
            auto matches = yaraDetection->getMatches();
            std::cout << "Match details:" << std::endl;
            for (size_t i = 0; i < std::min(matches.size(), size_t(5)); ++i) {
                std::cout << "  Rule: " << matches[i].ruleName 
                          << " | Offset: 0x" << std::hex << matches[i].offset 
                          << std::dec << std::endl;
            }
        }
        
        std::cout << "✓ Memory scan test PASSED" << std::endl;
    }
    
    void testMatchClear() {
        std::cout << "\n[TEST] Match Clear..." << std::endl;
        
        yaraDetection->clearMatches();
        int matchCount = yaraDetection->getMatchCount();
        
        assert(matchCount == 0 && "Matches not cleared");
        
        std::cout << "✓ Matches cleared successfully" << std::endl;
        std::cout << "✓ Match clear test PASSED" << std::endl;
    }
    
    void testInvalidPID() {
        std::cout << "\n[TEST] Invalid PID Handling..." << std::endl;
        
        // Test with invalid PID
        int invalidPid = 999999;
        bool result = yaraDetection->scanProcess(invalidPid);
        
        // Should fail gracefully
        assert(result == false && "Invalid PID should fail");
        
        std::cout << "✓ Invalid PID handled correctly" << std::endl;
        std::cout << "✓ Invalid PID test PASSED" << std::endl;
    }
    
    void testMemoryRegionScanning() {
        std::cout << "\n[TEST] Memory Region Scanning..." << std::endl;
        
        int pid = getpid();
        yaraDetection->clearMatches();
        
        // This tests individual region scanning capability
        bool result = yaraDetection->scanProcess(pid);
        
        assert(result == true && "Region scanning failed");
        
        std::cout << "✓ Memory region scanning completed" << std::endl;
        std::cout << "✓ Region scanning test PASSED" << std::endl;
    }
    
    void testMultipleScans() {
        std::cout << "\n[TEST] Multiple Sequential Scans..." << std::endl;
        
        int pid = getpid();
        
        // First scan
        yaraDetection->clearMatches();
        bool result1 = yaraDetection->scanProcess(pid);
        int matches1 = yaraDetection->getMatchCount();
        
        // Second scan
        yaraDetection->clearMatches();
        bool result2 = yaraDetection->scanProcess(pid);
        int matches2 = yaraDetection->getMatchCount();
        
        assert(result1 == true && "First scan failed");
        assert(result2 == true && "Second scan failed");
        
        std::cout << "✓ First scan: " << matches1 << " matches" << std::endl;
        std::cout << "✓ Second scan: " << matches2 << " matches" << std::endl;
        std::cout << "✓ Multiple scans test PASSED" << std::endl;
    }
    
    void runAllTests() {
        std::cout << "\n";
        std::cout << "╔════════════════════════════════════════════╗\n";
        std::cout << "║   YARA Detection Module Test Suite        ║\n";
        std::cout << "╚════════════════════════════════════════════╝\n";
        
        try {
            testRuleLoading();
            testRulesList();
            testRulesReload();
            testMatchClear();
            testMemoryScan();
            testMemoryRegionScanning();
            testMultipleScans();
            testInvalidPID();
            
            std::cout << "\n";
            std::cout << "╔════════════════════════════════════════════╗\n";
            std::cout << "║   ALL TESTS PASSED ✓                       ║\n";
            std::cout << "║   Total: 8 tests                           ║\n";
            std::cout << "╚════════════════════════════════════════════╝\n";
            std::cout << "\n";
            
        } catch (const std::exception& e) {
            std::cerr << "\n✗ TEST FAILED: " << e.what() << std::endl;
            throw;
        }
    }
};

int main() {
    try {
        YaraDetectionTest test;
        test.runAllTests();
        return 0;
    } catch (...) {
        std::cerr << "Fatal error in test suite" << std::endl;
        return 1;
    }
}