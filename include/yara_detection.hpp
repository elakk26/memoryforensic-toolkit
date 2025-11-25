#ifndef YARA_DETECTION_H
#define YARA_DETECTION_H

#include <memory>
#include <string>
#include <vector>
#include "memory_scan.hpp"
#include "../include/threat_detection.h"

// Forward declaration for YARA structures
typedef struct _YR_COMPILER YR_COMPILER;
typedef struct _YR_RULES YR_RULES;
typedef struct _YR_SCANNER YR_SCANNER;

struct YaraMatch {
    std::string ruleName;
    std::string ruleNamespace;
    std::string matchedString;
    size_t offset;
    ThreatLevel severity;
    std::string description;
};

struct YaraRuleFile {
    std::string filename;
    std::string category;
    bool isLoaded;
};

class YaraDetection {
private:
    YR_RULES* compiledRules;
    YR_COMPILER* compiler;
    std::vector<YaraMatch> detectedMatches;
    std::vector<YaraRuleFile> loadedRuleFiles;
    bool initialized;

    // Rule file paths
    const std::string RULES_DIR = "rules/";

    // Callback functions for YARA
    static int yaraCallbackFunction(int message, void* messageData, void* userData);

    // Internal helper methods
    bool compileRuleFile(const std::string& filepath);
    bool compileAllRules();
    void processYaraMatch(const std::string& ruleName,
                         const std::string& ns,
                         const std::string& matchStr,
                         size_t offset);

public:
    YaraDetection();
    ~YaraDetection();

    // Initialization
    bool initialize();
    void cleanup();

    // Rule management
    bool loadRulesFromDirectory(const std::string& directory);
    bool loadSingleRule(const std::string& filepath, const std::string& category);
    bool reloadRules();

    // Scanning functions
    bool scanMemoryRegion(const MemoryRegion& region);
    bool scanProcessMemory(int pid);
    bool scanBuffer(const uint8_t* buffer, size_t size, const std::string& identifier);

    // Analysis integration
    std::vector<ThreatIndicator> convertMatchesToThreats() const;
    ThreatLevel evaluateOverallThreat() const;

    // Getters
    std::vector<YaraMatch> getMatches() const;
    std::vector<YaraRuleFile> getLoadedRules() const;
    int getMatchCount() const;
    bool isInitialized() const;

    // Display and reporting
    void displayMatches() const;
    void displayRuleStats() const;

    // Clear results
    void clearMatches();
};

#endif // YARA_DETECTION_H