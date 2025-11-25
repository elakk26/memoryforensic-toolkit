#include "yara_detection.h"
#include <yara.h>
#include <iostream>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <cstring>

YaraDetection::YaraDetection() 
    : compiledRules(nullptr), compiler(nullptr), initialized(false) {
}

YaraDetection::~YaraDetection() {
    cleanup();
}

bool YaraDetection::initialize() {
    if (initialized) {
        return true;
    }
    
    int result = yr_initialize();
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to initialize YARA library" << std::endl;
        return false;
    }
    
    result = yr_compiler_create(&compiler);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to create YARA compiler" << std::endl;
        yr_finalize();
        return false;
    }
    
    initialized = true;
    std::cout << "YARA detection engine initialized successfully" << std::endl;
    return true;
}

void YaraDetection::cleanup() {
    if (compiledRules) {
        yr_rules_destroy(compiledRules);
        compiledRules = nullptr;
    }
    
    if (compiler) {
        yr_compiler_destroy(compiler);
        compiler = nullptr;
    }
    
    if (initialized) {
        yr_finalize();
        initialized = false;
    }
    
    detectedMatches.clear();
    loadedRuleFiles.clear();
}

bool YaraDetection::compileRuleFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        std::cerr << "Cannot open rule file: " << filepath << std::endl;
        return false;
    }
    
    FILE* ruleFile = fopen(filepath.c_str(), "r");
    if (!ruleFile) {
        std::cerr << "Failed to open: " << filepath << std::endl;
        return false;
    }
    
    int errors = yr_compiler_add_file(compiler, ruleFile, nullptr, filepath.c_str());
    fclose(ruleFile);
    
    if (errors > 0) {
        std::cerr << "Compilation errors in: " << filepath << std::endl;
        return false;
    }
    
    std::cout << "Successfully compiled: " << filepath << std::endl;
    return true;
}

bool YaraDetection::loadRulesFromDirectory(const std::string& directory) {
    if (!initialized) {
        std::cerr << "YARA not initialized" << std::endl;
        return false;
    }
    
    DIR* dir = opendir(directory.c_str());
    if (!dir) {
        std::cerr << "Cannot open rules directory: " << directory << std::endl;
        return false;
    }
    
    struct dirent* entry;
    int rulesLoaded = 0;
    
    while ((entry = readdir(dir)) != nullptr) {
        std::string filename = entry->d_name;
        
        if (filename.length() > 4 && filename.substr(filename.length() - 4) == ".yar") {
            std::string fullPath = directory + "/" + filename;
            
            if (compileRuleFile(fullPath)) {
                YaraRuleFile ruleFile;
                ruleFile.filename = filename;
                ruleFile.category = filename.substr(0, filename.length() - 4);
                ruleFile.isLoaded = true;
                loadedRuleFiles.push_back(ruleFile);
                rulesLoaded++;
            }
        }
    }
    closedir(dir);
    
    return compileAllRules();
}

bool YaraDetection::compileAllRules() {
    if (compiledRules) {
        yr_rules_destroy(compiledRules);
        compiledRules = nullptr;
    }
    
    int result = yr_compiler_get_rules(compiler, &compiledRules);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Failed to get compiled rules" << std::endl;
        return false;
    }
    
    std::cout << "All rules compiled successfully. Loaded " 
              << loadedRuleFiles.size() << " rule files" << std::endl;
    return true;
}

int YaraDetection::yaraCallbackFunction(int message, void* messageData, void* userData) {
    YaraDetection* detector = static_cast<YaraDetection*>(userData);
    
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        YR_RULE* rule = static_cast<YR_RULE*>(messageData);
        
        YaraMatch match;
        match.ruleName = rule->identifier;
        match.ruleNamespace = rule->ns ? rule->ns->name : "default";
        match.matchedString = "";
        match.offset = 0;
        
        // Determine severity based on rule name patterns
        std::string ruleLower = match.ruleName;
        std::transform(ruleLower.begin(), ruleLower.end(), ruleLower.begin(), ::tolower);
        
        if (ruleLower.find("malware") != std::string::npos || 
            ruleLower.find("exploit") != std::string::npos) {
            match.severity = DANGEROUS;
        } else if (ruleLower.find("suspicious") != std::string::npos) {
            match.severity = SUSPICIOUS;
        } else {
            match.severity = SAFE;
        }
        
        match.description = "YARA rule match: " + match.ruleName;
        detector->detectedMatches.push_back(match);
    }
    
    return CALLBACK_CONTINUE;
}

bool YaraDetection::scanMemoryRegion(const MemoryRegion& region) {
    if (!compiledRules) {
        std::cerr << "No rules loaded for scanning" << std::endl;
        return false;
    }
    
    // Open memory region for scanning
    std::string memPath = "/proc/self/mem";
    
    YR_SCANNER* scanner = nullptr;
    int result = yr_scanner_create(compiledRules, &scanner);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    yr_scanner_set_callback(scanner, yaraCallbackFunction, this);
    
    // Scan the region
    result = yr_scanner_scan_mem(scanner, 
                                 (uint8_t*)std::stol(region.address, nullptr, 16),
                                 std::stol(region.size, nullptr, 16));
    
    yr_scanner_destroy(scanner);
    
    return result == ERROR_SUCCESS;
}

bool YaraDetection::scanProcessMemory(int pid) {
    if (!compiledRules) {
        std::cerr << "No rules loaded" << std::endl;
        return false;
    }
    
    YR_SCANNER* scanner = nullptr;
    int result = yr_scanner_create(compiledRules, &scanner);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    yr_scanner_set_callback(scanner, yaraCallbackFunction, this);
    
    std::string procPath = "/proc/" + std::to_string(pid) + "/mem";
    result = yr_scanner_scan_proc(scanner, pid);
    
    yr_scanner_destroy(scanner);
    
    return result == ERROR_SUCCESS;
}

bool YaraDetection::scanBuffer(const uint8_t* buffer, size_t size, const std::string& identifier) {
    if (!compiledRules || !buffer) {
        return false;
    }
    
    YR_SCANNER* scanner = nullptr;
    int result = yr_scanner_create(compiledRules, &scanner);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    
    yr_scanner_set_callback(scanner, yaraCallbackFunction, this);
    result = yr_scanner_scan_mem(scanner, buffer, size);
    
    yr_scanner_destroy(scanner);
    
    return result == ERROR_SUCCESS;
}

std::vector<ThreatIndicator> YaraDetection::convertMatchesToThreats() const {
    std::vector<ThreatIndicator> threats;
    
    for (const auto& match : detectedMatches) {
        ThreatIndicator threat;
        threat.name = match.ruleName;
        threat.level = match.severity;
        threat.description = match.description + " in namespace: " + match.ruleNamespace;
        threat.affectedRegion = "Offset: " + std::to_string(match.offset);
        threat.detectionTime = std::time(nullptr);
        threats.push_back(threat);
    }
    
    return threats;
}

ThreatLevel YaraDetection::evaluateOverallThreat() const {
    ThreatLevel maxLevel = SAFE;
    
    for (const auto& match : detectedMatches) {
        if (match.severity > maxLevel) {
            maxLevel = match.severity;
        }
    }
    
    return maxLevel;
}

std::vector<YaraMatch> YaraDetection::getMatches() const {
    return detectedMatches;
}

std::vector<YaraRuleFile> YaraDetection::getLoadedRules() const {
    return loadedRuleFiles;
}

int YaraDetection::getMatchCount() const {
    return detectedMatches.size();
}

bool YaraDetection::isInitialized() const {
    return initialized;
}

void YaraDetection::displayMatches() const {
    std::cout << "\n=== YARA Detection Results ===" << std::endl;
    std::cout << "Total matches: " << detectedMatches.size() << std::endl;
    
    for (const auto& match : detectedMatches) {
        std::cout << "\n[" << match.ruleNamespace << "] " << match.ruleName << std::endl;
        std::cout << "  Severity: " << match.severity << std::endl;
        std::cout << "  Description: " << match.description << std::endl;
        std::cout << "  Offset: 0x" << std::hex << match.offset << std::dec << std::endl;
    }
}

void YaraDetection::displayRuleStats() const {
    std::cout << "\n=== Loaded YARA Rules ===" << std::endl;
    std::cout << "Total rule files: " << loadedRuleFiles.size() << std::endl;
    
    for (const auto& ruleFile : loadedRuleFiles) {
        std::cout << "  [" << (ruleFile.isLoaded ? "✓" : "✗") << "] " 
                  << ruleFile.filename << " (" << ruleFile.category << ")" << std::endl;
    }
}

void YaraDetection::clearMatches() {
    detectedMatches.clear();
}