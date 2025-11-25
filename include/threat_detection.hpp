#ifndef THREAT_DETECTION_H
#define THREAT_DETECTION_H

#include <vector>
#include <string>
#include <ctime>
#include "memory_scan.hpp"

// Forward declarations if needed
// struct MemoryRegion;
// struct ScanResult;

enum ThreatLevel {
    SAFE = 0,
    SUSPICIOUS = 1,
    DANGEROUS = 2
};

struct ThreatIndicator {
    std::string name;
    ThreatLevel level;
    std::string description;
    std::string affectedRegion;
    std::time_t detectionTime;

    // Constructor for easier initialization
    ThreatIndicator(const std::string& n, ThreatLevel lvl,
                   const std::string& desc, const std::string& region)
        : name(n), level(lvl), description(desc),
          affectedRegion(region), detectionTime(std::time(nullptr)) {}
};

class ThreatDetection {
private:
    std::vector<ThreatIndicator> detectedThreats;

    // Pattern lists - these should match YARA rule names/signatures
    const std::vector<std::string> SUSPICIOUS_PATTERNS = {
        "rwx",          // Read-Write-Execute memory
        "heap",         // Heap anomalies
        "stack",        // Stack anomalies
        "anonymous",    // Anonymous mappings
        "packed",       // Packed executables
        "suspicious_api" // Suspicious API usage
    };

    const std::vector<std::string> DANGEROUS_PATTERNS = {
        "shellcode",    // Shellcode signatures
        "inject",       // Code injection
        "malware",      // Known malware signatures
        "exploit",      // Exploit patterns
        "ransomware",   // Ransomware indicators
        "trojan"        // Trojan signatures
    };

    // Helper methods
    bool checkSuspiciousPatterns(const MemoryRegion& region);
    bool checkDangerousPatterns(const MemoryRegion& region);
    void evaluateRegion(const MemoryRegion& region);

    // Pattern matching helper (for YARA-like functionality)
    bool matchesPattern(const std::string& data, const std::string& pattern) const;

public:
    ThreatDetection();
    ~ThreatDetection();

    // Analysis functions
    ThreatLevel analyzeScanResults(const ScanResult& scanResult);
    void analyzeRegion(const MemoryRegion& region);

    // YARA-specific integration
    bool loadYaraRules(const std::string& rulesPath);
    void scanWithYara(const MemoryRegion& region);

    // Getters
    std::vector<ThreatIndicator> getThreats() const;
    ThreatLevel getOverallThreatLevel() const;
    int getThreatCount() const;
    ThreatIndicator* getThreatByIndex(size_t index);

    // Filtering
    std::vector<ThreatIndicator> getThreatsByLevel(ThreatLevel level) const;

    // Display functions
    void displayThreats() const;
    void displaySummary() const;
    void displayThreatDetails(const ThreatIndicator& threat) const;

    // Utility
    void clearThreats();
    bool hasThreats() const;
    void addThreat(const ThreatIndicator& threat);

    // Export/Report
    void exportToJson(const std::string& filename) const;
    std::string generateReport() const;
};

#endif // THREAT_DETECTION_H