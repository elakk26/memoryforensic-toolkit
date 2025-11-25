#include "../include/threat_detection.hpp"
#include <iostream>
#include <algorithm>
#include <iomanip>

ThreatDetection::ThreatDetection() {
}

ThreatDetection::~ThreatDetection() {
    clearThreats();
}

ThreatLevel ThreatDetection::analyzeScanResults(const ScanResult& scanResult) {
    clearThreats();

    ThreatLevel maxThreatLevel = SAFE;

    std::cout << "\n=== Analyzing " << scanResult.totalRegions
              << " memory regions ===" << std::endl;

    // Pattern-based detection only (no YARA)
    for (const auto& region : scanResult.regions) {
        evaluateRegion(region);
    }

    // Determine overall threat level
    for (const auto& threat : detectedThreats) {
        if (threat.level > maxThreatLevel) {
            maxThreatLevel = threat.level;
        }
    }

    std::cout << "Analysis complete. Found " << detectedThreats.size()
              << " potential threats." << std::endl;

    return maxThreatLevel;
}

bool ThreatDetection::checkSuspiciousPatterns(const MemoryRegion& region) {
    for (const auto& pattern : SUSPICIOUS_PATTERNS) {
        if (region.module.find(pattern) != std::string::npos ||
            region.address.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

bool ThreatDetection::checkDangerousPatterns(const MemoryRegion& region) {
    for (const auto& pattern : DANGEROUS_PATTERNS) {
        if (region.permissions.find(pattern) != std::string::npos ||
            region.module.find(pattern) != std::string::npos) {
            return true;
        }
    }
    return false;
}

void ThreatDetection::evaluateRegion(const MemoryRegion& region) {
    ThreatIndicator threat;
    threat.affectedRegion = region.address + " - " + region.module;
    threat.detectionTime = std::time(nullptr);

    // Check for dangerous patterns first
    if (checkDangerousPatterns(region)) {
        threat.name = "Dangerous Memory Configuration";
        threat.level = DANGEROUS;
        threat.description = "Memory region has Read-Write-Execute permissions";
        detectedThreats.push_back(threat);
    }
}

std::vector<ThreatIndicator> ThreatDetection::getThreats() const {
    return detectedThreats;
}

ThreatLevel ThreatDetection::getThreatLevel() const {
    ThreatLevel maxLevel = SAFE;
    for (const auto& threat : detectedThreats) {
        if (threat.level > maxLevel) {
            maxLevel = threat.level;
        }
    }
    return maxLevel;
}

int ThreatDetection::getThreatCount() const {
    return detectedThreats.size();
}

void ThreatDetection::displayThreats() const {
    std::cout << "\n=== Detected Threats ===" << std::endl;
    std::cout << "Total threats found: " << detectedThreats.size() << std::endl;

    int dangerous = 0, suspicious = 0, safe = 0;

    for (const auto& threat : detectedThreats) {
        switch (threat.level) {
            case DANGEROUS: dangerous++; break;
            case SUSPICIOUS: suspicious++; break;
            case SAFE: safe++; break;
        }
    }

    std::cout << "\nThreat Level Breakdown:" << std::endl;
    std::cout << "  DANGEROUS:  " << dangerous << std::endl;
    std::cout << "  SUSPICIOUS: " << suspicious << std::endl;
    std::cout << "  SAFE:       " << safe << std::endl;

    if (detectedThreats.empty()) {
        std::cout << "\nNo threats detected." << std::endl;
        return;
    }

    std::cout << "\nDetailed Threats:" << std::endl;
    for (size_t i = 0; i < detectedThreats.size(); ++i) {
        const auto& threat = detectedThreats[i];
        std::cout << "\n[" << (i + 1) << "] " << threat.name << std::endl;
        std::cout << "    Level: ";

        switch (threat.level) {
            case DANGEROUS:
                std::cout << "DANGEROUS";
                break;
            case SUSPICIOUS:
                std::cout << "SUSPICIOUS";
                break;
            case SAFE:
                std::cout << "SAFE";
                break;
        }

        std::cout << std::endl;
        std::cout << "    Description: " << threat.description << std::endl;
        std::cout << "    Affected Region: " << threat.affectedRegion << std::endl;

        auto tm = *std::localtime(&threat.detectionTime);
        std::cout << "    Detection Time: " << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << std::endl;
    }
}

void ThreatDetection::displaySummary() const {
    std::cout << "\n=== Threat Analysis Summary ===" << std::endl;

    ThreatLevel overall = getThreatLevel();
    std::cout << "Overall Threat Level: ";

    switch (overall) {
        case DANGEROUS:
            std::cout << "DANGEROUS - Immediate action required!" << std::endl;
            break;
        case SUSPICIOUS:
            std::cout << "SUSPICIOUS - Further investigation recommended" << std::endl;
            break;
        case SAFE:
            std::cout << "SAFE - No significant threats detected" << std::endl;
            break;
    }

    std::cout << "Total Threats: " << getThreatCount() << std::endl;
}

void ThreatDetection::clearThreats() {
    detectedThreats.clear();
}Memory region has dangerous characteristics: " +
                           region.permissions;
        detectedThreats.push_back(threat);
        return;
    }

    // Check for suspicious patterns
    if (checkSuspiciousPatterns(region)) {
        threat.name = "Suspicious Memory Pattern";
        threat.level = SUSPICIOUS;
        threat.description = "Memory region contains suspicious patterns in module: " +
                           region.module;
        detectedThreats.push_back(threat);
        return;
    }

    // Additional checks for RWX permissions
    if (region.permissions.find("r") != std::string::npos &&
        region.permissions.find("w") != std::string::npos &&
        region.permissions.find("x") != std::string::npos) {
        threat.name = "RWX Memory Region";
        threat.level = SUSPICIOUS;
        threat.description = "