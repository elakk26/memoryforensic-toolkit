#include "../include/monitoring.hpp"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

BehavioralMonitoring::BehavioralMonitoring()
    : isMonitoring(false), monitoringIntervalSeconds(5) {
}

BehavioralMonitoring::~BehavioralMonitoring() {
    stopMonitoring();
}

void BehavioralMonitoring::startMonitoring(int intervalSeconds) {
    if (isMonitoring) {
        std::cout << "Monitoring is already active" << std::endl;
        return;
    }

    monitoringIntervalSeconds = intervalSeconds;
    isMonitoring = true;

    logEvent("MONITORING_START", "Behavioral monitoring started", SAFE);

    std::cout << "Behavioral monitoring started with "
              << intervalSeconds << " second interval" << std::endl;
}

void BehavioralMonitoring::stopMonitoring() {
    if (!isMonitoring) {
        return;
    }

    isMonitoring = false;
    logEvent("MONITORING_STOP", "Behavioral monitoring stopped", SAFE);

    std::cout << "Behavioral monitoring stopped" << std::endl;
}

void BehavioralMonitoring::logEvent(const std::string& eventType,
                                    const std::string& description,
                                    ThreatLevel severity,
                                    const std::string& processInfo) {
    MonitoringEvent event;
    event.eventType = eventType;
    event.description = description;
    event.severity = severity;
    event.timestamp = std::time(nullptr);
    event.processInfo = processInfo;

    eventLog.push_back(event);
}

void BehavioralMonitoring::analyzeThreats(const std::vector<ThreatIndicator>& threats) {
    for (const auto& threat : threats) {
        std::string description = "Threat detected: " + threat.name + " - " + threat.description;
        logEvent("THREAT_DETECTED", description, threat.level, threat.affectedRegion);

        if (threat.level >= DANGEROUS) {
            generateAlert(threat);
        }
    }
}

void BehavioralMonitoring::generateAlert(const ThreatIndicator& threat) {
    std::cout << "\n!!! SECURITY ALERT !!!" << std::endl;
    std::cout << "Threat: " << threat.name << std::endl;
    std::cout << "Level: ";

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
    std::cout << "Description: " << threat.description << std::endl;
    std::cout << "Region: " << threat.affectedRegion << std::endl;
    std::cout << "!!!!!!!!!!!!!!!!!!!!!" << std::endl << std::endl;

    logEvent("ALERT_GENERATED", "Security alert for: " + threat.name, threat.level);
}

std::vector<MonitoringEvent> BehavioralMonitoring::getEventLog() const {
    return eventLog;
}

bool BehavioralMonitoring::isCurrentlyMonitoring() const {
    return isMonitoring;
}

int BehavioralMonitoring::getEventCount() const {
    return eventLog.size();
}

void BehavioralMonitoring::displayEventLog() const {
    std::cout << "\n=== Event Log ===" << std::endl;
    std::cout << "Total Events: " << eventLog.size() << std::endl;

    if (eventLog.empty()) {
        std::cout << "No events logged yet." << std::endl;
        return;
    }

    std::cout << "\n" << std::left;
    std::cout << std::setw(20) << "Timestamp"
              << std::setw(20) << "Event Type"
              << std::setw(12) << "Severity"
              << "Description" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    for (const auto& event : eventLog) {
        auto tm = *std::localtime(&event.timestamp);
        std::cout << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "  ";

        std::cout << std::left << std::setw(20) << event.eventType;

        std::string severityStr;
        switch (event.severity) {
            case DANGEROUS: severityStr = "DANGEROUS"; break;
            case SUSPICIOUS: severityStr = "SUSPICIOUS"; break;
            case SAFE: severityStr = "SAFE"; break;
        }
        std::cout << std::setw(12) << severityStr;

        std::cout << event.description << std::endl;

        if (!event.processInfo.empty()) {
            std::cout << std::string(52, ' ') << "Process: " << event.processInfo << std::endl;
        }
    }
}

void BehavioralMonitoring::displayMonitoringStatus() const {
    std::cout << "\n=== Monitoring Status ===" << std::endl;
    std::cout << "Status: " << (isMonitoring ? "ACTIVE" : "INACTIVE") << std::endl;

    if (isMonitoring) {
        std::cout << "Interval: " << monitoringIntervalSeconds << " seconds" << std::endl;
    }

    std::cout << "Events Logged: " << eventLog.size() << std::endl;

    // Count events by severity
    int dangerous = 0, suspicious = 0, safe = 0;
    for (const auto& event : eventLog) {
        switch (event.severity) {
            case DANGEROUS: dangerous++; break;
            case SUSPICIOUS: suspicious++; break;
            case SAFE: safe++; break;
        }
    }

    std::cout << "\nEvent Breakdown:" << std::endl;
    std::cout << "  DANGEROUS:  " << dangerous << std::endl;
    std::cout << "  SUSPICIOUS: " << suspicious << std::endl;
    std::cout << "  SAFE:       " << safe << std::endl;
}