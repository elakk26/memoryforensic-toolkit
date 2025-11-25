#ifndef BEHAVIORAL_MONITOR_H
#define BEHAVIORAL_MONITOR_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <ctime>

// Behavior types
enum BehaviorType {
    MEMORY_ALLOCATION,
    THREAD_CREATION,
    MODULE_LOAD,
    HANDLE_OPERATION,
    REGISTRY_ACCESS,
    FILE_OPERATION,
    NETWORK_CONNECTION,
    PROCESS_CREATION
};

// Threat levels
enum ThreatLevel {
    SAFE = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    CRITICAL = 4
};

struct BehaviorEvent {
    BehaviorType type;
    DWORD pid;
    std::string processName;
    std::string description;
    ThreatLevel threatLevel;
    std::time_t timestamp;
    std::string details;
};

struct ProcessProfile {
    DWORD pid;
    std::string name;
    int totalEvents;
    int suspiciousEvents;
    int riskScore;
    std::vector<BehaviorEvent> events;
    std::time_t firstSeen;
    std::time_t lastActivity;
};

struct MemoryRegionInfo {
    void* baseAddress;
    SIZE_T size;
    DWORD protection;
    DWORD type;
    std::string module;
    bool isSuspicious;
};

class BehavioralMonitor {
private:
    std::map<DWORD, ProcessProfile> profiles;
    std::vector<BehaviorEvent> allEvents;
    bool isMonitoring;

    // Analysis methods
    ThreatLevel assessMemoryRegion(const MemoryRegionInfo& region);
    ThreatLevel assessModuleLoad(const std::string& modulePath);
    ThreatLevel assessThreadCreation(DWORD pid, HANDLE hThread);

    // Helper methods
    std::string getProtectionString(DWORD protect);
    std::string getTypeString(DWORD type);
    bool isSystemProcess(DWORD pid);

public:
    BehavioralMonitor();
    ~BehavioralMonitor();

    // Monitoring control
    void startMonitoring();
    void stopMonitoring();
    bool isActive() const;

    // Process scanning
    void scanProcess(DWORD pid);
    void scanAllProcesses();

    // Event recording
    void recordEvent(const BehaviorEvent& event);
    void updateProcessProfile(DWORD pid);

    // Memory analysis
    std::vector<MemoryRegionInfo> getMemoryRegions(DWORD pid);
    bool detectRWXMemory(DWORD pid);
    bool detectUnbackedExecutable(DWORD pid);
    bool detectHollowedProcess(DWORD pid);

    // Module analysis
    std::vector<std::string> getLoadedModules(DWORD pid);
    bool detectSuspiciousModules(DWORD pid);

    // Thread analysis
    bool detectSuspiciousThreads(DWORD pid);

    // Reporting
    ProcessProfile getProcessProfile(DWORD pid) const;
    std::vector<BehaviorEvent> getHighRiskEvents() const;
    std::vector<DWORD> getSuspiciousProcesses() const;

    // Statistics
    int getTotalEvents() const;
    int getSuspiciousEventCount() const;
    int getMonitoredProcessCount() const;

    // Display
    void displayProcessProfile(DWORD pid) const;
    void displayAllProfiles() const;
    void displaySummary() const;

    // Clear data
    void clearProfile(DWORD pid);
    void clearAll();
};

#endif // BEHAVIORAL_MONITOR_H