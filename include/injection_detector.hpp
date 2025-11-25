#ifndef INJECTION_DETECTOR_H
#define INJECTION_DETECTOR_H

#include <windows.h>
#include <string>
#include <vector>
#include <map>

// Injection technique types
enum InjectionTechnique {
    UNKNOWN = 0,
    DLL_INJECTION,
    PROCESS_HOLLOWING,
    REFLECTIVE_DLL_INJECTION,
    ATOM_BOMBING,
    THREAD_EXECUTION_HIJACKING,
    PE_INJECTION,
    APC_INJECTION,
    PROCESS_DOPPELGANGING
};

// Behavioral anomaly types
enum BehaviorAnomaly {
    NONE = 0,
    SUSPICIOUS_MEMORY_ALLOCATION,
    SUSPICIOUS_THREAD_CREATION,
    SUSPICIOUS_HANDLE_USAGE,
    CODE_INJECTION_ATTEMPT,
    MEMORY_PERMISSION_CHANGE,
    REMOTE_THREAD_CREATION,
    UNUSUAL_API_CALLS,
    PACKED_EXECUTABLE,
    SUSPICIOUS_PARENT_CHILD,
    PRIVILEGE_ESCALATION_ATTEMPT
};

struct InjectionIndicator {
    InjectionTechnique technique;
    std::string processName;
    DWORD pid;
    std::string description;
    int severity;  // 1-10 scale
    std::time_t detectedTime;
    std::vector<std::string> evidence;
};

struct BehavioralPattern {
    BehaviorAnomaly anomaly;
    DWORD pid;
    std::string processName;
    std::string details;
    int riskScore;
    std::time_t timestamp;
};

class InjectionDetector {
private:
    std::vector<InjectionIndicator> detectedInjections;
    std::vector<BehavioralPattern> behavioralAnomalies;
    std::map<DWORD, std::vector<BehavioralPattern>> processHistory;

    // Detection methods for various injection techniques
    bool detectDllInjection(DWORD pid);
    bool detectProcessHollowing(DWORD pid);
    bool detectReflectiveDllInjection(DWORD pid);
    bool detectAtomBombing(DWORD pid);
    bool detectThreadHijacking(DWORD pid);
    bool detectAPCInjection(DWORD pid);

    // Memory analysis
    bool checkSuspiciousMemoryRegions(DWORD pid);
    bool checkRWXMemory(DWORD pid);
    bool checkUnbackedMemory(DWORD pid);

    // Behavioral analysis
    bool checkSuspiciousThreads(DWORD pid);
    bool checkSuspiciousHandles(DWORD pid);
    bool checkParentChildRelationship(DWORD pid);
    bool checkLoadedModules(DWORD pid);

    // PE Analysis
    bool isPacked(DWORD pid);
    bool hasAnomalousEntryPoint(DWORD pid);

    // Helper functions
    std::string getTechniqueName(InjectionTechnique tech);
    std::string getAnomalyName(BehaviorAnomaly anomaly);
    int calculateRiskScore(const std::vector<BehavioralPattern>& patterns);

public:
    InjectionDetector();
    ~InjectionDetector();

    // Main detection functions
    void scanProcess(DWORD pid, const std::string& processName);
    void scanAllProcesses();

    // Behavioral monitoring
    void startBehavioralMonitoring(DWORD pid);
    void updateBehavioralProfile(DWORD pid);

    // Analysis and reporting
    std::vector<InjectionIndicator> getDetectedInjections() const;
    std::vector<BehavioralPattern> getBehavioralAnomalies() const;
    std::vector<BehavioralPattern> getProcessBehavior(DWORD pid) const;

    // Risk assessment
    int getProcessRiskScore(DWORD pid);
    bool isProcessSuspicious(DWORD pid);

    // Display functions
    void displayInjectionResults() const;
    void displayBehavioralAnalysis() const;
    void displayProcessRiskProfile(DWORD pid) const;

    // Utilities
    void clearDetections();
    int getTotalThreats() const;
    std::string generateDetailedReport() const;
};

#endif // INJECTION_DETECTOR_H