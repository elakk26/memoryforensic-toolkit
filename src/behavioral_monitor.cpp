#include "../include/behavioral_monitor.hpp"
#include <iostream>
#include <iomanip>
#include <tlhelp32.h>
#include <psapi.h>

BehavioralMonitor::BehavioralMonitor() : isMonitoring(false) {}

BehavioralMonitor::~BehavioralMonitor() {
    stopMonitoring();
}

void BehavioralMonitor::startMonitoring() {
    isMonitoring = true;
    std::cout << "[+] Behavioral monitoring started\n";
}

void BehavioralMonitor::stopMonitoring() {
    isMonitoring = false;
    std::cout << "[+] Behavioral monitoring stopped\n";
}

bool BehavioralMonitor::isActive() const {
    return isMonitoring;
}

std::string BehavioralMonitor::getProtectionString(DWORD protect) {
    if (protect & PAGE_EXECUTE_READWRITE) return "RWX";
    if (protect & PAGE_EXECUTE_READ) return "RX";
    if (protect & PAGE_EXECUTE) return "X";
    if (protect & PAGE_READWRITE) return "RW";
    if (protect & PAGE_READONLY) return "R";
    return "---";
}

std::string BehavioralMonitor::getTypeString(DWORD type) {
    switch(type) {
        case MEM_IMAGE: return "IMAGE";
        case MEM_MAPPED: return "MAPPED";
        case MEM_PRIVATE: return "PRIVATE";
        default: return "UNKNOWN";
    }
}

std::vector<MemoryRegionInfo> BehavioralMonitor::getMemoryRegions(DWORD pid) {
    std::vector<MemoryRegionInfo> regions;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return regions;
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT) {
            MemoryRegionInfo info;
            info.baseAddress = mbi.BaseAddress;
            info.size = mbi.RegionSize;
            info.protection = mbi.Protect;
            info.type = mbi.Type;
            info.isSuspicious = false;
            
            // Check if suspicious
            if ((mbi.Protect & PAGE_EXECUTE_READWRITE) && mbi.Type == MEM_PRIVATE) {
                info.isSuspicious = true;
            }
            
            regions.push_back(info);
        }
        
        address = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return regions;
}

bool BehavioralMonitor::detectRWXMemory(DWORD pid) {
    std::vector<MemoryRegionInfo> regions = getMemoryRegions(pid);
    bool found = false;
    
    for (const auto& region : regions) {
        if ((region.protection & PAGE_EXECUTE_READWRITE) && 
            region.type != MEM_IMAGE) {
            
            found = true;
            
            BehaviorEvent event;
            event.type = MEMORY_ALLOCATION;
            event.pid = pid;
            event.description = "RWX memory region detected";
            event.threatLevel = HIGH;
            event.timestamp = std::time(nullptr);
            
            char addr[32];
            sprintf(addr, "0x%p", region.baseAddress);
            event.details = "Address: " + std::string(addr) + 
                          ", Size: " + std::to_string(region.size / 1024) + " KB";
            
            recordEvent(event);
        }
    }
    
    return found;
}

bool BehavioralMonitor::detectUnbackedExecutable(DWORD pid) {
    std::vector<MemoryRegionInfo> regions = getMemoryRegions(pid);
    bool found = false;
    
    for (const auto& region : regions) {
        if (region.type == MEM_PRIVATE && 
            (region.protection & PAGE_EXECUTE)) {
            
            found = true;
            
            BehaviorEvent event;
            event.type = MEMORY_ALLOCATION;
            event.pid = pid;
            event.description = "Unbacked executable memory (possible injection)";
            event.threatLevel = CRITICAL;
            event.timestamp = std::time(nullptr);
            
            char addr[32];
            sprintf(addr, "0x%p", region.baseAddress);
            event.details = "Private executable at: " + std::string(addr);
            
            recordEvent(event);
        }
    }
    
    return found;
}

std::vector<std::string> BehavioralMonitor::getLoadedModules(DWORD pid) {
    std::vector<std::string> modules;
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return modules;
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    if (Module32First(hSnapshot, &me32)) {
        do {
            modules.push_back(me32.szExePath);
        } while (Module32Next(hSnapshot, &me32));
    }
    
    CloseHandle(hSnapshot);
    return modules;
}

bool BehavioralMonitor::detectSuspiciousModules(DWORD pid) {
    std::vector<std::string> modules = getLoadedModules(pid);
    bool found = false;
    
    for (const auto& modulePath : modules) {
        std::string pathLower = modulePath;
        for (auto& c : pathLower) c = tolower(c);
        
        // Check for suspicious locations
        if (pathLower.find("\\temp\\") != std::string::npos ||
            pathLower.find("\\appdata\\local\\temp\\") != std::string::npos ||
            pathLower.find("\\users\\public\\") != std::string::npos ||
            pathLower.find("\\downloads\\") != std::string::npos) {
            
            found = true;
            
            BehaviorEvent event;
            event.type = MODULE_LOAD;
            event.pid = pid;
            event.description = "Module loaded from suspicious location";
            event.threatLevel = HIGH;
            event.timestamp = std::time(nullptr);
            event.details = modulePath;
            
            recordEvent(event);
        }
    }
    
    return found;
}

bool BehavioralMonitor::detectSuspiciousThreads(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    bool found = false;
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                // Thread found - could add more analysis here
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    return found;
}

void BehavioralMonitor::scanProcess(DWORD pid) {
    // Initialize profile if doesn't exist
    if (profiles.find(pid) == profiles.end()) {
        ProcessProfile profile;
        profile.pid = pid;
        profile.totalEvents = 0;
        profile.suspiciousEvents = 0;
        profile.riskScore = 0;
        profile.firstSeen = std::time(nullptr);
        profile.lastActivity = std::time(nullptr);
        
        // Get process name
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess) {
            char name[MAX_PATH];
            if (GetProcessImageFileNameA(hProcess, name, MAX_PATH)) {
                profile.name = name;
            }
            CloseHandle(hProcess);
        }
        
        profiles[pid] = profile;
    }
    
    // Perform scans
    detectRWXMemory(pid);
    detectUnbackedExecutable(pid);
    detectSuspiciousModules(pid);
    detectSuspiciousThreads(pid);
    
    updateProcessProfile(pid);
}

void BehavioralMonitor::recordEvent(const BehaviorEvent& event) {
    allEvents.push_back(event);
    
    if (profiles.find(event.pid) != profiles.end()) {
        profiles[event.pid].events.push_back(event);
        profiles[event.pid].totalEvents++;
        
        if (event.threatLevel >= MEDIUM) {
            profiles[event.pid].suspiciousEvents++;
        }
        
        profiles[event.pid].lastActivity = event.timestamp;
    }
}

void BehavioralMonitor::updateProcessProfile(DWORD pid) {
    if (profiles.find(pid) == profiles.end()) return;
    
    ProcessProfile& profile = profiles[pid];
    
    // Calculate risk score
    profile.riskScore = 0;
    for (const auto& event : profile.events) {
        profile.riskScore += static_cast<int>(event.threatLevel) * 5;
    }
    
    profile.riskScore = std::min(profile.riskScore, 100);
}

ProcessProfile BehavioralMonitor::getProcessProfile(DWORD pid) const {
    auto it = profiles.find(pid);
    if (it != profiles.end()) {
        return it->second;
    }
    return ProcessProfile();
}

std::vector<BehaviorEvent> BehavioralMonitor::getHighRiskEvents() const {
    std::vector<BehaviorEvent> highRisk;
    
    for (const auto& event : allEvents) {
        if (event.threatLevel >= HIGH) {
            highRisk.push_back(event);
        }
    }
    
    return highRisk;
}

std::vector<DWORD> BehavioralMonitor::getSuspiciousProcesses() const {
    std::vector<DWORD> suspicious;
    
    for (const auto& pair : profiles) {
        if (pair.second.riskScore >= 20 || pair.second.suspiciousEvents > 0) {
            suspicious.push_back(pair.first);
        }
    }
    
    return suspicious;
}

int BehavioralMonitor::getTotalEvents() const {
    return allEvents.size();
}

int BehavioralMonitor::getSuspiciousEventCount() const {
    int count = 0;
    for (const auto& event : allEvents) {
        if (event.threatLevel >= MEDIUM) {
            count++;
        }
    }
    return count;
}

int BehavioralMonitor::getMonitoredProcessCount() const {
    return profiles.size();
}

void BehavioralMonitor::displayProcessProfile(DWORD pid) const {
    auto it = profiles.find(pid);
    if (it == profiles.end()) {
        std::cout << "No profile found for PID " << pid << "\n";
        return;
    }
    
    const ProcessProfile& profile = it->second;
    
    std::cout << "\n\033[36m========================================\n";
    std::cout << "   PROCESS BEHAVIORAL PROFILE\n";
    std::cout << "========================================\033[0m\n\n";
    
    std::cout << "PID: " << profile.pid << "\n";
    std::cout << "Name: " << profile.name << "\n";
    std::cout << "Risk Score: ";
    
    if (profile.riskScore >= 50) {
        std::cout << "\033[31m" << profile.riskScore << "/100 [CRITICAL]\033[0m\n";
    } else if (profile.riskScore >= 25) {
        std::cout << "\033[33m" << profile.riskScore << "/100 [HIGH]\033[0m\n";
    } else {
        std::cout << "\033[32m" << profile.riskScore << "/100 [LOW]\033[0m\n";
    }
    
    std::cout << "Total Events: " << profile.totalEvents << "\n";
    std::cout << "Suspicious Events: " << profile.suspiciousEvents << "\n\n";
    
    if (!profile.events.empty()) {
        std::cout << "Recent Events:\n";
        int count = 0;
        for (const auto& event : profile.events) {
            if (count++ >= 5) break;
            
            std::cout << "  [" << count << "] " << event.description << "\n";
            std::cout << "      Threat Level: " << event.threatLevel << "\n";
            if (!event.details.empty()) {
                std::cout << "      Details: " << event.details << "\n";
            }
        }
    }
}

void BehavioralMonitor::displaySummary() const {
    std::cout << "\n\033[36m========================================\n";
    std::cout << "   MONITORING SUMMARY\n";
    std::cout << "========================================\033[0m\n\n";
    
    std::cout << "Monitored Processes: " << getMonitoredProcessCount() << "\n";
    std::cout << "Total Events: " << getTotalEvents() << "\n";
    std::cout << "Suspicious Events: " << getSuspiciousEventCount() << "\n";
    std::cout << "High-Risk Processes: " << getSuspiciousProcesses().size() << "\n";
}

void BehavioralMonitor::clearProfile(DWORD pid) {
    profiles.erase(pid);
}

void BehavioralMonitor::clearAll() {
    profiles.clear();
    allEvents.clear();
}