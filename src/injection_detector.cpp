#include "../include/injection_detector.hpp"
#include <iostream>
#include <iomanip>
#include <tlhelp32.h>
#include <psapi.h>

InjectionDetector::InjectionDetector() {}
InjectionDetector::~InjectionDetector() {}

std::string InjectionDetector::getTechniqueName(InjectionTechnique tech) {
    switch(tech) {
        case DLL_INJECTION: return "DLL Injection";
        case PROCESS_HOLLOWING: return "Process Hollowing";
        case REFLECTIVE_DLL_INJECTION: return "Reflective DLL Injection";
        case ATOM_BOMBING: return "Atom Bombing";
        case THREAD_EXECUTION_HIJACKING: return "Thread Execution Hijacking";
        case PE_INJECTION: return "PE Injection";
        case APC_INJECTION: return "APC Injection";
        case PROCESS_DOPPELGANGING: return "Process Doppelganging";
        default: return "Unknown";
    }
}

std::string InjectionDetector::getAnomalyName(BehaviorAnomaly anomaly) {
    switch(anomaly) {
        case SUSPICIOUS_MEMORY_ALLOCATION: return "Suspicious Memory Allocation";
        case SUSPICIOUS_THREAD_CREATION: return "Suspicious Thread Creation";
        case SUSPICIOUS_HANDLE_USAGE: return "Suspicious Handle Usage";
        case CODE_INJECTION_ATTEMPT: return "Code Injection Attempt";
        case MEMORY_PERMISSION_CHANGE: return "Memory Permission Change";
        case REMOTE_THREAD_CREATION: return "Remote Thread Creation";
        case UNUSUAL_API_CALLS: return "Unusual API Calls";
        case PACKED_EXECUTABLE: return "Packed Executable";
        case SUSPICIOUS_PARENT_CHILD: return "Suspicious Parent-Child Relationship";
        case PRIVILEGE_ESCALATION_ATTEMPT: return "Privilege Escalation Attempt";
        default: return "None";
    }
}

bool InjectionDetector::checkRWXMemory(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;
    bool foundRWX = false;
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        // Check for RWX (Read-Write-Execute) memory regions - highly suspicious
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect & PAGE_EXECUTE_READWRITE) ||
            (mbi.Protect & PAGE_EXECUTE_WRITECOPY)) {
            
            // Skip known legitimate regions
            if (mbi.Type != MEM_IMAGE && mbi.Type != MEM_MAPPED) {
                foundRWX = true;
                
                BehavioralPattern pattern;
                pattern.anomaly = SUSPICIOUS_MEMORY_ALLOCATION;
                pattern.pid = pid;
                pattern.details = "RWX memory region at 0x" + 
                    std::to_string(reinterpret_cast<uintptr_t>(mbi.BaseAddress));
                pattern.riskScore = 8;
                pattern.timestamp = std::time(nullptr);
                behavioralAnomalies.push_back(pattern);
            }
        }
        
        address = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return foundRWX;
}

bool InjectionDetector::checkUnbackedMemory(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = nullptr;
    bool foundUnbacked = false;
    
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        // Check for private executable memory (not backed by a file)
        if (mbi.State == MEM_COMMIT && 
            mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & PAGE_EXECUTE) ||
            (mbi.Protect & PAGE_EXECUTE_READ) ||
            (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            
            foundUnbacked = true;
            
            BehavioralPattern pattern;
            pattern.anomaly = CODE_INJECTION_ATTEMPT;
            pattern.pid = pid;
            pattern.details = "Unbacked executable memory (possible injected code)";
            pattern.riskScore = 9;
            pattern.timestamp = std::time(nullptr);
            behavioralAnomalies.push_back(pattern);
        }
        
        address = static_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;
    }
    
    CloseHandle(hProcess);
    return foundUnbacked;
}

bool InjectionDetector::detectDllInjection(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    bool suspicious = false;
    std::vector<std::string> suspiciousDlls;
    
    if (Module32First(hSnapshot, &me32)) {
        do {
            std::string modulePath = me32.szExePath;
            std::string moduleName = me32.szModule;
            
            // Check for DLLs loaded from suspicious locations
            if (modulePath.find("\\Temp\\") != std::string::npos ||
                modulePath.find("\\AppData\\Local\\Temp\\") != std::string::npos ||
                modulePath.find("\\Users\\Public\\") != std::string::npos) {
                
                suspicious = true;
                suspiciousDlls.push_back(moduleName);
            }
            
        } while (Module32Next(hSnapshot, &me32));
    }
    
    CloseHandle(hSnapshot);
    
    if (suspicious) {
        InjectionIndicator indicator;
        indicator.technique = DLL_INJECTION;
        indicator.pid = pid;
        indicator.description = "DLL loaded from suspicious location";
        indicator.severity = 7;
        indicator.detectedTime = std::time(nullptr);
        indicator.evidence = suspiciousDlls;
        detectedInjections.push_back(indicator);
    }
    
    return suspicious;
}

bool InjectionDetector::detectProcessHollowing(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    
    // Get the base address of the main module
    HMODULE hMods[1024];
    DWORD cbNeeded;
    bool suspicious = false;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        MODULEINFO mi;
        if (GetModuleInformation(hProcess, hMods[0], &mi, sizeof(mi))) {
            // Read PE header
            IMAGE_DOS_HEADER dosHeader;
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(hProcess, mi.lpBaseOfDll, &dosHeader, sizeof(dosHeader), &bytesRead)) {
                if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                    IMAGE_NT_HEADERS ntHeaders;
                    LPVOID ntHeaderAddr = static_cast<LPBYTE>(mi.lpBaseOfDll) + dosHeader.e_lfanew;
                    
                    if (ReadProcessMemory(hProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
                        // Check for entry point anomalies
                        DWORD entryPoint = ntHeaders.OptionalHeader.AddressOfEntryPoint;
                        
                        // Suspicious if entry point is 0 or outside the image
                        if (entryPoint == 0 || entryPoint > ntHeaders.OptionalHeader.SizeOfImage) {
                            suspicious = true;
                            
                            InjectionIndicator indicator;
                            indicator.technique = PROCESS_HOLLOWING;
                            indicator.pid = pid;
                            indicator.description = "Anomalous entry point detected";
                            indicator.severity = 9;
                            indicator.detectedTime = std::time(nullptr);
                            detectedInjections.push_back(indicator);
                        }
                    }
                }
            }
        }
    }
    
    CloseHandle(hProcess);
    return suspicious;
}

bool InjectionDetector::checkSuspiciousThreads(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    bool suspicious = false;
    
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    // Check thread start address
                    PVOID startAddress = nullptr;
                    NTSTATUS status = NtQueryInformationThread(hThread, 
                        (THREADINFOCLASS)9, // ThreadQuerySetWin32StartAddress
                        &startAddress, sizeof(startAddress), nullptr);
                    
                    if (status == 0 && startAddress) {
                        // Check if start address is in unbacked memory
                        MEMORY_BASIC_INFORMATION mbi;
                        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                        
                        if (hProcess && VirtualQueryEx(hProcess, startAddress, &mbi, sizeof(mbi))) {
                            if (mbi.Type == MEM_PRIVATE && (mbi.Protect & PAGE_EXECUTE)) {
                                suspicious = true;
                                
                                BehavioralPattern pattern;
                                pattern.anomaly = REMOTE_THREAD_CREATION;
                                pattern.pid = pid;
                                pattern.details = "Thread with start address in unbacked memory";
                                pattern.riskScore = 8;
                                pattern.timestamp = std::time(nullptr);
                                behavioralAnomalies.push_back(pattern);
                            }
                        }
                        
                        if (hProcess) CloseHandle(hProcess);
                    }
                    
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    
    CloseHandle(hSnapshot);
    return suspicious;
}

bool InjectionDetector::isPacked(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return false;
    
    HMODULE hMods[1];
    DWORD cbNeeded;
    bool packed = false;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        MODULEINFO mi;
        if (GetModuleInformation(hProcess, hMods[0], &mi, sizeof(mi))) {
            IMAGE_DOS_HEADER dosHeader;
            SIZE_T bytesRead;
            
            if (ReadProcessMemory(hProcess, mi.lpBaseOfDll, &dosHeader, sizeof(dosHeader), &bytesRead)) {
                if (dosHeader.e_magic == IMAGE_DOS_SIGNATURE) {
                    IMAGE_NT_HEADERS ntHeaders;
                    LPVOID ntHeaderAddr = static_cast<LPBYTE>(mi.lpBaseOfDll) + dosHeader.e_lfanew;
                    
                    if (ReadProcessMemory(hProcess, ntHeaderAddr, &ntHeaders, sizeof(ntHeaders), &bytesRead)) {
                        // Check for packer signatures
                        DWORD sizeOfRawData = 0;
                        DWORD virtualSize = 0;
                        
                        // If virtual size is much larger than raw size, likely packed
                        if (ntHeaders.OptionalHeader.SizeOfImage > 0) {
                            float ratio = (float)ntHeaders.OptionalHeader.SizeOfCode / 
                                         (float)ntHeaders.OptionalHeader.SizeOfImage;
                            
                            if (ratio < 0.1 || ratio > 0.9) {
                                packed = true;
                                
                                BehavioralPattern pattern;
                                pattern.anomaly = PACKED_EXECUTABLE;
                                pattern.pid = pid;
                                pattern.details = "Executable appears to be packed";
                                pattern.riskScore = 6;
                                pattern.timestamp = std::time(nullptr);
                                behavioralAnomalies.push_back(pattern);
                            }
                        }
                    }
                }
            }
        }
    }
    
    CloseHandle(hProcess);
    return packed;
}

void InjectionDetector::scanProcess(DWORD pid, const std::string& processName) {
    // Clear previous results for this process
    auto it = processHistory.find(pid);
    if (it != processHistory.end()) {
        it->second.clear();
    }
    
    // Perform all detection checks
    detectDllInjection(pid);
    detectProcessHollowing(pid);
    checkRWXMemory(pid);
    checkUnbackedMemory(pid);
    checkSuspiciousThreads(pid);
    isPacked(pid);
    
    // Store in history
    processHistory[pid] = behavioralAnomalies;
}

int InjectionDetector::calculateRiskScore(const std::vector<BehavioralPattern>& patterns) {
    int totalScore = 0;
    for (const auto& pattern : patterns) {
        totalScore += pattern.riskScore;
    }
    return std::min(totalScore, 100); // Cap at 100
}

int InjectionDetector::getProcessRiskScore(DWORD pid) {
    auto it = processHistory.find(pid);
    if (it != processHistory.end()) {
        return calculateRiskScore(it->second);
    }
    return 0;
}

bool InjectionDetector::isProcessSuspicious(DWORD pid) {
    return getProcessRiskScore(pid) >= 15; // Threshold for suspicious
}

void InjectionDetector::displayInjectionResults() const {
    std::cout << "\n\033[36m========================================\n";
    std::cout << "   INJECTION DETECTION RESULTS\n";
    std::cout << "========================================\033[0m\n\n";
    
    if (detectedInjections.empty()) {
        std::cout << "\033[32m[✓] No injection techniques detected\033[0m\n";
        return;
    }
    
    std::cout << "\033[31m[!] Detected " << detectedInjections.size() 
              << " injection indicators\033[0m\n\n";
    
    for (size_t i = 0; i < detectedInjections.size(); i++) {
        const auto& inj = detectedInjections[i];
        std::cout << "[\033[31m" << (i+1) << "\033[0m] " 
                  << "\033[33m" << getTechniqueName(inj.technique) << "\033[0m\n";
        std::cout << "    PID: " << inj.pid << "\n";
        std::cout << "    Process: " << inj.processName << "\n";
        std::cout << "    Severity: " << inj.severity << "/10\n";
        std::cout << "    Details: " << inj.description << "\n";
        
        if (!inj.evidence.empty()) {
            std::cout << "    Evidence:\n";
            for (const auto& ev : inj.evidence) {
                std::cout << "      - " << ev << "\n";
            }
        }
        std::cout << "\n";
    }
}

void InjectionDetector::displayBehavioralAnalysis() const {
    std::cout << "\n\033[36m========================================\n";
    std::cout << "   BEHAVIORAL ANALYSIS\n";
    std::cout << "========================================\033[0m\n\n";
    
    if (behavioralAnomalies.empty()) {
        std::cout << "\033[32m[✓] No behavioral anomalies detected\033[0m\n";
        return;
    }
    
    std::cout << "\033[33m[!] Detected " << behavioralAnomalies.size() 
              << " behavioral anomalies\033[0m\n\n";
    
    for (size_t i = 0; i < behavioralAnomalies.size(); i++) {
        const auto& anom = behavioralAnomalies[i];
        std::cout << "[\033[33m" << (i+1) << "\033[0m] " 
                  << getAnomalyName(anom.anomaly) << "\n";
        std::cout << "    PID: " << anom.pid << "\n";
        std::cout << "    Risk Score: " << anom.riskScore << "/10\n";
        std::cout << "    Details: " << anom.details << "\n\n";
    }
}

int InjectionDetector::getTotalThreats() const {
    return detectedInjections.size() + behavioralAnomalies.size();
}

void InjectionDetector::clearDetections() {
    detectedInjections.clear();
    behavioralAnomalies.clear();
    processHistory.clear();
}

std::vector<InjectionIndicator> InjectionDetector::getDetectedInjections() const {
    return detectedInjections;
}

std::vector<BehavioralPattern> InjectionDetector::getBehavioralAnomalies() const {
    return behavioralAnomalies;
}