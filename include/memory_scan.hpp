/**
 * memory_scan.hpp
 * Memory scanner with accurate Working Set calculation
 * Matches Windows Task Manager memory reporting
 */

#ifndef MEMORY_SCAN_HPP
#define MEMORY_SCAN_HPP

#include <string>
#include <vector>
#include <ctime>
#include <iomanip>

struct MemoryRegion {
    std::string address;        // Start address of memory region
    std::string size;           // Size in bytes (virtual)
    std::string permissions;    // rwx permissions
    std::string module;         // Module/library name or [anonymous]
    std::time_t scanTime;       // When this region was scanned
};

struct MemoryStats {
    unsigned long long virtualMemory = 0;   // VmSize - Total virtual memory
    unsigned long long residentMemory = 0;  // VmRSS - Total resident memory
    unsigned long long workingSet = 0;      // Private Working Set - MATCHES TASK MANAGER
    unsigned long long privateMemory = 0;   // RssAnon - Private pages
    unsigned long long sharedMemory = 0;    // RssFile - Shared pages
    unsigned long long dataMemory = 0;      // VmData - Data segment size
    unsigned long long stackMemory = 0;     // VmStk - Stack size
    unsigned long long codeMemory = 0;      // VmExe - Code segment size
    unsigned long long libraryMemory = 0;   // VmLib - Shared library memory
    unsigned long long swapMemory = 0;      // VmSwap - Swapped out memory
};

struct ScanResult {
    std::vector<MemoryRegion> regions;
    int totalRegions;
    std::time_t scanTimestamp;
    std::string scanStatus;
    unsigned long long actualMemoryUsage;  // Working Set - matches task manager
};

class MemoryScan {
private:
    std::vector<MemoryRegion> scanResults;

    std::vector<std::string> getProcessMemoryMaps(int pid);
    MemoryRegion parseMemoryLine(const std::string& line);

public:
    MemoryScan();
    ~MemoryScan();

    // Core scanning functions
    ScanResult performScan(int processId = 0);

    // Memory statistics (matches task manager)
    unsigned long long getWorkingSetMemory(int pid);   // Private Working Set (Task Manager)
    unsigned long long getActualMemoryUsage(int pid);  // Returns RSS in bytes
    MemoryStats getDetailedMemoryStats(int pid);       // All memory metrics
    void displayMemoryStats(int pid);                  // Pretty print stats
    
    // Process information
    std::string getProcessName(int pid);
    
    // Utility functions
    std::string formatBytes(unsigned long long bytes) const;
    unsigned long long getTotalMemoryUsage() const;  // Virtual memory size
    std::vector<MemoryRegion> getScanResults() const;
    int getRegionCount() const;
};

#endif // MEMORY_SCAN_HPP