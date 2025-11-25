/**
 * memory_scan.cpp
 * Enhanced memory scanner with accurate Working Set calculation
 * Matches Windows Task Manager memory reporting on Wine/Proton
 */

#include "../include/memory_scan.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <cstring>
#include <iomanip>

MemoryScan::MemoryScan() {
}

MemoryScan::~MemoryScan() {
    scanResults.clear();
}

ScanResult MemoryScan::performScan(int processId) {
    ScanResult result;
    scanResults.clear();

    int pid = processId == 0 ? getpid() : processId;

    std::cout << "\n=== Starting Memory Scan ===" << std::endl;
    std::cout << "Target Process ID: " << pid << std::endl;

    // Get process name
    std::string processName = getProcessName(pid);
    std::cout << "Process Name: " << processName << std::endl;

    // Get accurate working set memory (matches task manager)
    unsigned long long workingSet = getWorkingSetMemory(pid);

    // Get memory maps
    auto memoryMaps = getProcessMemoryMaps(pid);

    std::cout << "Found " << memoryMaps.size() << " memory regions" << std::endl;

    // Parse each memory map line
    for (const auto& line : memoryMaps) {
        MemoryRegion region = parseMemoryLine(line);
        if (!region.address.empty()) {
            region.scanTime = std::time(nullptr);
            scanResults.push_back(region);
        }
    }

    result.regions = scanResults;
    result.totalRegions = scanResults.size();
    result.scanTimestamp = std::time(nullptr);
    result.scanStatus = "Completed";
    result.actualMemoryUsage = workingSet;

    std::cout << "Memory Usage: " << formatBytes(workingSet) << std::endl;
    std::cout << "Scan completed successfully" << std::endl;

    return result;
}

unsigned long long MemoryScan::getWorkingSetMemory(int pid) {
    // Read from /proc/[pid]/statm for accurate working set
    std::string statmPath = "/proc/" + std::to_string(pid) + "/statm";
    std::ifstream statmFile(statmPath);

    if (!statmFile.is_open()) {
        std::cerr << "Failed to open: " << statmPath << std::endl;
        // Fallback to RSS from status
        return getActualMemoryUsage(pid);
    }

    // statm format: size resident shared text lib data dt
    // We want 'resident' - RSS in pages
    unsigned long long size, resident, shared;
    statmFile >> size >> resident >> shared;
    statmFile.close();

    // Get page size
    long pageSize = sysconf(_SC_PAGESIZE);

    // Calculate private working set (resident - shared)
    // This matches Windows Task Manager "Memory (Private Working Set)"
    unsigned long long privateWorkingSet = (resident - shared) * pageSize;

    return privateWorkingSet;
}

unsigned long long MemoryScan::getActualMemoryUsage(int pid) {
    std::string statusPath = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream statusFile(statusPath);

    if (!statusFile.is_open()) {
        std::cerr << "Failed to open: " << statusPath << std::endl;
        return 0;
    }

    std::string line;
    unsigned long long rssKB = 0;

    while (std::getline(statusFile, line)) {
        // Look for VmRSS (Resident Set Size)
        if (line.find("VmRSS:") == 0) {
            std::istringstream iss(line);
            std::string label;
            unsigned long long value;
            std::string unit;

            iss >> label >> value >> unit;
            rssKB = value;
            break;
        }
    }

    statusFile.close();

    // Convert KB to bytes
    return rssKB * 1024;
}

std::string MemoryScan::getProcessName(int pid) {
    // First try to get from cmdline (better for Wine processes)
    std::string cmdlinePath = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmdlineFile(cmdlinePath);

    if (cmdlineFile.is_open()) {
        std::string cmdline;
        std::getline(cmdlineFile, cmdline, '\0');
        cmdlineFile.close();

        // Extract just the executable name
        size_t lastSlash = cmdline.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            cmdline = cmdline.substr(lastSlash + 1);
        }

        if (!cmdline.empty()) {
            return cmdline;
        }
    }

    // Fallback to status file
    std::string statusPath = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream statusFile(statusPath);

    if (!statusFile.is_open()) {
        return "Unknown";
    }

    std::string line;
    while (std::getline(statusFile, line)) {
        if (line.find("Name:") == 0) {
            std::istringstream iss(line);
            std::string label, name;
            iss >> label >> name;
            statusFile.close();
            return name;
        }
    }

    statusFile.close();
    return "Unknown";
}

std::vector<std::string> MemoryScan::getProcessMemoryMaps(int pid) {
    std::vector<std::string> maps;
    std::string mapsPath = "/proc/" + std::to_string(pid) + "/maps";

    std::ifstream mapsFile(mapsPath);
    if (!mapsFile.is_open()) {
        std::cerr << "Failed to open: " << mapsPath << std::endl;
        return maps;
    }

    std::string line;
    while (std::getline(mapsFile, line)) {
        maps.push_back(line);
    }

    mapsFile.close();
    return maps;
}

MemoryRegion MemoryScan::parseMemoryLine(const std::string& line) {
    MemoryRegion region;

    std::istringstream iss(line);
    std::string addressRange, permissions, offset, device, inode;

    iss >> addressRange >> permissions >> offset >> device >> inode;

    // Parse address range
    size_t dashPos = addressRange.find('-');
    if (dashPos != std::string::npos) {
        std::string startAddr = addressRange.substr(0, dashPos);
        std::string endAddr = addressRange.substr(dashPos + 1);

        region.address = startAddr;

        // Calculate size correctly
        unsigned long long start = std::stoull(startAddr, nullptr, 16);
        unsigned long long end = std::stoull(endAddr, nullptr, 16);
        unsigned long long sizeBytes = end - start;

        // Store size in bytes as string
        region.size = std::to_string(sizeBytes);
    }

    region.permissions = permissions;

    // Get module name (everything after inode)
    std::string remaining;
    std::getline(iss, remaining);

    // Trim leading whitespace
    size_t firstNonSpace = remaining.find_first_not_of(" \t");
    if (firstNonSpace != std::string::npos) {
        region.module = remaining.substr(firstNonSpace);
    } else {
        region.module = "[anonymous]";
    }

    return region;
}

std::string MemoryScan::formatBytes(unsigned long long bytes) const {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unitIndex < 4) {
        size /= 1024.0;
        unitIndex++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(4) << size << " " << units[unitIndex];
    return oss.str();
}

unsigned long long MemoryScan::getTotalMemoryUsage() const {
    unsigned long long total = 0;

    for (const auto& region : scanResults) {
        try {
            unsigned long long size = std::stoull(region.size);
            total += size;
        } catch (...) {
            // Skip invalid sizes
        }
    }

    return total;
}

MemoryStats MemoryScan::getDetailedMemoryStats(int pid) {
    MemoryStats stats;

    std::string statusPath = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream statusFile(statusPath);

    if (!statusFile.is_open()) {
        std::cerr << "Failed to open: " << statusPath << std::endl;
        return stats;
    }

    std::string line;

    while (std::getline(statusFile, line)) {
        std::istringstream iss(line);
        std::string label;
        unsigned long long value;

        iss >> label >> value;

        if (label == "VmSize:") {
            stats.virtualMemory = value * 1024;
        } else if (label == "VmRSS:") {
            stats.residentMemory = value * 1024;
        } else if (label == "RssAnon:") {
            stats.privateMemory = value * 1024; // Anonymous RSS (private)
        } else if (label == "RssFile:") {
            stats.sharedMemory = value * 1024; // File-backed RSS (shared)
        } else if (label == "VmData:") {
            stats.dataMemory = value * 1024;
        } else if (label == "VmStk:") {
            stats.stackMemory = value * 1024;
        } else if (label == "VmExe:") {
            stats.codeMemory = value * 1024;
        } else if (label == "VmLib:") {
            stats.libraryMemory = value * 1024;
        } else if (label == "VmSwap:") {
            stats.swapMemory = value * 1024;
        }
    }

    statusFile.close();

    // Calculate working set (private working set)
    stats.workingSet = getWorkingSetMemory(pid);

    return stats;
}

void MemoryScan::displayMemoryStats(int pid) {
    MemoryStats stats = getDetailedMemoryStats(pid);
    std::string processName = getProcessName(pid);

    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║          Process Memory Statistics                     ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    std::cout << "Process ID:              " << pid << std::endl;
    std::cout << "Process Name:            " << processName << std::endl;
    std::cout << std::endl;
    std::cout << "┌─────────────────────────────────────────────────────┐" << std::endl;
    std::cout << "│ Memory Usage (Task Manager Compatible)             │" << std::endl;
    std::cout << "├─────────────────────────────────────────────────────┤" << std::endl;
    std::cout << "│ Memory Usage:           " << std::setw(20) << std::right
              << formatBytes(stats.workingSet) << "    │" << std::endl;
    std::cout << "│ Private Memory:         " << std::setw(20) << std::right
              << formatBytes(stats.privateMemory) << "    │" << std::endl;
    std::cout << "│ Shared Memory:          " << std::setw(20) << std::right
              << formatBytes(stats.sharedMemory) << "    │" << std::endl;
    std::cout << "│ Virtual Memory:         " << std::setw(20) << std::right
              << formatBytes(stats.virtualMemory) << "    │" << std::endl;
    std::cout << "├─────────────────────────────────────────────────────┤" << std::endl;
    std::cout << "│ Data Segment:           " << std::setw(20) << std::right
              << formatBytes(stats.dataMemory) << "    │" << std::endl;
    std::cout << "│ Stack:                  " << std::setw(20) << std::right
              << formatBytes(stats.stackMemory) << "    │" << std::endl;
    std::cout << "│ Code:                   " << std::setw(20) << std::right
              << formatBytes(stats.codeMemory) << "    │" << std::endl;
    std::cout << "│ Libraries:              " << std::setw(20) << std::right
              << formatBytes(stats.libraryMemory) << "    │" << std::endl;

    if (stats.swapMemory > 0) {
        std::cout << "│ Swap:                   " << std::setw(20) << std::right
                  << formatBytes(stats.swapMemory) << "    │" << std::endl;
    }

    std::cout << "└─────────────────────────────────────────────────────┘" << std::endl;
    std::cout << std::endl;

    // Calculate percentage
    double percentUsage = (static_cast<double>(stats.workingSet) / stats.virtualMemory) * 100.0;
    std::cout << "Physical/Virtual Ratio:  " << std::fixed << std::setprecision(1)
              << percentUsage << "%" << std::endl;
}

std::vector<MemoryRegion> MemoryScan::getScanResults() const {
    return scanResults;
}

int MemoryScan::getRegionCount() const {
    return scanResults.size();
}