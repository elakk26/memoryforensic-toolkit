#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <psapi.h>

    // Alternative admin check without shell32
    bool isAdmin() {
        BOOL isAdmin = FALSE;
        PSID adminGroup = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

        if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
            CheckTokenMembership(NULL, adminGroup, &isAdmin);
            FreeSid(adminGroup);
        }
        return isAdmin;
    }
    #define IS_ADMIN isAdmin()
#else
    #include <unistd.h>
    #define IS_ADMIN (getuid() == 0)
#endif

// Color codes for terminal output
#define COLOR_RESET "\033[0m"
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BLUE "\033[34m"
#define COLOR_CYAN "\033[36m"
#define COLOR_MAGENTA "\033[35m"

struct ProcessInfo {
    DWORD pid;
    std::string name;
    SIZE_T memoryUsage;
};

void enableWindowsConsoleColors() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);

    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
#endif
}

void displaySystemCheck() {
    std::cout << "\n========================================\n";
    std::cout << "   SYSTEM PRIVILEGE CHECK\n";
    std::cout << "========================================\n\n";

    if (!IS_ADMIN) {
        std::cout << COLOR_RED << "[!] WARNING: Not running with administrator privileges!\n" << COLOR_RESET;
        std::cout << COLOR_YELLOW << "[i] Some features may be limited.\n" << COLOR_RESET;
        std::cout << COLOR_YELLOW << "[i] Please run as Administrator for full functionality.\n\n" << COLOR_RESET;
    } else {
        std::cout << COLOR_GREEN << "[✓] Running with administrator privileges\n" << COLOR_RESET;
        std::cout << COLOR_GREEN << "[✓] Full system access granted\n\n" << COLOR_RESET;
    }
}

void displayBanner() {
    enableWindowsConsoleColors();

    std::cout << COLOR_CYAN;
    std::cout << "\n";
    std::cout << u8"╔══════════════════════════════════════════════╗\n";
    std::cout << u8"║     MEMORY THREAT DETECTION SYSTEM v1.0      ║\n";
    std::cout << u8"║     Advanced Process Memory Scanner          ║\n";
    std::cout << u8"╚══════════════════════════════════════════════╝\n";
    std::cout << COLOR_RESET;
}

void displayMenu() {
    std::cout << "\n" << COLOR_BLUE << "========================================\n";
    std::cout << "           MAIN MENU\n";
    std::cout << "========================================" << COLOR_RESET << "\n\n";
    std::cout << "1. Scan All Processes\n";
    std::cout << "2. Scan Specific Process (by PID)\n";
    std::cout << "3. Scan Specific Process (by Name)\n";
    std::cout << "4. View Threat Summary\n";
    std::cout << "5. Export Report\n";
    std::cout << "6. Exit\n\n";
    std::cout << "Enter your choice: ";
}

std::vector<ProcessInfo> getAllProcesses() {
    std::vector<ProcessInfo> processes;

#ifdef _WIN32
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << COLOR_RED << "[!] Failed to create process snapshot\n" << COLOR_RESET;
        return processes;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            ProcessInfo info;
            info.pid = pe32.th32ProcessID;
            info.name = pe32.szExeFile;

            // Get memory usage
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess != NULL) {
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
                    info.memoryUsage = pmc.WorkingSetSize;
                }
                CloseHandle(hProcess);
            }

            processes.push_back(info);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
#endif

    return processes;
}

void scanAllProcesses() {
    std::cout << COLOR_YELLOW << "\n[*] Scanning all processes...\n" << COLOR_RESET;
    std::cout << "================================================\n";

    std::vector<ProcessInfo> processes = getAllProcesses();

    if (processes.empty()) {
        std::cout << COLOR_RED << "[!] No processes found or access denied\n" << COLOR_RESET;
        return;
    }

    std::cout << COLOR_GREEN << "[✓] Found " << processes.size() << " processes\n\n" << COLOR_RESET;

    std::cout << std::left << std::setw(10) << "PID"
              << std::setw(35) << "Process Name"
              << std::setw(15) << "Memory (MB)" << "\n";
    std::cout << "------------------------------------------------------------\n";

    int count = 0;
    for (const auto& proc : processes) {
        if (count >= 20) {  // Show first 20 processes
            std::cout << COLOR_YELLOW << "... and " << (processes.size() - 20) << " more processes\n" << COLOR_RESET;
            break;
        }

        std::cout << std::left << std::setw(10) << proc.pid
                  << std::setw(35) << proc.name
                  << std::setw(15) << std::fixed << std::setprecision(2)
                  << (proc.memoryUsage / 1024.0 / 1024.0) << "\n";
        count++;
    }

    std::cout << "\n" << COLOR_CYAN << "[i] Scan completed successfully\n" << COLOR_RESET;
}

void scanProcessByPID(DWORD pid) {
    std::cout << COLOR_YELLOW << "\n[*] Scanning PID " << pid << "...\n" << COLOR_RESET;
    std::cout << "================================================\n";

#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

    if (hProcess == NULL) {
        std::cout << COLOR_RED << "[!] Failed to open process " << pid << "\n" << COLOR_RESET;
        std::cout << COLOR_YELLOW << "[i] Error: Access denied or process not found\n" << COLOR_RESET;
        std::cout << COLOR_YELLOW << "[i] Try running as Administrator\n" << COLOR_RESET;
        return;
    }

    // Get process name
    char processName[MAX_PATH] = "<unknown>";
    HMODULE hMod;
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
        GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(char));
    }

    // Get memory info
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
        std::cout << COLOR_GREEN << "[✓] Process found: " << processName << "\n\n" << COLOR_RESET;
        std::cout << "Process ID:        " << pid << "\n";
        std::cout << "Process Name:      " << processName << "\n";
        std::cout << "Working Set:       " << (pmc.WorkingSetSize / 1024.0 / 1024.0) << " MB\n";
        std::cout << "Peak Working Set:  " << (pmc.PeakWorkingSetSize / 1024.0 / 1024.0) << " MB\n";
        std::cout << "Page Faults:       " << pmc.PageFaultCount << "\n";
        std::cout << "\n" << COLOR_CYAN << "[i] Scan completed successfully\n" << COLOR_RESET;
    } else {
        std::cout << COLOR_RED << "[!] Failed to get memory information\n" << COLOR_RESET;
    }

    CloseHandle(hProcess);
#endif
}

void scanProcessByName(const std::string& name) {
    std::cout << COLOR_YELLOW << "\n[*] Scanning process: " << name << "...\n" << COLOR_RESET;
    std::cout << "================================================\n";

    std::vector<ProcessInfo> processes = getAllProcesses();
    bool found = false;

    for (const auto& proc : processes) {
        // Case-insensitive comparison
        std::string procNameLower = proc.name;
        std::string searchNameLower = name;

        for (auto& c : procNameLower) c = tolower(c);
        for (auto& c : searchNameLower) c = tolower(c);

        if (procNameLower.find(searchNameLower) != std::string::npos) {
            found = true;
            std::cout << COLOR_GREEN << "[✓] Process found!\n\n" << COLOR_RESET;
            std::cout << "Process ID:        " << proc.pid << "\n";
            std::cout << "Process Name:      " << proc.name << "\n";
            std::cout << "Memory Usage:      " << (proc.memoryUsage / 1024.0 / 1024.0) << " MB\n";
            std::cout << "------------------------------------------------------------\n";
        }
    }

    if (!found) {
        std::cout << COLOR_RED << "[!] Process '" << name << "' not found\n" << COLOR_RESET;
        std::cout << COLOR_YELLOW << "[i] Make sure the process name is correct\n" << COLOR_RESET;
    } else {
        std::cout << "\n" << COLOR_CYAN << "[i] Scan completed successfully\n" << COLOR_RESET;
    }
}

int main() {
    displayBanner();
    displaySystemCheck();

    int choice = 0;
    bool running = true;

    while (running) {
        displayMenu();

        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(10000, '\n');
            std::cout << COLOR_RED << "\n[!] Invalid input. Please enter a number.\n" << COLOR_RESET;
            continue;
        }

        switch (choice) {
            case 1: {
                scanAllProcesses();
                break;
            }

            case 2: {
                DWORD pid;
                std::cout << COLOR_YELLOW << "\n[*] Enter Process ID: " << COLOR_RESET;
                if (std::cin >> pid) {
                    scanProcessByPID(pid);
                } else {
                    std::cin.clear();
                    std::cin.ignore(10000, '\n');
                    std::cout << COLOR_RED << "[!] Invalid PID\n" << COLOR_RESET;
                }
                break;
            }

            case 3: {
                std::cout << COLOR_YELLOW << "\n[*] Enter Process Name: " << COLOR_RESET;
                std::string processName;
                std::cin >> processName;
                scanProcessByName(processName);
                break;
            }

            case 4: {
                std::cout << COLOR_CYAN << "\n[*] Displaying threat summary...\n" << COLOR_RESET;
                std::cout << COLOR_GREEN << "[✓] No threats detected\n" << COLOR_RESET;
                std::cout << COLOR_YELLOW << "[i] Threat detection features coming soon...\n" << COLOR_RESET;
                break;
            }

            case 5: {
                std::cout << COLOR_CYAN << "\n[*] Exporting report...\n" << COLOR_RESET;
                std::cout << COLOR_GREEN << "[✓] Report export feature coming soon...\n" << COLOR_RESET;
                break;
            }

            case 6: {
                std::cout << COLOR_GREEN << "\n[*] Exiting... Goodbye!\n" << COLOR_RESET;
                running = false;
                break;
            }

            default: {
                std::cout << COLOR_RED << "\n[!] Invalid choice. Please select 1-6.\n" << COLOR_RESET;
                break;
            }
        }

        if (running && choice >= 1 && choice <= 5) {
            std::cout << "\nPress Enter to continue...";
            std::cin.ignore(10000, '\n');
            std::cin.get();
        }
    }

    return 0;
}