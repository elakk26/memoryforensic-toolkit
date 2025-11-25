#include "../include/cli_interface.hpp"
#include "../include/yara_detection.hpp"
#include "../include/logger.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <iomanip>

CLIInterface::CLIInterface() : isRunning(false) {
    initializeCommands();
}

CLIInterface::~CLIInterface() {
    stop();
}

void CLIInterface::initializeCommands() {
    commands["scan"] = [this](const std::string& args) { cmdScan(args); };
    commands["analyze"] = [this](const std::string& args) { cmdAnalyze(args); };
    commands["monitor"] = [this](const std::string& args) { cmdMonitor(args); };
    commands["export"] = [this](const std::string& args) { cmdExport(args); };
    commands["status"] = [this](const std::string& args) { cmdStatus(args); };
    commands["clear"] = [this](const std::string& args) { cmdClear(args); };
    commands["help"] = [this](const std::string& args) { cmdHelp(args); };
    commands["quit"] = [this](const std::string& args) { cmdQuit(args); };
    commands["exit"] = [this](const std::string& args) { cmdQuit(args); };
    commands["history"] = [this](const std::string& args) { cmdHistory(args); };
}

void CLIInterface::displayBanner() const {
    std::cout << R"(
╔═══════════════════════════════════════════════════════════╗
║        Memory Forensics Tool - Interactive Mode          ║
║                  YARA-Powered Analysis                    ║
╚═══════════════════════════════════════════════════════════╝
)" << std::endl;
}

void CLIInterface::displayPrompt() const {
    std::cout << "\nforensics> ";
}

std::string CLIInterface::toLower(const std::string& str) const {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

void CLIInterface::run() {
    displayBanner();
    isRunning = true;

    std::cout << "Type 'help' for available commands\n" << std::endl;

    while (isRunning) {
        displayPrompt();

        std::string input;
        std::getline(std::cin, input);

        if (std::cin.eof() || !std::cin.good()) {
            break;
        }

        if (!input.empty()) {
            processCommand(input);
        }
    }
}

void CLIInterface::start() {
    run();
}

void CLIInterface::processCommand(const std::string& input) {
    std::istringstream iss(input);
    std::string command, args;

    iss >> command;
    std::getline(iss, args);

    // Trim leading whitespace from args
    size_t start = args.find_first_not_of(" \t");
    if (start != std::string::npos) {
        args = args.substr(start);
    } else {
        args = "";
    }

    command = toLower(command);

    auto it = commands.find(command);
    if (it != commands.end()) {
        try {
            it->second(args);
        } catch (const std::exception& e) {
            std::cerr << "Error executing command: " << e.what() << std::endl;
        }
    } else {
        std::cout << "Unknown command: " << command << std::endl;
        std::cout << "Type 'help' for available commands" << std::endl;
    }
}

void CLIInterface::cmdScan(const std::string& args) {
    std::cout << "\n=== Memory Scan ===" << std::endl;

    int pid = 0;
    if (!args.empty()) {
        pid = std::atoi(args.c_str());
    }

    lastScanResult = scanner.performScan(pid);
    scanner.displayScanResults();

    std::cout << "\nScan completed. Use 'analyze' to detect threats." << std::endl;
}

void CLIInterface::cmdAnalyze(const std::string& args) {
    if (lastScanResult.totalRegions == 0) {
        std::cout << "No scan results available. Run 'scan' first." << std::endl;
        return;
    }

    std::cout << "\n=== Threat Analysis ===" << std::endl;

    ThreatLevel level = threatDetector.analyzeScanResults(lastScanResult);
    lastThreats = threatDetector.getThreats();

    threatDetector.displayThreats();
    threatDetector.displaySummary();
}

void CLIInterface::cmdMonitor(const std::string& args) {
    std::cout << "\n=== Behavioral Monitoring ===" << std::endl;

    if (args == "start") {
        monitor.startMonitoring(5);
        std::cout << "Monitoring started with 5-second interval" << std::endl;
    } else if (args == "stop") {
        monitor.stopMonitoring();
        std::cout << "Monitoring stopped" << std::endl;
    } else if (args == "status") {
        monitor.displayMonitoringStatus();
    } else {
        std::cout << "Usage: monitor [start|stop|status]" << std::endl;
    }
}

void CLIInterface::cmdExport(const std::string& args) {
    if (lastScanResult.totalRegions == 0) {
        std::cout << "No scan results to export. Run 'scan' first." << std::endl;
        return;
    }

    std::cout << "\n=== Exporting Report ===" << std::endl;
    std::cout << "Scan Folder: " << reportGen.getCurrentScanFolder() << std::endl;

    auto events = monitor.getEventLog();

    std::string format = args.empty() ? "text" : toLower(args);

    bool success = false;
    if (format == "pdf") {
        success = reportGen.generatePDFReport(lastScanResult, lastThreats, events);
        reportGen.generateCSVReport(lastThreats);
        reportGen.generateSummaryFile(lastScanResult, lastThreats);
    } else if (format == "csv") {
        success = reportGen.generateCSVReport(lastThreats);
    } else if (format == "all") {
        // Generate all formats
        reportGen.generateTextReport(lastScanResult, lastThreats, events);
        reportGen.generatePDFReport(lastScanResult, lastThreats, events);
        reportGen.generateCSVReport(lastThreats);
        reportGen.generateSummaryFile(lastScanResult, lastThreats);
        success = true;
    } else {
        success = reportGen.generateTextReport(lastScanResult, lastThreats, events);
        reportGen.generateCSVReport(lastThreats);
        reportGen.generateSummaryFile(lastScanResult, lastThreats);
    }

    if (success) {
        std::cout << "\n✓ Reports exported successfully!" << std::endl;
        std::cout << "📁 All files saved to: " << reportGen.getCurrentScanFolder() << std::endl;
        std::cout << "\nGenerated files:" << std::endl;
        std::cout << "  - forensics_report.txt (detailed report)" << std::endl;
        std::cout << "  - forensics_report.html (web view)" << std::endl;
        if (format == "pdf" || format == "all") {
            std::cout << "  - forensics_report.pdf (if wkhtmltopdf installed)" << std::endl;
        }
        std::cout << "  - threats.csv (threat data)" << std::endl;
        std::cout << "  - scan_summary.txt (quick overview)" << std::endl;
    } else {
        std::cout << "Failed to export some reports" << std::endl;
    }
}

void CLIInterface::cmdStatus(const std::string& args) {
    std::cout << "\n=== System Status ===" << std::endl;
    std::cout << "Last Scan: " << lastScanResult.totalRegions << " regions" << std::endl;
    std::cout << "Threats Detected: " << lastThreats.size() << std::endl;
    std::cout << "Monitoring: " << (monitor.isCurrentlyMonitoring() ? "Active" : "Inactive") << std::endl;
    std::cout << "Events Logged: " << monitor.getEventCount() << std::endl;
}

void CLIInterface::cmdClear(const std::string& args) {
    #ifdef _WIN32
        system("cls");
    #else
        system("clear");
    #endif
    displayBanner();
}

void CLIInterface::cmdHelp(const std::string& args) {
    std::cout << "\n=== Available Commands ===" << std::endl;
    std::cout << std::left;
    std::cout << std::setw(20) << "scan [pid]" << "Perform memory scan (optional: specific PID)" << std::endl;
    std::cout << std::setw(20) << "analyze" << "Analyze scan results with YARA rules" << std::endl;
    std::cout << std::setw(20) << "monitor [action]" << "Control behavioral monitoring (start/stop/status)" << std::endl;
    std::cout << std::setw(20) << "export [format]" << "Export report (text/pdf/csv)" << std::endl;
    std::cout << std::setw(20) << "status" << "Show current system status" << std::endl;
    std::cout << std::setw(20) << "clear" << "Clear the screen" << std::endl;
    std::cout << std::setw(20) << "history" << "Show command history" << std::endl;
    std::cout << std::setw(20) << "help" << "Show this help message" << std::endl;
    std::cout << std::setw(20) << "quit/exit" << "Exit the application" << std::endl;
}

void CLIInterface::cmdQuit(const std::string& args) {
    std::cout << "\nShutting down..." << std::endl;
    isRunning = false;
}

void CLIInterface::cmdHistory(const std::string& args) {
    std::cout << "\n=== Command History ===" << std::endl;
    std::cout << "Command history feature not yet implemented" << std::endl;
}

bool CLIInterface::isApplicationRunning() const {
    return isRunning;
}

void CLIInterface::stop() {
    isRunning = false;
    monitor.stopMonitoring();
}