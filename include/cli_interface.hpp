#ifndef CLI_INTERFACE_H
#define CLI_INTERFACE_H

#include "../include/memory_scan.hpp"
#include "../include/threat_detection.h"
#include "../include/monitoring.hpp"
#include "../include/report_generator.h"
#include <string>
#include <map>
#include <functional>
#include <memory>

class CLIInterface {
private:
    std::unique_ptr<MemoryScan> scanner;
    std::unique_ptr<ThreatDetection> threatDetector;
    std::unique_ptr<Monitoring> monitor;
    std::unique_ptr<ReportGenerator> reportGen;

    bool isRunning;
    ScanResult lastScanResult;
    std::vector<ThreatIndicator> lastThreats;
    std::vector<MonitoringEvent> lastEvents;

    std::map<std::string, std::function<void(const std::string&)>> commands;

    void cmdScan(const std::string& args);
    void cmdAnalyze(const std::string& args);
    void cmdMonitor(const std::string& args);
    void cmdExport(const std::string& args);
    void cmdStatus(const std::string& args);
    void cmdClear(const std::string& args);
    void cmdHelp(const std::string& args);
    void cmdQuit(const std::string& args);
    void cmdHistory(const std::string& args);
    void cmdYARA(const std::string& args);

    void initializeCommands();
    void displayBanner() const;
    void displayPrompt() const;
    std::string toLower(const std::string& str) const;

public:
    CLIInterface();
    ~CLIInterface();

    void start();
    void processCommand(const std::string& input);

    bool isApplicationRunning() const;
    void stop();
};

#endif