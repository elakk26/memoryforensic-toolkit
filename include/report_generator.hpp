#ifndef REPORT_GENERATOR_H
#define REPORT_GENERATOR_H

#include "../include/threat_detection.hpp"
#include "../include/memory_scan.hpp"
#include "../include/monitoring.hpp"
#include <string>
#include <vector>
#include <fstream>

#ifdef _WIN32
    #include <direct.h>
    #include <stdlib.h>
    #define mkdir(path, mode) _mkdir(path)
#else
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <limits.h>
    #include <stdlib.h>
#endif

struct ScanSummary {
    int totalProcesses;
    int suspiciousProcesses;
    int criticalThreats;
    int highThreats;
    int mediumThreats;
    int lowThreats;
    std::time_t scanTime;
    std::string scanDuration;
};

class ReportGenerator {
private:
    std::string outputDir;
    std::string reportFileName;
    std::string currentScanId;
    std::string currentScanPath;
    std::ofstream outFile;

    // HTML generation helpers
    std::string generateHTMLHeader();
    std::string generateHTMLFooter();
    std::string generateCSS();
    std::string generateSummarySection(const ScanSummary& summary);

    // Utility functions
    std::string getTimestampString() const;
    std::string getFormattedTimestamp(std::time_t timestamp) const;

    // Folder management
    void createNewScanFolder();

public:
    ReportGenerator();
    ~ReportGenerator();

    // Configuration
    void setOutputDirectory(const std::string& dir);

    // Report generation
    bool generateTextReport(const ScanResult& scan,
                           const std::vector<ThreatIndicator>& threats,
                           const std::vector<MonitoringEvent>& events);

    bool generatePDFReport(const ScanResult& scan,
                          const std::vector<ThreatIndicator>& threats,
                          const std::vector<MonitoringEvent>& events);

    bool generateCSVReport(const std::vector<ThreatIndicator>& threats);

    bool generateSummaryFile(const ScanResult& scan,
                            const std::vector<ThreatIndicator>& threats);

    // Utility
    std::string getTimestamp();
    std::string getThreatLevelString(ThreatLevel level) const;
    std::string getColorForThreatLevel(ThreatLevel level);

    // Getters
    std::string getLastReportFile() const;
    std::string getOutputDirectory() const;
    std::string getCurrentScanFolder() const;
    std::string getScanId() const;
    std::string getAbsolutePath(const std::string& relativePath) const;
};

#endif // REPORT_GENERATOR_H