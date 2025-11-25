#include "../include/report_generator.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>

#ifdef _WIN32
    #include <windows.h>
    #define popen _popen
    #define pclose _pclose
#else
    #include <unistd.h>
#endif

ReportGenerator::ReportGenerator() : outputDir("reports"), currentScanId("") {
    // Initialize scan session
    createNewScanFolder();
}

ReportGenerator::~ReportGenerator() {
    if (outFile.is_open()) {
        outFile.close();
    }
}

void ReportGenerator::setOutputDirectory(const std::string& dir) {
    outputDir = dir;
}

std::string ReportGenerator::getTimestampString() const {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y%m%d_%H%M%S");
    return oss.str();
}

void ReportGenerator::createNewScanFolder() {
    currentScanId = "scan_" + getTimestampString();
    currentScanPath = outputDir + "/" + currentScanId;

    // Get absolute path
    char absolutePath[4096];
    #ifdef _WIN32
        // Create reports directory first
        _mkdir(outputDir.c_str());
        _mkdir(currentScanPath.c_str());

        // Get full path
        _fullpath(absolutePath, currentScanPath.c_str(), sizeof(absolutePath));
    #else
        // Create reports directory first
        mkdir(outputDir.c_str(), 0755);
        mkdir(currentScanPath.c_str(), 0755);

        // Get full path
        realpath(currentScanPath.c_str(), absolutePath);
    #endif

    std::cout << "\n╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║           SCAN FOLDER CREATED                          ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << "\n Scan ID: " << currentScanId << std::endl;
    std::cout << " Relative Path: " << currentScanPath << std::endl;
    std::cout << "  Full Path: " << absolutePath << std::endl;
    std::cout << "\nAll reports will be saved to this folder." << std::endl;
    std::cout << "════════════════════════════════════════════════════════\n" << std::endl;

    // Store the absolute path for later use
    currentScanPath = std::string(absolutePath);
}

std::string ReportGenerator::getCurrentScanFolder() const {
    return currentScanPath;
}

std::string ReportGenerator::getScanId() const {
    return currentScanId;
}

std::string ReportGenerator::getAbsolutePath(const std::string& relativePath) const {
    char absolutePath[4096];

    #ifdef _WIN32
        _fullpath(absolutePath, relativePath.c_str(), sizeof(absolutePath));
    #else
        if (realpath(relativePath.c_str(), absolutePath) == nullptr) {
            return relativePath; // Return relative if absolute fails
        }
    #endif

    return std::string(absolutePath);
}

std::string ReportGenerator::getTimestamp() {
    std::time_t now = std::time(nullptr);
    char buf[100];
    struct std::tm* timeinfo = std::localtime(&now);
    if (timeinfo != nullptr) {
        std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", timeinfo);
    } else {
        return "ERROR: Unable to get timestamp";
    }
    return std::string(buf);
}

std::string ReportGenerator::getThreatLevelString(ThreatLevel level) const {
    switch(level) {
        case SAFE: return "SAFE";
        case SUSPICIOUS: return "SUSPICIOUS";
        case DANGEROUS: return "DANGEROUS";
        default: return "UNKNOWN";
    }
}

std::string ReportGenerator::getFormattedTimestamp(std::time_t timestamp) const {
    auto tm = *std::localtime(&timestamp);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string ReportGenerator::getColorForThreatLevel(ThreatLevel level) {
    switch(level) {
        case SAFE: return "#28a745";
        case SUSPICIOUS: return "#ffc107";
        case DANGEROUS: return "#dc3545";
        default: return "#6c757d";
    }
}

std::string ReportGenerator::generateCSS() {
    return R"(
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 20px;
                color: #333;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background: white;
                border-radius: 15px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                overflow: hidden;
            }
            .header {
                background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
                color: white;
                padding: 40px;
                text-align: center;
            }
            .header h1 {
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            .header p {
                font-size: 1.1em;
                opacity: 0.9;
            }
            .content {
                padding: 40px;
            }
            .summary-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 40px;
            }
            .summary-card {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 25px;
                border-radius: 10px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
                transition: transform 0.3s;
            }
            .summary-card:hover {
                transform: translateY(-5px);
            }
            .summary-card h3 {
                font-size: 0.9em;
                opacity: 0.9;
                margin-bottom: 10px;
            }
            .summary-card .value {
                font-size: 2.5em;
                font-weight: bold;
            }
            .section {
                margin-bottom: 40px;
            }
            .section h2 {
                color: #2a5298;
                margin-bottom: 20px;
                padding-bottom: 10px;
                border-bottom: 3px solid #667eea;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                background: white;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                border-radius: 8px;
                overflow: hidden;
            }
            thead {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
            }
            th, td {
                padding: 15px;
                text-align: left;
                border-bottom: 1px solid #dee2e6;
            }
            tbody tr:nth-child(even) {
                background: #f8f9fa;
            }
            tbody tr:hover {
                background: #e9ecef;
            }
            .badge {
                display: inline-block;
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.85em;
                font-weight: bold;
                color: white;
            }
            .threat-list {
                list-style: none;
            }
            .threat-item {
                background: #f8f9fa;
                margin-bottom: 15px;
                padding: 20px;
                border-left: 4px solid #667eea;
                border-radius: 5px;
            }
            .threat-item h4 {
                margin-bottom: 10px;
                color: #2a5298;
            }
            .threat-item p {
                color: #6c757d;
                margin-bottom: 5px;
            }
            .footer {
                background: #f8f9fa;
                padding: 20px;
                text-align: center;
                color: #6c757d;
                border-top: 1px solid #dee2e6;
            }
            @media print {
                body { background: white; padding: 0; }
                .container { box-shadow: none; }
            }
        </style>
    )";
}

std::string ReportGenerator::generateHTMLHeader() {
    std::ostringstream oss;
    oss << R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Memory Forensics Report</title>
)" << generateCSS() << R"(
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Memory Forensics Analysis Report</h1>
            <p>Generated: )" << getTimestamp() << R"(</p>
        </div>
        <div class="content">
)";
    return oss.str();
}

std::string ReportGenerator::generateHTMLFooter() {
    return R"(
        </div>
        <div class="footer">
            <p>Memory Forensics Tool v2.0 with YARA Integration | Advanced Threat Detection</p>
        </div>
    </div>
</body>
</html>
)";
}

std::string ReportGenerator::generateSummarySection(const ScanSummary& summary) {
    std::ostringstream oss;

    oss << R"(<div class="section">
        <h2>Scan Summary</h2>
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Total Regions</h3>
                <div class="value">)" << summary.totalProcesses << R"(</div>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
                <h3>Suspicious</h3>
                <div class="value">)" << summary.suspiciousProcesses << R"(</div>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #fa709a 0%, #fee140 100%);">
                <h3>Dangerous Threats</h3>
                <div class="value">)" << summary.criticalThreats << R"(</div>
            </div>
            <div class="summary-card" style="background: linear-gradient(135deg, #30cfd0 0%, #330867 100%);">
                <h3>Safe Regions</h3>
                <div class="value">)" << summary.lowThreats << R"(</div>
            </div>
        </div>
        <p><strong>Scan Time:</strong> )" << getFormattedTimestamp(summary.scanTime) << R"(</p>
        <p><strong>Duration:</strong> )" << summary.scanDuration << R"(</p>
    </div>)";

    return oss.str();
}

bool ReportGenerator::generateTextReport(const ScanResult& scan,
                                         const std::vector<ThreatIndicator>& threats,
                                         const std::vector<MonitoringEvent>& events) {
    reportFileName = currentScanPath + "/forensics_report.txt";

    std::ofstream report(reportFileName);
    if (!report.is_open()) {
        std::cerr << "Failed to create report file: " << reportFileName << std::endl;
        return false;
    }

    // Header
    report << "========================================" << std::endl;
    report << "  MEMORY FORENSICS ANALYSIS REPORT" << std::endl;
    report << "========================================" << std::endl;
    report << "Scan ID: " << currentScanId << std::endl;
    report << "Generated: " << getTimestamp() << std::endl;
    report << "Tool Version: 2.0 with YARA" << std::endl;
    report << "========================================" << std::endl << std::endl;

    // Scan Summary
    report << "SCAN SUMMARY" << std::endl;
    report << "------------" << std::endl;
    report << "Scan Timestamp: " << getFormattedTimestamp(scan.scanTimestamp) << std::endl;
    report << "Status: " << scan.scanStatus << std::endl;
    report << "Total Memory Regions: " << scan.totalRegions << std::endl;
    report << std::endl;

    // Memory Regions
    report << "MEMORY REGIONS ANALYZED" << std::endl;
    report << "-----------------------" << std::endl;
    report << std::left;
    report << std::setw(18) << "Address"
           << std::setw(12) << "Size"
           << std::setw(12) << "Permissions"
           << "Module" << std::endl;
    report << std::string(80, '-') << std::endl;

    for (const auto& region : scan.regions) {
        report << std::setw(18) << region.address
               << std::setw(12) << region.size
               << std::setw(12) << region.permissions
               << region.module << std::endl;
    }
    report << std::endl;

    // Threats
    report << "DETECTED THREATS" << std::endl;
    report << "----------------" << std::endl;
    report << "Total Threats: " << threats.size() << std::endl << std::endl;

    if (threats.empty()) {
        report << "No threats detected." << std::endl;
    } else {
        int dangerous = 0, suspicious = 0, safe = 0;
        for (const auto& threat : threats) {
            switch (threat.level) {
                case DANGEROUS: dangerous++; break;
                case SUSPICIOUS: suspicious++; break;
                case SAFE: safe++; break;
            }
        }

        report << "Threat Level Breakdown:" << std::endl;
        report << "  DANGEROUS:  " << dangerous << std::endl;
        report << "  SUSPICIOUS: " << suspicious << std::endl;
        report << "  SAFE:       " << safe << std::endl << std::endl;

        report << "Detailed Threat Information:" << std::endl;
        report << std::string(80, '-') << std::endl;

        for (size_t i = 0; i < threats.size(); ++i) {
            const auto& threat = threats[i];
            report << "\n[" << (i + 1) << "] " << threat.name << std::endl;
            report << "    Level: " << getThreatLevelString(threat.level) << std::endl;
            report << "    Description: " << threat.description << std::endl;
            report << "    Affected Region: " << threat.affectedRegion << std::endl;
            report << "    Detection Time: " << getFormattedTimestamp(threat.detectionTime) << std::endl;
        }
    }
    report << std::endl;

    // Monitoring Events
    if (!events.empty()) {
        report << "MONITORING EVENTS" << std::endl;
        report << "-----------------" << std::endl;
        report << "Total Events: " << events.size() << std::endl << std::endl;

        for (const auto& event : events) {
            report << "[" << getFormattedTimestamp(event.timestamp) << "] ";
            report << event.eventType << " - " << event.description << std::endl;
            if (!event.processInfo.empty()) {
                report << "  Process: " << event.processInfo << std::endl;
            }
        }
        report << std::endl;
    }

    // Footer
    report << "========================================" << std::endl;
    report << "End of Report" << std::endl;
    report << "========================================" << std::endl;

    report.close();

    std::cout << "✓ Text report generated: " << reportFileName << std::endl;
    return true;
}

bool ReportGenerator::generatePDFReport(const ScanResult& scan,
                                        const std::vector<ThreatIndicator>& threats,
                                        const std::vector<MonitoringEvent>& events) {
    std::cout << "\n=== PDF Report Generation ===" << std::endl;

    // Generate files in the scan-specific folder
    std::string htmlFile = currentScanPath + "/forensics_report.html";
    std::string pdfFile = currentScanPath + "/forensics_report.pdf";

    // Generate HTML content
    std::ofstream html(htmlFile);
    if (!html.is_open()) {
        std::cerr << "Failed to create HTML file in scan folder" << std::endl;
        return false;
    }

    html << generateHTMLHeader();

    // Create summary
    ScanSummary summary;
    summary.totalProcesses = scan.totalRegions;
    summary.suspiciousProcesses = 0;
    summary.criticalThreats = 0;
    summary.lowThreats = 0;
    summary.scanTime = scan.scanTimestamp;
    summary.scanDuration = "N/A";

    for (const auto& threat : threats) {
        if (threat.level == DANGEROUS) summary.criticalThreats++;
        else if (threat.level == SUSPICIOUS) summary.suspiciousProcesses++;
        else summary.lowThreats++;
    }

    html << generateSummarySection(summary);

    // Memory regions table
    html << R"(<div class="section">
        <h2>💾 Memory Regions</h2>
        <table>
            <thead>
                <tr>
                    <th>Address</th>
                    <th>Size</th>
                    <th>Permissions</th>
                    <th>Module</th>
                </tr>
            </thead>
            <tbody>
)";

    for (const auto& region : scan.regions) {
        html << "<tr>"
             << "<td>" << region.address << "</td>"
             << "<td>" << region.size << "</td>"
             << "<td>" << region.permissions << "</td>"
             << "<td>" << region.module << "</td>"
             << "</tr>";
    }

    html << R"(            </tbody>
        </table>
    </div>)";

    // Threats section
    html << R"(<div class="section">
        <h2> Detected Threats</h2>
        <ul class="threat-list">
)";

    for (const auto& threat : threats) {
        html << R"(<li class="threat-item">
            <h4>)" << threat.name << R"( <span class="badge" style="background-color: )"
             << getColorForThreatLevel(threat.level) << R"(">)"
             << getThreatLevelString(threat.level) << R"(</span></h4>
            <p><strong>Description:</strong> )" << threat.description << R"(</p>
            <p><strong>Affected Region:</strong> )" << threat.affectedRegion << R"(</p>
            <p><strong>Detection Time:</strong> )" << getFormattedTimestamp(threat.detectionTime) << R"(</p>
        </li>)";
    }

    html << R"(        </ul>
    </div>)";

    html << generateHTMLFooter();
    html.close();

    std::cout << "✓ HTML report created: " << htmlFile << std::endl;

    // Try to convert HTML to PDF using wkhtmltopdf
    std::cout << "Attempting to convert HTML to PDF..." << std::endl;

    #ifdef _WIN32
    std::string command = "wkhtmltopdf \"" + htmlFile + "\" \"" + pdfFile + "\" 2>nul";
    #else
    std::string command = "wkhtmltopdf \"" + htmlFile + "\" \"" + pdfFile + "\" 2>/dev/null";
    #endif

    int result = system(command.c_str());

    if (result == 0) {
        std::cout << "✓ PDF report generated: " << pdfFile << std::endl;
        reportFileName = pdfFile;

        // Keep both HTML and PDF in the scan folder
        std::cout << "✓ HTML report also available: " << htmlFile << std::endl;
        return true;
    } else {
        std::cerr << "⚠ wkhtmltopdf not found or failed" << std::endl;
        std::cerr << "The HTML report is available at: " << htmlFile << std::endl;
        std::cerr << "\nTo generate PDFs, please install wkhtmltopdf:" << std::endl;
        std::cerr << "  Windows: Download from https://wkhtmltopdf.org/downloads.html" << std::endl;
        std::cerr << "  Linux: sudo apt-get install wkhtmltopdf" << std::endl;
        std::cerr << "\nAlternatively, open the HTML file in a browser and print to PDF." << std::endl;

        reportFileName = htmlFile;
        return false;
    }
}

bool ReportGenerator::generateCSVReport(const std::vector<ThreatIndicator>& threats) {
    reportFileName = currentScanPath + "/threats.csv";

    std::ofstream csv(reportFileName);
    if (!csv.is_open()) {
        std::cerr << "Failed to create CSV file: " << reportFileName << std::endl;
        return false;
    }

    // CSV Header
    csv << "Threat Name,Level,Description,Affected Region,Detection Time" << std::endl;

    // Data rows
    for (const auto& threat : threats) {
        csv << "\"" << threat.name << "\",";
        csv << "\"" << getThreatLevelString(threat.level) << "\",";
        csv << "\"" << threat.description << "\",";
        csv << "\"" << threat.affectedRegion << "\",";
        csv << "\"" << getFormattedTimestamp(threat.detectionTime) << "\"";
        csv << std::endl;
    }

    csv.close();

    std::cout << "✓ CSV report generated: " << reportFileName << std::endl;
    return true;
}

bool ReportGenerator::generateSummaryFile(const ScanResult& scan,
                                          const std::vector<ThreatIndicator>& threats) {
    std::string summaryFile = currentScanPath + "/scan_summary.txt";

    std::ofstream summary(summaryFile);
    if (!summary.is_open()) {
        return false;
    }

    summary << "SCAN SUMMARY" << std::endl;
    summary << "============" << std::endl;
    summary << "Scan ID: " << currentScanId << std::endl;
    summary << "Timestamp: " << getTimestamp() << std::endl;
    summary << "Total Regions: " << scan.totalRegions << std::endl;
    summary << "Total Threats: " << threats.size() << std::endl;

    int dangerous = 0, suspicious = 0, safe = 0;
    for (const auto& threat : threats) {
        switch (threat.level) {
            case DANGEROUS: dangerous++; break;
            case SUSPICIOUS: suspicious++; break;
            case SAFE: safe++; break;
        }
    }

    summary << "\nThreat Breakdown:" << std::endl;
    summary << "  Dangerous: " << dangerous << std::endl;
    summary << "  Suspicious: " << suspicious << std::endl;
    summary << "  Safe: " << safe << std::endl;

    summary.close();

    std::cout << "✓ Summary file generated: " << summaryFile << std::endl;
    return true;
}

std::string ReportGenerator::getLastReportFile() const {
    return reportFileName;
}

std::string ReportGenerator::getOutputDirectory() const {
    return outputDir;
}