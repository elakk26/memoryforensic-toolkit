#include "../include/Logger.hpp"
#include <iostream>
#include <iomanip>
#include <ctime>
#include <sstream>

std::unique_ptr<Logger> Logger::instance = nullptr;
std::mutex Logger::mutex_;

Logger::Logger() : currentLevel(INFO), consoleOutput(true) {
}

Logger::~Logger() {
    close();
}

Logger& Logger::getInstance() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!instance) {
        instance.reset(new Logger());
    }
    return *instance;
}

void Logger::setLogFile(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);

    if (logFile.is_open()) {
        logFile.close();
    }

    logFilePath = filepath;
    logFile.open(filepath, std::ios::app);

    if (!logFile.is_open()) {
        std::cerr << "Failed to open log file: " << filepath << std::endl;
    }
}

void Logger::setLogLevel(LogLevel level) {
    currentLevel = level;
}

void Logger::setConsoleOutput(bool enable) {
    consoleOutput = enable;
}

std::string Logger::getCurrentTimestamp() const {
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string Logger::levelToString(LogLevel level) const {
    switch (level) {
        case DEBUG: return "DEBUG";
        case INFO: return "INFO";
        case WARNING: return "WARNING";
        case ERROR: return "ERROR";
        case CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

void Logger::writeLog(LogLevel level, const std::string& message) {
    if (level < currentLevel) {
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);

    std::string timestamp = getCurrentTimestamp();
    std::string levelStr = levelToString(level);
    std::string logEntry = "[" + timestamp + "] [" + levelStr + "] " + message;

    // Write to console
    if (consoleOutput) {
        if (level >= ERROR) {
            std::cerr << logEntry << std::endl;
        } else {
            std::cout << logEntry << std::endl;
        }
    }

    // Write to file
    if (logFile.is_open()) {
        logFile << logEntry << std::endl;
    }
}

void Logger::debug(const std::string& message) {
    writeLog(DEBUG, message);
}

void Logger::info(const std::string& message) {
    writeLog(INFO, message);
}

void Logger::warning(const std::string& message) {
    writeLog(WARNING, message);
}

void Logger::error(const std::string& message) {
    writeLog(ERROR, message);
}

void Logger::critical(const std::string& message) {
    writeLog(CRITICAL, message);
}

void Logger::flush() {
    if (logFile.is_open()) {
        logFile.flush();
    }
}

void Logger::close() {
    if (logFile.is_open()) {
        logFile.close();
    }
}