#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <memory>

enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

class Logger {
private:
    static std::unique_ptr<Logger> instance;
    static std::mutex mutex_;

    std::ofstream logFile;
    LogLevel currentLevel;
    std::string logFilePath;
    bool consoleOutput;

    Logger();

    std::string getCurrentTimestamp() const;
    std::string levelToString(LogLevel level) const;
    void writeLog(LogLevel level, const std::string& message);

public:
    ~Logger();

    // Singleton pattern
    static Logger& getInstance();

    // Configuration
    void setLogFile(const std::string& filepath);
    void setLogLevel(LogLevel level);
    void setConsoleOutput(bool enable);

    // Logging methods
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);

    // Utility
    void flush();
    void close();

    // Delete copy constructor and assignment operator
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
};

#endif // LOGGER_H