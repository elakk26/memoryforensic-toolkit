#ifndef MONITORING_H
#define MONITORING_H

#include <atomic>
#include <ctime>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include "../include/threat_detection.hpp"

enum class EventType {
    MEMORY_CHANGE,
    THREAT_DETECTED,
    SCAN_COMPLETED,
    SYSTEM_EVENT,
    ALERT
};

struct MonitoringEvent {
    EventType type;
    std::string description;
    std::time_t timestamp;
    ThreatLevel severity;
    std::string details;
};

class Monitoring {
private:
    std::vector<MonitoringEvent> events;
    std::thread monitoringThread;
    std::atomic<bool> isMonitoring;
    std::mutex eventMutex;

    int monitorInterval;
    int targetPid;

    void monitoringLoop();
    void addEvent(const MonitoringEvent& event);
    std::string eventTypeToString(EventType type) const;
    std::string threatLevelToString(ThreatLevel level) const;

public:
    Monitoring();
    ~Monitoring();

    bool startMonitoring(int pid = 0, int intervalSeconds = 5);
    void stopMonitoring();
    bool isActive() const;

    void setMonitorInterval(int seconds);
    void setTargetProcess(int pid);

    std::vector<MonitoringEvent> getEvents() const;
    int getEventCount() const;
    void clearEvents();

    void displayEvents() const;
    void displayRecentEvents(int count) const;
    void displayMonitoringStatus() const;
};

#endif