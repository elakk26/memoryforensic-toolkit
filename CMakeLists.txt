cmake_minimum_required(VERSION 3.10)
project(MemoryForensics VERSION 2.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

set(PROJECT_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(INCLUDE_DIR "${PROJECT_ROOT_DIR}/include")
set(SRC_DIR "${PROJECT_ROOT_DIR}/src")

include_directories(${INCLUDE_DIR})

set(HEADERS
        ${INCLUDE_DIR}/cli_interface.h
        ${INCLUDE_DIR}/logger.h
        ${INCLUDE_DIR}/memory_scan.h
        ${INCLUDE_DIR}/monitoring.h
        ${INCLUDE_DIR}/report_generator.h
        ${INCLUDE_DIR}/threat_detection.h
)

set(SOURCES
        ${SRC_DIR}/main.cpp
        ${SRC_DIR}/cli_interface.cpp
        ${SRC_DIR}/logger.cpp
        ${SRC_DIR}/memory_scan.cpp
        ${SRC_DIR}/monitoring.cpp
        ${SRC_DIR}/report_generator.cpp
        ${SRC_DIR}/threat_detection.cpp
        include/injection_detector.hpp
        src/injection_detector.cpp
        src/injection_detector.cpp
        include/behavioral_monitor.hpp
        src/behavioral_monitor.cpp
        src/report_generator.cpp
)

add_executable(memory_forensics ${SOURCES} ${HEADERS})

target_link_libraries(memory_forensics PRIVATE pthread)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(memory_forensics PRIVATE -g -O0 -DDEBUG)
    message(STATUS "Building in Debug mode")
else()
    target_compile_options(memory_forensics PRIVATE -O2)
    message(STATUS "Building in Release mode")
endif()

set_target_properties(memory_forensics PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

message(STATUS "Memory Forensics Tool Configuration:")
message(STATUS "  Version: 2.0")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Source Directory: ${SRC_DIR}")
message(STATUS "  Include Directory: ${INCLUDE_DIR}")
message(STATUS "  Output: ${CMAKE_BINARY_DIR}/bin/memory_forensics")