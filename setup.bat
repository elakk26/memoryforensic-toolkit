@echo off
echo ==========================================
echo Memory Forensics Tool - YARA Build
echo ==========================================

REM Check if YARA is installed
where yara >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: YARA not found in PATH
    echo Please install YARA first:
    echo   1. Download from: https://github.com/VirusTotal/yara/releases
    echo   2. Or install via vcpkg: vcpkg install yara
    echo   3. Or install via MSYS2: pacman -S mingw-w64-x86_64-yara
    pause
    exit /b 1
)

echo YARA found: OK

REM Create directories
if not exist build mkdir build
if not exist rules mkdir rules
if not exist reports mkdir reports
if not exist logs mkdir logs

echo.
echo Copying YARA rules...
if exist rules\*.yar (
    xcopy /Y /Q rules\*.yar build\rules\ >nul 2>&1
    echo YARA rules copied
) else (
    echo WARNING: No YARA rules found in rules directory
    echo Please ensure you have .yar files in the rules folder
)

echo.
echo Compiling with YARA support...

REM Compile the program
g++ -std=c++17 -Iinclude ^
    -DUSE_YARA ^
    src/main.cpp ^
    src/cli_interface.cpp ^
    src/memory_scan.cpp ^
    src/threat_detection.cpp ^
    src/yara_detection.cpp ^
    src/monitoring.cpp ^
    src/report_generator.cpp ^
    src/logger.cpp ^
    -o build/memory_forensics.exe ^
    -lyara ^
    -lws2_32 ^
    -static-libgcc ^
    -static-libstdc++

if %errorlevel% neq 0 (
    echo.
    echo ==========================================
    echo Build FAILED!
    echo ==========================================
    echo.
    echo Common issues:
    echo   1. YARA library not found - install libyara-dev or yara-devel
    echo   2. Missing compiler - install MinGW-w64
    echo   3. Wrong library path - check YARA installation
    echo.
    pause
    exit /b 1
)

echo.
echo ==========================================
echo Build successful with YARA!
echo ==========================================
echo Executable: build\memory_forensics.exe
echo YARA Rules: build\rules\
echo.

REM === Run the scanner and save output ===
echo Running memory scanner...
build\memory_forensics.exe -s > logs\scan_output.txt

if %errorlevel% neq 0 (
    echo [!] Scan failed to run
    pause
    exit /b 1
)

REM === Summing memory usage from the output ===
echo.
echo Calculating total memory usage...

setlocal enabledelayedexpansion
set "total=0"

for /f "tokens=3 delims=:" %%A in ('findstr /c:"Memory Usage:" logs\scan_output.txt') do (
    set "line=%%A"
    set "line=!line:MB=!"
    set "line=!line: =!"
    for /f %%B in ('powershell -nologo -command "!total! + !line!"') do set total=%%B
)

echo.
echo ==========================================
echo [✓] Scan completed
echo [✓] Total Chrome Memory Usage: %total% MB
echo ==========================================

pause
