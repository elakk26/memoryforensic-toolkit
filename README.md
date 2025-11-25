# Memory Forensics Analysis Tool with YARA

Advanced memory scanning and threat detection system powered by YARA rule engine.

## Overview

This project implements a comprehensive memory forensics toolkit that combines:
- **Memory Scanning**: Real-time analysis of process memory regions
- **Threat Detection**: Pattern-based and YARA rule-based threat identification
- **Behavioral Monitoring**: Event logging and system monitoring
- **Report Generation**: PDF, Text, and CSV report exports

## Architecture

### Flowchart
```
Start
  ↓
Memory Scan
  ↓
Suspicious? (Decision)
  ├─ Yes → Behavioral Monitoring → Alert
  └─ No → System Safe
  ↓
Exit
```

### Components

1. **Memory Scan** (`memory_scan.h/cpp`)
    - Reads process memory maps
    - Parses memory regions
    - Returns scan results

2. **Threat Detection** (`threat_detection.h/cpp`)
    - Legacy pattern-based detection
    - YARA rule integration
    - Threat level determination

3. **YARA Detection** (`yara_detection.h/cpp`)
    - YARA rule compilation
    - Memory scanning with YARA
    - Rule management

4. **Behavioral Monitoring** (`monitoring.h/cpp`)
    - Event logging
    - Alert generation
    - Real-time monitoring

5. **Report Generator** (`report_generator.h/cpp`)
    - PDF report generation
    - Text report generation
    - CSV report generation

6. **CLI Interface** (`cli_interface.h/cpp`)
    - Interactive command interface
    - User command processing
    - Application control

## YARA Rules

### Rule Categories

1. **Malware Signatures** (`rules/malware_signatures.yar`)
    - Shell execution patterns
    - Network injection detection
    - Process hollowing detection
    - DLL injection patterns
    - Registry modification

2. **Vulnerability Patterns** (`rules/vulnerability_patterns.yar`)
    - Buffer overflow detection
    - Use-after-free patterns
    - SQL injection detection
    - Format string vulnerabilities
    - Integer overflow patterns
    - Null pointer dereference

3. **Suspicious Behavior** (`rules/suspicious_behavior.yar`)
    - Packed code detection
    - Anti-debugging techniques
    - Rootkit patterns
    - Privilege escalation attempts
    - Network beacon detection
    - Suspicious file operations

4. **Code Injection** (`rules/code_injection.yar`)
    - Shellcode pattern detection
    - Return-oriented programming (ROP)
    - Self-modifying code
    - Thread hijacking
    - Heap spray attacks
    - Stack overflow patterns
    - Hook installation

## Installation

### Prerequisites

```bash
# Update system
sudo apt-get update

# Install build tools
sudo apt-get install -y build-essential cmake pkg-config

# Install dependencies
sudo apt-get install -y libharu-dev libpng-dev zlib1g-dev git
```

### Build

```bash
# Make build script executable
chmod +x build.sh

# Run build script (handles YARA installation)
./build.sh
```

The build script will:
1. Check and install CMake and g++
2. Download and compile YARA library
3. Install all dependencies
4. Compile the project
5. Create test executables

### Manual YARA Installation (Alternative)

```bash
# Install YARA development libraries
sudo apt-get install -y libyara-dev

# Or build from source
git clone https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure --with-crypto
make -j$(nproc)
sudo make install
sudo ldconfig
```

## Usage

### Start Application

```bash
./build/memory_forensics
```

### Available Commands

#### Scanning & Analysis
```
scan [PID]    - Perform memory scan (default: current process)
analyze       - Analyze for threats using YARA rules
```

#### Monitoring & Reporting
```
monitor start  - Start behavioral monitoring
monitor stop   - Stop monitoring
monitor log    - Display event log
monitor status - Show monitoring status

export all     - Export all reports (PDF, Text, CSV)
export pdf     - Export PDF report only
export text    - Export text report only
export csv     - Export CSV report only
```

#### YARA Engine Control
```
yara status    - Show YARA engine status
yara enable    - Enable YARA detection
yara disable   - Disable YARA detection
yara reload    - Reload YARA rules
```

#### System Commands
```
status         - Display system status
history        - Show event log history
clear          - Clear screen
help           - Show all commands
quit/exit      - Exit application
```

### Workflow Example

```bash
# 1. Start application
./build/memory_forensics

# 2. Scan current process memory
forensics> scan

# 3. Enable YARA (if not already enabled)
forensics> yara enable

# 4. Analyze for threats
forensics> analyze

# 5. Start monitoring
forensics> monitor start

# 6. Export reports
forensics> export all

# 7. View event log
forensics> history

# 8. Exit
forensics> quit
```

## Running Tests

### Individual Component Tests

```bash
# Test memory scanning
./build/test_memory_scan

# Test threat detection
./build/test_threat_detection

# Test YARA detection
./build/test_yara

# Test report generation
./build/test_report_generator
```

## Project Structure

```
memory_forensics/
├── build.sh                          # Build script with YARA support
├── CMakeLists.txt                    # CMake configuration
├── README.md                         # This file
│
├── src/
│   ├── main.cpp                      # Application entry point
│   ├── memory_scan.cpp               # Memory scanning
│   ├── threat_detection.cpp          # Threat detection with YARA
│   ├── yara_detection.cpp            # YARA engine implementation
│   ├── cli_interface.cpp             # CLI implementation
│   ├── monitoring.cpp                # Behavioral monitoring
│   └── report_generator.cpp          # Report generation
│
├── include/
│   ├── memory_scan.h
│   ├── threat_detection.h
│   ├── yara_detection.h
│   ├── cli_interface.h
│   ├── monitoring.h
│   └── report_generator.h
│
├── rules/
│   ├── malware_signatures.yar        # Malware detection rules
│   ├── vulnerability_patterns.yar    # Vulnerability detection
│   ├── suspicious_behavior.yar       # Suspicious behavior rules
│   └── code_injection.yar            # Code injection detection
│
├── tests/
│   ├── test_memory_scan.cpp
│   ├── test_threat_detection.cpp
│   └── test_yara_detection.cpp
│
├── build/                            # Build artifacts (generated)
│   ├── memory_forensics              # Main executable
│   ├── test_memory_scan
│   ├── test_threat_detection
│   └── test_yara
│
├── reports/                          # Generated reports
│   ├── report_*.txt
│   ├── forensics_report_*.pdf
│   └── threats_*.csv
│
└── yara-src/                         # YARA source (if built from source)
```

## Threat Levels

- **SAFE** (0): No threats detected
- **SUSPICIOUS** (1): Suspicious patterns or behavior detected
- **DANGEROUS** (2): Critical threats detected, immediate action required

## Output Files

### Reports Directory
Generated reports are saved in `./reports/`:
- **Text Reports**: `report_YYYYMMDD_HHMMSS.txt`
- **PDF Reports**: `forensics_report_YYYYMMDD_HHMMSS.pdf`
- **CSV Reports**: `threats_YYYYMMDD_HHMMSS.csv`

## Customizing YARA Rules

Add new YARA rules to the `rules/` directory:

```yara
rule Custom_Threat {
    meta:
        description = "Your rule description"
        severity = "high"
        author = "Your name"
    
    strings:
        $pattern1 = "suspicious_string" nocase
        $pattern2 = { 4D 5A 90 00 } // MZ header
    
    condition:
        all of them
}
```

## Performance Considerations

- Scanning: O(n) where n = number of memory regions
- YARA matching: Depends on rule complexity
- Memory usage: Minimal for small regions, scales with region count
- Report generation: Fast for <1000 threats

## Troubleshooting

### YARA Not Found
```bash
# Check YARA installation
yara --version

# Reinstall YARA
sudo apt-get remove libyara-dev
./build.sh
```

### Build Fails
```bash
# Clean and rebuild
rm -rf build CMakeCache.txt
./build.sh
```

### Rules Not Loading
```bash
# Verify rules directory exists
ls -la rules/

# Check rule syntax
yara -c rules/malware_signatures.yar /dev/null
```

## Security Notes

- Run with appropriate permissions for process access
- YARA rules should be regularly updated
- Monitor for false positives/negatives
- Reports contain sensitive system information

## Future Enhancements

- [ ] Network traffic analysis
- [ ] Process behavior analysis
- [ ] Machine learning threat detection
- [ ] Web UI dashboard
- [ ] Database storage for reports
- [ ] Threat intelligence integration
- [ ] Automated remediation actions
- [ ] Multi-process scanning

## License

This project is provided as-is for security research and educational purposes.

## Contributing

To add new features:
1. Update relevant source files
2. Update headers if needed
3. Create test files
4. Update CMakeLists.txt
5. Test with `./build.sh`

## References

- [YARA Documentation](https://yara.readthedocs.io/)
- [Linux /proc/maps Format](https://man7.org/linux/man-pages/man5/proc.5.html)
- [Memory Forensics Techniques](https://volatility-labs.blogspot.com/)