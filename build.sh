#!/bin/bash

# Memory Forensics Tool with YARA - Build & Setup Script
# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Main banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  Memory Forensics Tool with YARA - Build Setup v2.0       ║"
echo "║  Advanced Memory Scanning & Threat Detection              ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root for some operations
if [[ $EUID -ne 0 ]]; then
    print_warning "Some operations may require sudo. You will be prompted when needed."
fi

# ============================================================
# 1. CHECK AND INSTALL PREREQUISITES
# ============================================================
print_status "Checking prerequisites..."

# Check for CMake
if ! command -v cmake &> /dev/null; then
    print_warning "CMake not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y cmake
    print_success "CMake installed"
else
    print_success "CMake found"
fi

# Check for g++
if ! command -v g++ &> /dev/null; then
    print_warning "g++ not found. Installing..."
    sudo apt-get install -y build-essential
    print_success "g++ installed"
else
    print_success "g++ found"
fi

# Check for pkg-config
if ! command -v pkg-config &> /dev/null; then
    print_warning "pkg-config not found. Installing..."
    sudo apt-get install -y pkg-config
    print_success "pkg-config installed"
else
    print_success "pkg-config found"
fi

# ============================================================
# 2. INSTALL LIBRARY DEPENDENCIES
# ============================================================
print_status "Installing library dependencies..."

# PDF library dependencies
print_status "Installing PDF library dependencies..."
sudo apt-get install -y libharu-dev libpng-dev zlib1g-dev

# Git (for YARA repository if needed)
if ! command -v git &> /dev/null; then
    print_warning "Git not found. Installing..."
    sudo apt-get install -y git
else
    print_success "Git found"
fi

print_success "Library dependencies installed"

# ============================================================
# 3. INSTALL YARA
# ============================================================
print_status "Checking YARA installation..."

if ! command -v yara &> /dev/null; then
    print_warning "YARA not found. Installing YARA library..."

    # Check if YARA source already exists
    if [ ! -d "yara-src" ]; then
        print_status "Downloading YARA source code..."
        mkdir -p yara-src
        cd yara-src

        # Clone YARA repository or download stable version
        git clone https://github.com/VirusTotal/yara.git . 2>/dev/null || {
            print_warning "Git clone failed, downloading tarball instead..."
            cd ..
            rm -rf yara-src
            mkdir yara-src
            cd yara-src
            wget https://github.com/VirusTotal/yara/archive/refs/tags/v4.3.2.tar.gz -O yara.tar.gz
            tar -xzf yara.tar.gz --strip-components=1
            rm yara.tar.gz
        }
    else
        cd yara-src
    fi

    print_status "Configuring and building YARA..."

    # Install build dependencies for YARA
    sudo apt-get install -y automake libtool make

    # Bootstrap if Makefile doesn't exist
    if [ ! -f "Makefile" ]; then
        ./bootstrap.sh 2>/dev/null || true
    fi

    ./configure --with-crypto
    make -j$(nproc)

    print_status "Installing YARA..."
    sudo make install

    # Update library cache
    sudo ldconfig

    cd ..
    print_success "YARA installed successfully"
else
    print_success "YARA already installed"
fi

# Verify YARA installation
if pkg-config --exists yara; then
    print_success "YARA pkg-config verified"
    YARA_VERSION=$(yara --version 2>/dev/null | head -n1)
    print_success "YARA Version: $YARA_VERSION"
else
    print_warning "YARA pkg-config not found, but binary exists"
fi

# ============================================================
# 4. CREATE PROJECT STRUCTURE
# ============================================================
print_status "Creating project directory structure..."

# Create necessary directories
mkdir -p build
mkdir -p src
mkdir -p include
mkdir -p rules
mkdir -p reports
mkdir -p tests

print_success "Project directories created"

# ============================================================
# 5. CREATE YARA RULES DIRECTORY AND SAMPLE RULES
# ============================================================
print_status "Setting up YARA rules directory..."

if [ ! -d "rules" ]; then
    mkdir -p rules
fi

# Check if rules already exist
if [ ! -f "rules/malware_signatures.yar" ]; then
    print_warning "YARA rules not found. Creating placeholder rules..."

    # Create placeholder for rules (user should populate)
    echo "// YARA rules will be populated here" > rules/placeholder.yar
    print_warning "Please add YARA rule files to the 'rules' directory"
fi

print_success "YARA rules directory ready"

# ============================================================
# 6. BUILD PROJECT
# ============================================================
print_status "Building Memory Forensics Tool with YARA..."

cd build

# Clean previous build if it exists
if [ -f "CMakeCache.txt" ]; then
    print_status "Cleaning previous build..."
    rm -rf CMakeCache.txt cmake_install.cmake Makefile CMakeFiles
fi

# Run CMake
print_status "Running CMake configuration..."
cmake ..

if [ $? -ne 0 ]; then
    print_error "CMake configuration failed!"
    print_error "Make sure all dependencies are installed properly"
    exit 1
fi

# Run Make
print_status "Compiling project..."
make -j$(nproc)

if [ $? -ne 0 ]; then
    print_error "Build failed!"
    exit 1
fi

cd ..

print_success "Build completed successfully!"

# ============================================================
# 7. VERIFY BUILD
# ============================================================
print_status "Verifying build..."

if [ -f "build/memory_forensics" ]; then
    print_success "Main executable created: build/memory_forensics"
else
    print_error "Main executable not found"
    exit 1
fi

# List test executables
if [ -f "build/test_memory_scan" ]; then
    print_success "Test executables created"
fi

# ============================================================
# 8. DISPLAY BUILD SUMMARY
# ============================================================
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            BUILD COMPLETED SUCCESSFULLY                   ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

print_success "Memory Forensics Tool with YARA built successfully!"
echo ""
echo -e "${BLUE}═══ NEXT STEPS ═══${NC}"
echo ""
echo -e "${YELLOW}1. Add YARA Rules:${NC}"
echo "   Place your YARA rule files in the 'rules/' directory"
echo "   Supported formats: .yar, .yara"
echo ""
echo -e "${YELLOW}2. Run Main Application:${NC}"
echo "   ${GREEN}./build/memory_forensics${NC}"
echo ""
echo -e "${YELLOW}3. Run Individual Tests:${NC}"
echo "   ${GREEN}./build/test_memory_scan${NC}"
echo "   ${GREEN}./build/test_threat_detection${NC}"
echo "   ${GREEN}./build/test_report_generator${NC}"
echo ""
echo -e "${YELLOW}4. Project Structure:${NC}"
echo "   build/       - Compiled executables"
echo "   src/         - Source code files"
echo "   include/     - Header files"
echo "   rules/       - YARA rule files"
echo "   reports/     - Generated reports"
echo "   tests/       - Test files"
echo ""
echo -e "${YELLOW}5. Available Commands in Application:${NC}"
echo "   scan         - Perform memory scan"
echo "   analyze      - Run threat analysis (with YARA)"
echo "   monitor      - Start behavioral monitoring"
echo "   export       - Export reports (PDF, Text, CSV)"
echo "   status       - Display system status"
echo "   help         - Show all commands"
echo ""

print_success "Setup complete! Ready to scan for threats using YARA rules."
print_success "Run './build/memory_forensics' to start."
echo ""