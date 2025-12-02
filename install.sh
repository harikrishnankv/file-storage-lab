#!/bin/bash
# File Storage Lab - Complete Installation Script
# This script handles all dependencies and installation automatically

set -e  # Exit on error

echo "🚀 File Storage Lab - Complete Installation"
echo "============================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install Python3 on different OS
install_python3() {
    echo -e "${YELLOW}📦 Installing Python 3...${NC}"
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Linux
        if command_exists apt-get; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip
        elif command_exists yum; then
            sudo yum install -y python3 python3-pip
        elif command_exists dnf; then
            sudo dnf install -y python3 python3-pip
        elif command_exists pacman; then
            sudo pacman -S --noconfirm python python-pip
        else
            echo -e "${RED}❌ Cannot auto-install Python3. Please install it manually.${NC}"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command_exists brew; then
            brew install python3
        else
            echo -e "${RED}❌ Homebrew not found. Please install Python3 manually or install Homebrew first.${NC}"
            echo "   Visit: https://www.python.org/downloads/"
            exit 1
        fi
    else
        echo -e "${RED}❌ Unsupported OS. Please install Python3 manually.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Python 3 installed"
}

# Check and install Python 3
# Try python3 first, then python (which might be Python 3 on some systems)
PYTHON_CMD=""
if command_exists python3; then
    PYTHON_CMD="python3"
elif command_exists python && python --version 2>&1 | grep -q "Python 3"; then
    PYTHON_CMD="python"
else
    echo -e "${RED}❌ Python 3 not found${NC}"
    read -p "Would you like to install Python 3 automatically? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_python3
        PYTHON_CMD="python3"
    else
        echo "Please install Python 3 manually and run this script again."
        echo "Download from: https://www.python.org/downloads/"
        exit 1
    fi
fi

if [ -z "$PYTHON_CMD" ]; then
    PYTHON_CMD="python3"
fi

PYTHON_VERSION=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python 3 found: $PYTHON_VERSION (using: $PYTHON_CMD)"

# Check and install pip (use the detected Python command)
if ! $PYTHON_CMD -m pip --version &> /dev/null; then
    echo -e "${YELLOW}⚠${NC}  pip not found, installing..."
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command_exists apt-get; then
            sudo apt-get install -y python3-pip
        elif command_exists yum; then
            sudo yum install -y python3-pip
        elif command_exists dnf; then
            sudo dnf install -y python3-pip
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        $PYTHON_CMD get-pip.py
        rm get-pip.py
    fi
    echo -e "${GREEN}✓${NC} pip installed"
else
    echo -e "${GREEN}✓${NC} pip found"
fi

# Get the script directory (project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Check if we're in the correct directory
if [ ! -f "backend/requirements.txt" ]; then
    echo -e "${RED}❌ Error: backend/requirements.txt not found${NC}"
    echo "Please run this script from the project root directory"
    exit 1
fi

echo ""
echo "📦 Installing Python dependencies..."
cd backend

# Upgrade pip first (use the detected Python command)
$PYTHON_CMD -m pip install --upgrade pip --user 2>/dev/null || true

# Install requirements (use the detected Python command)
if $PYTHON_CMD -m pip install --user -r requirements.txt; then
    echo -e "${GREEN}✓${NC} Dependencies installed successfully"
else
    echo -e "${YELLOW}⚠${NC}  Some dependencies may have failed, trying with --break-system-packages..."
    $PYTHON_CMD -m pip install --break-system-packages -r requirements.txt 2>/dev/null || {
        echo -e "${RED}❌ Failed to install dependencies${NC}"
        echo "Please install manually: cd backend && $PYTHON_CMD -m pip install -r requirements.txt"
        exit 1
    }
    echo -e "${GREEN}✓${NC} Dependencies installed"
fi

# Ensure required directories exist
echo ""
echo "📁 Creating required directories..."
mkdir -p database
mkdir -p uploads
echo -e "${GREEN}✓${NC} Directories created"

cd ..

echo ""
echo -e "${GREEN}✅ Installation complete!${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo ""
echo "To start the application, run:"
echo -e "${YELLOW}  ./start.sh${NC}"
echo ""
echo "Or manually:"
echo -e "${YELLOW}  cd backend && $PYTHON_CMD app.py${NC}"
echo ""
echo "The application will be available at:"
echo -e "${GREEN}  http://localhost:5002${NC}"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
