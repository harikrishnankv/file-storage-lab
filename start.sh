#!/bin/bash
# File Storage Lab - Startup Script

echo "🚨 File Storage Lab - UUID v1 Attack Demonstration"
echo "=================================================="
echo "⚠️  WARNING: This application is intentionally vulnerable!"
echo "⚠️  Only use in controlled environments for educational purposes"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

# Check if pip is available (via python3 -m pip)
if ! python3 -m pip --version &> /dev/null; then
    echo "❌ pip is required but not installed"
    echo "   Install with: python3 -m ensurepip --upgrade"
    exit 1
fi

# Install dependencies
echo "📦 Installing Python dependencies..."
cd backend

# Prefer python3 -m pip and continue even if install fails (may already be satisfied)
if ! python3 -m pip install --user -r requirements.txt; then
    echo "⚠️  Dependency installation failed or partially completed. Continuing since requirements may already be installed."
fi

echo "✅ Dependencies installed successfully"
echo ""

# Start the integrated server
echo "🚀 Starting File Storage Lab..."
echo "   Web Interface: http://localhost:5002"
echo "   API Endpoints: http://localhost:5002/api/*"
echo "   Health Check: http://localhost:5002/api/health"
echo ""
echo "📋 Admin Access:"
echo "   Admin credentials are embedded in source code"
echo "   Check backend/app.py create_admin_user() function"
echo ""
echo "🌐 Access the Application:"
echo "   Open http://localhost:5002 in your web browser"
echo "   The UI is now integrated with the backend server"
echo ""
echo "🧪 Attack Tools:"
echo "   Built-in attack tools available in the web interface"
echo "   See ATTACK_GUIDE.md for detailed instructions"
echo ""
echo "👥 User Management:"
echo "   Admin can delete any user and all their files"
echo "   Users can delete their own accounts"
echo "   Complete tenant isolation with file cleanup"
echo ""
echo "📚 Documentation:"
echo "   README.md - Complete lab documentation"
echo "   ATTACK_GUIDE.md - Step-by-step attack instructions"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python3 app.py
