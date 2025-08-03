#!/bin/bash
# Lurenet Honeypot Startup Script

echo "🍯 Starting Lurenet HTTP Honeypot..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt 2>/dev/null || echo "⚠️  No requirements.txt found"

# Run validation
echo "🔍 Validating environment..."
python run_honeypot.py --validate

# Start honeypot
echo "🚀 Starting honeypot..."
python main.py --host 0.0.0.0 --port 8080 "$@"
