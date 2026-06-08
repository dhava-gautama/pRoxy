#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

echo "🔄 Cleaning up existing pRoxy processes..."

# Kill any existing pRoxy processes with comprehensive patterns
kill_processes() {
    local pattern="$1"
    local name="$2"
    PIDS=$(pgrep -f "$pattern" 2>/dev/null | grep -v "^$$" || true)
    if [ -n "$PIDS" ]; then
        echo "  → Killing $name processes: $PIDS"
        echo "$PIDS" | xargs kill 2>/dev/null || true
        sleep 0.5
        # Force kill any that didn't die
        REMAINING=$(pgrep -f "$pattern" 2>/dev/null | grep -v "^$$" || true)
        if [ -n "$REMAINING" ]; then
            echo "  → Force killing remaining $name: $REMAINING"
            echo "$REMAINING" | xargs kill -9 2>/dev/null || true
            sleep 0.5
        fi
    fi
}

# Kill any processes using ports 8080 and 8082
for port in 8080 8082; do
    PORT_PIDS=$(lsof -ti:$port 2>/dev/null || true)
    if [ -n "$PORT_PIDS" ]; then
        echo "  → Killing processes on port $port: $PORT_PIDS"
        # Try graceful kill first
        echo "$PORT_PIDS" | xargs kill 2>/dev/null || true
        sleep 1
        # Force kill if still running
        REMAINING_PIDS=$(lsof -ti:$port 2>/dev/null || true)
        if [ -n "$REMAINING_PIDS" ]; then
            echo "  → Force killing remaining processes on port $port: $REMAINING_PIDS"
            echo "$REMAINING_PIDS" | xargs kill -9 2>/dev/null || true
            sleep 0.5
        fi
    fi
done

echo "✅ Process cleanup completed"

# Activate virtual environment (check both .venv and venv)
if [ -f ".venv/bin/activate" ]; then
    echo "🐍 Activating virtual environment (.venv)"
    source .venv/bin/activate
elif [ -f "venv/bin/activate" ]; then
    echo "🐍 Activating virtual environment (venv)"
    source venv/bin/activate
else
    echo "❌ No virtual environment found (.venv or venv)"
    echo "Please create one with: python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt"
    exit 1
fi

echo "🚀 Starting pRoxy..."
exec python main.py "$@"
