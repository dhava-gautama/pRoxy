#!/usr/bin/env bash
set -e

cd "$(dirname "$0")"

# Kill any existing pRoxy processes
PIDS=$(pgrep -f "python.*main\.py" 2>/dev/null | grep -v "^$$" || true)
if [ -n "$PIDS" ]; then
  echo "Killing existing pRoxy processes: $PIDS"
  echo "$PIDS" | xargs kill 2>/dev/null || true
  sleep 1
  # Force kill any that didn't die
  REMAINING=$(pgrep -f "python.*main\.py" 2>/dev/null | grep -v "^$$" || true)
  if [ -n "$REMAINING" ]; then
    echo "Force killing: $REMAINING"
    echo "$REMAINING" | xargs kill -9 2>/dev/null || true
    sleep 1
  fi
fi

source venv/bin/activate
exec python main.py "$@"
