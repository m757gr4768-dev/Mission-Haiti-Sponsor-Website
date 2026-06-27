#!/bin/bash
set -u

APP_DIR="/Users/Paul/Documents/Codex/2026-06-25/help-me-build-a-secure-web"
PYTHON="/Users/Paul/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
PORT="8001"

cd "$APP_DIR" || exit 1

echo "Restarting Mission-Haiti Sponsor Updates..."
echo
echo "Stopping old local app servers on ports 8000, 8001, and 8002 if they are running."

for old_port in 8000 8001 8002; do
  pids="$(/usr/sbin/lsof -ti tcp:${old_port} 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    echo "Stopping server on port ${old_port}: ${pids}"
    kill $pids 2>/dev/null || true
  fi
done

sleep 1

echo
echo "Starting the updated app on:"
echo "http://127.0.0.1:${PORT}"
echo
echo "Leave this window open while using the app."
echo "Press Control+C in this window to stop the app."
echo

(sleep 1; open "http://127.0.0.1:${PORT}/students/2/edit") &
PORT="$PORT" "$PYTHON" app.py
