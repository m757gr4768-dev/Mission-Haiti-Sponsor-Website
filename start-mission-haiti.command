#!/bin/bash
set -u

APP_DIR="/Users/Paul/Documents/Codex/2026-06-25/help-me-build-a-secure-web"
PYTHON="/Users/Paul/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3"
PORT="${PORT:-8001}"

cd "$APP_DIR" || exit 1

echo "Starting Mission-Haiti Sponsor Updates..."
echo
echo "When the app is ready, open:"
echo "http://127.0.0.1:${PORT}"
echo
echo "Leave this window open while using the app."
echo "Press Control+C in this window to stop the app."
echo

(sleep 1; open "http://127.0.0.1:${PORT}") &
PORT="$PORT" "$PYTHON" app.py
