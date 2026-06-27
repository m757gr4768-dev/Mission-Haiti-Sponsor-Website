#!/bin/bash
cd "/Users/Paul/Documents/Codex/2026-06-25/help-me-build-a-secure-web" || exit 1

echo "Mission-Haiti app is starting..."
echo
echo "Opening the student edit page in a moment."
echo "Keep this window open while using the app."
echo

for old_port in 8000 8001 8002; do
  pids="$(/usr/sbin/lsof -ti tcp:${old_port} 2>/dev/null || true)"
  if [ -n "$pids" ]; then
    kill $pids 2>/dev/null || true
  fi
done

sleep 1
(sleep 2; /usr/bin/open "http://127.0.0.1:8001/students/2/edit") &
PORT=8001 "/Users/Paul/.cache/codex-runtimes/codex-primary-runtime/dependencies/python/bin/python3" app.py
