#!/bin/sh
# Process supervisor for the CipherShield all-in-one image.
#
# Runs the Next.js UI and the FastAPI API together, exits non-zero if either
# dies unexpectedly, and forwards SIGTERM/SIGINT so `docker stop` drains both
# processes cleanly. Executed under tini (PID 1) as a non-root user.
set -eu

API_PORT="${API_PORT:-8000}"
PORT="${PORT:-3000}"
export API_PORT PORT

cd /srv/ciphershield

node web/server.js &
NODE_PID=$!
uvicorn app.main:create_app --factory --host 0.0.0.0 --port "$API_PORT" &
API_PID=$!

requested=0
shutdown() {
  requested=1
  kill -TERM "$NODE_PID" "$API_PID" 2>/dev/null || true
}
trap shutdown TERM INT

while :; do
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    echo "ciphershield: UI process exited" >&2
    break
  fi
  if ! kill -0 "$API_PID" 2>/dev/null; then
    echo "ciphershield: API process exited" >&2
    break
  fi
  # Interruptible sleep: the trap fires now, not after the sleep finishes.
  sleep 1 &
  wait $! 2>/dev/null || true
done

kill -TERM "$NODE_PID" "$API_PID" 2>/dev/null || true
wait "$NODE_PID" 2>/dev/null || true
wait "$API_PID" 2>/dev/null || true

if [ "$requested" -eq 1 ]; then
  echo "ciphershield: stopped cleanly"
  exit 0
fi
echo "ciphershield: a process died unexpectedly; shutting down" >&2
exit 1
