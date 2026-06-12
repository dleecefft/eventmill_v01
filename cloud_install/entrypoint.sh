#!/bin/sh
# Cloud Run entrypoint — logs all signals before forwarding to ttyd
# This helps diagnose why containers are being killed.

log_signal() {
    echo "[entrypoint] Received signal: $1 at $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" >&2
}

# Trap all common signals and log them
for sig in HUP INT QUIT TERM USR1 USR2; do
    trap "log_signal $sig; kill -$sig \$PID" $sig
done

echo "[entrypoint] Starting ttyd (PID $$) at $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" >&2
# Read cgroup memory limit (try v2 then v1)
MEM_LIMIT=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo 'unknown')
if [ "$MEM_LIMIT" != "unknown" ] && [ "$MEM_LIMIT" != "max" ]; then
    MEM_LIMIT_MB=$((MEM_LIMIT / 1024 / 1024))
    echo "[entrypoint] Memory limit: ${MEM_LIMIT_MB} MB" >&2
else
    echo "[entrypoint] Memory limit: ${MEM_LIMIT}" >&2
fi
echo "[entrypoint] CPU limit: $(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo 'unknown')" >&2

# Start ttyd in background so we can trap signals
ttyd -W -p "${PORT}" \
    -c "${TTYD_USERNAME}:${TTYD_PASSWORD}" \
    --ping-interval 30 \
    -t fontSize=16 \
    python -m framework.cli.shell &

PID=$!
echo "[entrypoint] ttyd started as PID $PID" >&2

# Wait for ttyd to exit and capture its exit code
wait $PID
EXIT_CODE=$?
echo "[entrypoint] ttyd exited with code $EXIT_CODE at $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)" >&2
exit $EXIT_CODE
