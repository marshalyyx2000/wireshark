#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/env-linux.sh"
cd "${WS_BUILD}"
LOG=/tmp/ws-build.log
cmake --build . --target wireshark tshark dumpcap -j4 >"$LOG" 2>&1
RC=$?
echo "BUILD_EXIT=$RC"
echo "=== unique errors ==="
grep -E 'error:' "$LOG" | sed 's/\x1b\[[0-9;]*m//g' | sort -u | head -80
echo "=== failed targets ==="
grep -E '^FAILED:' "$LOG" | sed 's/\x1b\[[0-9;]*m//g' | sort -u | head -40
exit "$RC"
