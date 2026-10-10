#!/usr/bin/env bash
set -uo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/env-linux.sh"
cd "${WS_BUILD}"
LOG=/tmp/ws-build.log
ERR=/mnt/f/software/temp/wireshark-industrial/_ws_build_errors.txt
cmake --build . --target wireshark tshark dumpcap -j4 >"$LOG" 2>&1
RC=$?
{
  echo "BUILD_EXIT=$RC"
  grep -E 'error:|FAILED:|undefined reference' "$LOG" | sed 's/\x1b\[[0-9;]*m//g' | sort -u | head -80
} >"$ERR"
echo "wrote $ERR"
exit "$RC"
