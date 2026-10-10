#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/env-linux.sh"

if [[ ! -f "${WS_BUILD}/build.ninja" && ! -f "${WS_BUILD}/CMakeCache.txt" ]]; then
  echo "ERROR: not configured. Run configure-linux.sh first."
  exit 1
fi
cd "${WS_BUILD}"
echo "=== build wireshark tshark dumpcap ==="
cmake --build . --target wireshark tshark dumpcap -j"$(nproc 2>/dev/null || echo 4)"
echo "BUILD_OK"
