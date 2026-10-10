#!/usr/bin/env bash
# Set http(s)_proxy for WSL2 -> Windows host Clash/etc on port 7897.
# Usage: source tools/minimal-build/wsl-proxy-env.sh
PROXY_PORT="${PROXY_PORT:-7897}"
HOSTIP="$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')"
if [[ -z "$HOSTIP" ]]; then
  HOSTIP="$(cat /etc/resolv.conf 2>/dev/null | awk '/nameserver/ {print $2; exit}')"
fi
export http_proxy="http://${HOSTIP}:${PROXY_PORT}"
export https_proxy="http://${HOSTIP}:${PROXY_PORT}"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$https_proxy"
export no_proxy="localhost,127.0.0.1,${HOSTIP}"
export NO_PROXY="$no_proxy"
echo "proxy=$https_proxy"
