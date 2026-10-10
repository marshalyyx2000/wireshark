#!/usr/bin/env bash
set -euo pipefail
export PATH="/usr/bin:/bin:/usr/sbin:/sbin:/opt/ws-toolchain/bin:${PATH:-}"
echo "PATH ok: $(command -v ls) $(command -v python3 || true)"
echo "=== compilers ==="
/usr/bin/g++ --version | head -1
/opt/ws-toolchain/bin/g++ -dumpversion
/opt/ws-toolchain/bin/cmake --version | head -1
echo "=== python ==="
python3 --version || true
python3.6 --version 2>/dev/null || true
python3.7 --version 2>/dev/null || true
echo "=== pkg-config ==="
for p in glib-2.0 libxml-2.0 libgcrypt libcares libpcre2-8; do
  v=$(pkg-config --modversion "$p" 2>/dev/null || echo missing)
  echo "$p=$v"
done
echo "=== dpkg ==="
dpkg -l libglib2.0-dev libxml2-dev libgcrypt20-dev libc-ares-dev libpcre2-dev libpcap-dev flex bison 2>/dev/null | awk '/^ii/{print $2,$3}' || true
echo "=== Qt ==="
/opt/Qt5.14.1/5.14.1/gcc_64/bin/qmake -query QT_VERSION
test -f /opt/Qt5.14.1/5.14.1/gcc_64/lib/cmake/Qt5/Qt5Config.cmake && echo Qt5Config=OK
echo "PROBE_OK"
