#!/usr/bin/env bash
# Source-only env for Ubuntu 16.04 industrial minimal build.
# Does NOT modify system PATH permanently. Usage: source tools/minimal-build/env-linux.sh

_WS_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_WS_REPO_ROOT="$(cd "${_WS_SCRIPT_DIR}/../.." && pwd)"

export WS_TOOLCHAIN="${WS_TOOLCHAIN:-/opt/ws-toolchain}"
export WS_DEPS="${WS_DEPS:-/opt/ws-deps}"
export WS_QT="${WS_QT:-/opt/Qt5.14.1/5.14.1/gcc_64}"
export WS_BUILD="${WS_BUILD:-/opt/ws-build}"
export WS_SRC="${WS_SRC:-${_WS_REPO_ROOT}}"

# Keep only Unix bins (drop Windows PATH bleed that breaks libtool/configure).
export PATH="${WS_TOOLCHAIN}/bin:${WS_DEPS}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

# WSL2 NAT proxy -> Windows host (Clash etc. on 7897)
if [[ -z "${http_proxy:-}${HTTP_PROXY:-}" ]]; then
  WIN_HOST="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
  PROXY_PORT="${WS_PROXY_PORT:-7897}"
  if [[ -n "$WIN_HOST" ]]; then
    export http_proxy="http://${WIN_HOST}:${PROXY_PORT}"
    export https_proxy="$http_proxy"
    export HTTP_PROXY="$http_proxy"
    export HTTPS_PROXY="$http_proxy"
    export ALL_PROXY="$http_proxy"
  fi
fi

export CC="${WS_TOOLCHAIN}/bin/gcc"
export CXX="${WS_TOOLCHAIN}/bin/g++"
export CMAKE_PREFIX_PATH="${WS_DEPS}:${WS_QT}"
export PKG_CONFIG_PATH="${WS_DEPS}/lib/pkgconfig:${WS_DEPS}/lib64/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
export LD_LIBRARY_PATH="${WS_QT}/lib:${WS_DEPS}/lib:${WS_DEPS}/lib64${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export WIRESHARK_QT5_PREFIX_PATH="${WS_QT}"

if [[ -x "${WS_TOOLCHAIN}/bin/python3" ]]; then
  export PYTHON="${WS_TOOLCHAIN}/bin/python3"
elif [[ -x "${WS_TOOLCHAIN}/miniconda/bin/python3" ]]; then
  export PATH="${WS_TOOLCHAIN}/miniconda/bin:${PATH}"
  export PYTHON="${WS_TOOLCHAIN}/miniconda/bin/python3"
fi

echo "WS_SRC=$WS_SRC"
echo "WS_BUILD=$WS_BUILD"
echo "WS_TOOLCHAIN=$WS_TOOLCHAIN"
echo "WS_DEPS=$WS_DEPS"
echo "WS_QT=$WS_QT"
echo "proxy=${https_proxy:-none}"
echo "CC=$CC  CXX=$CXX"
command -v cmake && cmake --version | head -1
command -v g++ && g++ -dumpversion
command -v python3 && python3 --version
