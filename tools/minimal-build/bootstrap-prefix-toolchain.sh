#!/usr/bin/env bash
# Install CMake/Ninja into /opt/ws-toolchain only. Does not change system defaults.
set -euo pipefail

PREFIX_TC="${WS_TOOLCHAIN:-/opt/ws-toolchain}"
PREFIX_DEPS="${WS_DEPS:-/opt/ws-deps}"
PREFIX_BUILD="${WS_BUILD:-/opt/ws-build}"
TMPDIR_BOOT="${TMPDIR:-/tmp}/ws-bootstrap"
CMAKE_VER="${CMAKE_VER:-3.28.3}"

# WSL2 NAT: Windows proxy on localhost is not reachable; use host IP from resolv.conf.
if [[ -z "${http_proxy:-}${HTTP_PROXY:-}" ]]; then
  WIN_HOST="$(awk '/^nameserver/{print $2; exit}' /etc/resolv.conf 2>/dev/null || true)"
  PROXY_PORT="${WS_PROXY_PORT:-7897}"
  if [[ -n "$WIN_HOST" ]]; then
    export http_proxy="http://${WIN_HOST}:${PROXY_PORT}"
    export https_proxy="http://${WIN_HOST}:${PROXY_PORT}"
    export HTTP_PROXY="$http_proxy"
    export HTTPS_PROXY="$https_proxy"
    export ALL_PROXY="$http_proxy"
    echo "Using Windows host proxy: $http_proxy"
  fi
fi

echo "=== disable leftover toolchain PPA list (if any) ==="
PPA_LIST=/etc/apt/sources.list.d/ubuntu-toolchain-r-ubuntu-test-xenial.list
if [[ -f "$PPA_LIST" ]]; then
  sudo mv "$PPA_LIST" "${PPA_LIST}.disabled"
  echo "disabled: $PPA_LIST"
fi

echo "=== create prefixes ==="
sudo mkdir -p "$PREFIX_TC" "$PREFIX_DEPS" "$PREFIX_BUILD" "$TMPDIR_BOOT"
sudo chown -R "$(id -u):$(id -g)" "$PREFIX_TC" "$PREFIX_DEPS" "$PREFIX_BUILD" "$TMPDIR_BOOT"
mkdir -p "$PREFIX_TC/bin"
cd "$TMPDIR_BOOT"

CMAKE_SH="cmake-${CMAKE_VER}-linux-x86_64.sh"
# Prefer Windows-side cache if present
for CAND in \
  "/mnt/c/Development/ws-bootstrap/${CMAKE_SH}" \
  "/mnt/f/software/temp/ws-bootstrap/${CMAKE_SH}" \
  "${TMPDIR_BOOT}/${CMAKE_SH}"
do
  if [[ -f "$CAND" ]]; then
    cp -f "$CAND" "./${CMAKE_SH}"
    echo "Using cached CMake installer: $CAND"
    break
  fi
done

if [[ ! -x "$PREFIX_TC/bin/cmake" ]]; then
  if [[ ! -f "$CMAKE_SH" ]]; then
    echo "=== download CMake ${CMAKE_VER} ==="
    wget -O "$CMAKE_SH" "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VER}/${CMAKE_SH}"
  fi
  sh "$CMAKE_SH" --prefix="$PREFIX_TC" --skip-license
fi
"$PREFIX_TC/bin/cmake" --version | head -1

NINJA_ZIP=ninja-linux.zip
for CAND in \
  "/mnt/c/Development/ws-bootstrap/${NINJA_ZIP}" \
  "/mnt/f/software/temp/ws-bootstrap/${NINJA_ZIP}" \
  "${TMPDIR_BOOT}/${NINJA_ZIP}"
do
  if [[ -f "$CAND" ]]; then
    cp -f "$CAND" "./${NINJA_ZIP}"
    echo "Using cached Ninja zip: $CAND"
    break
  fi
done

if [[ ! -x "$PREFIX_TC/bin/ninja" ]]; then
  if [[ ! -f "$NINJA_ZIP" ]]; then
    echo "=== download Ninja ==="
    wget -O "$NINJA_ZIP" https://github.com/ninja-build/ninja/releases/download/v1.11.1/ninja-linux.zip
  fi
  python3 - <<PY
import zipfile
zipfile.ZipFile("${TMPDIR_BOOT}/${NINJA_ZIP}").extractall("${PREFIX_TC}/bin")
PY
  chmod +x "$PREFIX_TC/bin/ninja"
fi
"$PREFIX_TC/bin/ninja" --version

# Prefer already-present g++-9 via wrappers only (system /usr/bin/g++ stays 5.4).
if [[ -x /usr/bin/g++-9 && -x /usr/bin/gcc-9 ]]; then
  ln -sfn /usr/bin/gcc-9 "$PREFIX_TC/bin/gcc"
  ln -sfn /usr/bin/g++-9 "$PREFIX_TC/bin/g++"
  ln -sfn /usr/bin/gcc-9 "$PREFIX_TC/bin/cc"
  ln -sfn /usr/bin/g++-9 "$PREFIX_TC/bin/c++"
  echo "prefix wrappers -> /usr/bin/gcc-9 and g++-9"
else
  echo "WARNING: /usr/bin/g++-9 not found; install a relocatable GCC into $PREFIX_TC later"
fi

echo "=== prefix toolchain ==="
"$PREFIX_TC/bin/cmake" --version | head -1
"$PREFIX_TC/bin/g++" -dumpversion || true
echo "=== system defaults (must remain unchanged) ==="
/usr/bin/g++ --version | head -1
/usr/bin/cmake --version | head -1
echo "BOOTSTRAP_TOOLCHAIN_OK"
