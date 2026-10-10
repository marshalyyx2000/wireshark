#!/usr/bin/env bash
# Install CMake/Ninja from Windows-downloaded artifacts into /opt/ws-toolchain.
# Does not change system /usr/bin/cmake or /usr/bin/g++.
set -euo pipefail

PREFIX_TC="${WS_TOOLCHAIN:-/opt/ws-toolchain}"
HOST_BOOT="${HOST_BOOT:-/mnt/c/Development/ws-bootstrap}"
CMAKE_SH="${HOST_BOOT}/cmake-3.28.3-linux-x86_64.sh"
NINJA_ZIP="${HOST_BOOT}/ninja-linux.zip"

sudo mkdir -p "$PREFIX_TC" /opt/ws-deps /opt/ws-build
sudo chown -R "$(id -u):$(id -g)" "$PREFIX_TC" /opt/ws-deps /opt/ws-build
mkdir -p "$PREFIX_TC/bin"

if [[ ! -f "$CMAKE_SH" ]]; then
  echo "ERROR: missing $CMAKE_SH"
  exit 1
fi
if [[ ! -x "$PREFIX_TC/bin/cmake" ]]; then
  echo "=== install CMake from host artifact ==="
  sh "$CMAKE_SH" --prefix="$PREFIX_TC" --skip-license
fi
"$PREFIX_TC/bin/cmake" --version | head -1

if [[ ! -x "$PREFIX_TC/bin/ninja" ]]; then
  echo "=== install Ninja from host artifact ==="
  python3 - <<PY
import zipfile
zipfile.ZipFile("${NINJA_ZIP}").extractall("${PREFIX_TC}/bin")
PY
  chmod +x "$PREFIX_TC/bin/ninja"
fi
"$PREFIX_TC/bin/ninja" --version

if [[ -x /usr/bin/g++-9 && -x /usr/bin/gcc-9 ]]; then
  ln -sfn /usr/bin/gcc-9 "$PREFIX_TC/bin/gcc"
  ln -sfn /usr/bin/g++-9 "$PREFIX_TC/bin/g++"
  ln -sfn /usr/bin/gcc-9 "$PREFIX_TC/bin/cc"
  ln -sfn /usr/bin/g++-9 "$PREFIX_TC/bin/c++"
  echo "prefix wrappers -> gcc-9/g++-9"
fi

# Disable leftover PPA list if still active
PPA_LIST=/etc/apt/sources.list.d/ubuntu-toolchain-r-ubuntu-test-xenial.list
if [[ -f "$PPA_LIST" ]]; then
  sudo mv "$PPA_LIST" "${PPA_LIST}.disabled" || true
fi

echo "=== system defaults ==="
/usr/bin/g++ --version | head -1
/usr/bin/cmake --version | head -1
echo "INSTALL_PREFIX_OK"
