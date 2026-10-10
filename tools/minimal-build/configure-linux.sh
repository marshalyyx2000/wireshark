#!/usr/bin/env bash
# Configure ENABLE_MINIMAL_BUILD + USE_qt5 for Ubuntu 16.04 prefix toolchain.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/env-linux.sh"

mkdir -p "${WS_BUILD}"
cd "${WS_BUILD}"

echo "=== configure USE_qt5 + ENABLE_MINIMAL_BUILD ==="
cmake -G Ninja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER="${CC}" \
  -DCMAKE_CXX_COMPILER="${CXX}" \
  -DCMAKE_PREFIX_PATH="${CMAKE_PREFIX_PATH}" \
  -DUSE_qt5=ON \
  -DENABLE_MINIMAL_BUILD=ON \
  -DENABLE_LUA=OFF -DENABLE_GNUTLS=OFF -DENABLE_KERBEROS=OFF -DENABLE_SMI=OFF \
  -DENABLE_SPEEXDSP=OFF -DENABLE_SBC=OFF -DENABLE_BCG729=OFF -DENABLE_AMRNB=OFF \
  -DENABLE_AMRWB=OFF -DENABLE_ILBC=OFF -DENABLE_OPUS=OFF -DENABLE_SPANDSP=OFF \
  -DENABLE_NGHTTP2=OFF -DENABLE_NGHTTP3=OFF -DENABLE_SNAPPY=OFF -DENABLE_BROTLI=OFF \
  -DENABLE_MINIZIP=OFF -DENABLE_MINIZIPNG=OFF -DENABLE_PLUGINS=OFF \
  -DBUILD_androiddump=OFF -DBUILD_sshdump=OFF -DBUILD_ciscodump=OFF \
  -DBUILD_dpauxmon=OFF -DBUILD_randpktdump=OFF -DBUILD_wifidump=OFF \
  -DBUILD_udpdump=OFF -DBUILD_sharkd=OFF -DBUILD_mmdbresolve=OFF \
  -DBUILD_rawshark=OFF -DBUILD_capinfos=OFF -DBUILD_captype=OFF \
  -DBUILD_mergecap=OFF -DBUILD_editcap=OFF -DBUILD_reordercap=OFF \
  -DBUILD_text2pcap=OFF -DBUILD_randpkt=OFF -DBUILD_dftest=OFF \
  -DBUILD_dcerpcidl2wrs=OFF -DBUILD_stratoshark=OFF \
  -DBUILD_tshark=ON -DBUILD_dumpcap=ON -DBUILD_wireshark=ON \
  -DENABLE_LTO=OFF \
  -DENABLE_WERROR=OFF \
  "${WS_SRC}"

echo "CMAKE_EXIT=$?"
