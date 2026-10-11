#!/usr/bin/env bash
# Build a self-contained .deb for the Ubuntu 16.04 industrial minimal build.
# Installs under /opt/binyao-wireshark and ships prefix Qt/GLib libs (not system).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/env-linux.sh"

PKG_NAME="${PKG_NAME:-binyao-wireshark}"
PKG_VERSION="${PKG_VERSION:-0.10.5}"
PKG_REV="${PKG_REV:-1}"
PKG_ARCH="${PKG_ARCH:-amd64}"
INSTALL_ROOT="${INSTALL_ROOT:-/opt/binyao-wireshark}"
OUT_DIR="${OUT_DIR:-${WS_SRC}}"
STAGE="${STAGE:-/tmp/${PKG_NAME}-deb-stage}"
DEB_FILE="${OUT_DIR}/${PKG_NAME}_${PKG_VERSION}-${PKG_REV}_${PKG_ARCH}.deb"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: missing command: $1" >&2
    exit 1
  }
}

need_cmd dpkg-deb
need_cmd cmake
need_cmd ldd
need_cmd rsync

if [[ ! -x "${WS_BUILD}/run/wireshark" ]]; then
  echo "ERROR: ${WS_BUILD}/run/wireshark not found. Build first." >&2
  exit 1
fi

echo "=== copy_data_files ==="
cmake --build "${WS_BUILD}" --target copy_data_files -j"$(nproc 2>/dev/null || echo 4)"

echo "=== stage ${STAGE} ==="
rm -rf "${STAGE}"
PREFIX_DIR="${STAGE}${INSTALL_ROOT}"
mkdir -p \
  "${PREFIX_DIR}/bin" \
  "${PREFIX_DIR}/lib" \
  "${PREFIX_DIR}/lib/qt/plugins" \
  "${PREFIX_DIR}/share/wireshark" \
  "${PREFIX_DIR}/translations" \
  "${PREFIX_DIR}/languages" \
  "${STAGE}/usr/bin" \
  "${STAGE}/usr/share/applications" \
  "${STAGE}/DEBIAN"

# App binaries + private shared libs (skip static archives / build tools).
rsync -a \
  --include='wireshark' \
  --include='tshark' \
  --include='dumpcap' \
  --include='libwireshark.so*' \
  --include='libwiretap.so*' \
  --include='libwsutil.so*' \
  --include='libuiqt_plugin.so*' \
  --exclude='*' \
  "${WS_BUILD}/run/" "${PREFIX_DIR}/bin/"

# Move .so into lib/; keep binaries in bin/.
shopt -s nullglob
for f in "${PREFIX_DIR}/bin"/lib*.so*; do
  mv "$f" "${PREFIX_DIR}/lib/"
done
shopt -u nullglob

# Runtime data (wrappers set WIRESHARK_DATA_DIR to share/wireshark).
rsync -a \
  --exclude='wireshark' --exclude='tshark' --exclude='dumpcap' \
  --exclude='lemon' --exclude='*.a' --exclude='lib*.so*' \
  --exclude='extcap' --exclude='translations' --exclude='languages' \
  --exclude='qt.conf' \
  "${WS_BUILD}/run/" "${PREFIX_DIR}/share/wireshark/"

if [[ -d "${WS_BUILD}/run/translations" ]]; then
  rsync -a "${WS_BUILD}/run/translations/" "${PREFIX_DIR}/translations/"
fi
if [[ -d "${WS_BUILD}/run/languages" ]]; then
  rsync -a "${WS_BUILD}/run/languages/" "${PREFIX_DIR}/languages/"
fi

copy_lib_tree() {
  local src="$1"
  local name
  name="$(basename "$src")"
  if [[ -e "$src" ]]; then
    cp -a "$src" "${PREFIX_DIR}/lib/"
    # Follow one level of symlinks into real files already handled by -a.
    echo "  lib: $name"
  fi
}

echo "=== collect shared libraries (prefix Qt + ws-deps) ==="
# Seed with main binaries and private libs.
mapfile -t _seeds < <(find "${PREFIX_DIR}/bin" "${PREFIX_DIR}/lib" -type f -executable -o -name '*.so*' 2>/dev/null)

# Also include Qt platform plugin early so its deps are collected.
_QXCB="${WS_QT}/plugins/platforms/libqxcb.so"
[[ -f "${_QXCB}" ]] && _seeds+=("${_QXCB}")

declare -A SEEN=()
QUEUE=("${_seeds[@]}")

while ((${#QUEUE[@]})); do
  cur="${QUEUE[0]}"
  QUEUE=("${QUEUE[@]:1}")
  [[ -n "${cur:-}" && -e "$cur" ]] || continue
  [[ -n "${SEEN[$cur]:-}" ]] && continue
  SEEN[$cur]=1

  while IFS= read -r line; do
    # "libfoo.so.1 => /path/libfoo.so.1 (0x...)"
    dest="$(awk '/=>/ {print $3}' <<<"$line")"
    [[ -n "$dest" && "$dest" != "not" && -e "$dest" ]] || continue
    case "$dest" in
      /lib/*|/lib64/*|/usr/lib/*|/usr/lib64/*)
        # Keep system libs as package Depends; do not bundle.
        continue
        ;;
      "${WS_QT}"/*|"${WS_DEPS}"/*|"${WS_BUILD}/run"/*)
        base="$(basename "$dest")"
        if [[ ! -e "${PREFIX_DIR}/lib/${base}" ]]; then
          cp -a "$dest" "${PREFIX_DIR}/lib/"
          # Resolve symlink target into lib/ as well.
          if [[ -L "$dest" ]]; then
            real="$(readlink -f "$dest")"
            if [[ -n "$real" && -e "$real" ]]; then
              rbase="$(basename "$real")"
              [[ -e "${PREFIX_DIR}/lib/${rbase}" ]] || cp -a "$real" "${PREFIX_DIR}/lib/"
            fi
          fi
          QUEUE+=("$dest")
        fi
        ;;
    esac
  done < <(ldd "$cur" 2>/dev/null || true)
done

echo "=== Qt plugins ==="
for plug_dir in platforms imageformats iconengines styles platforminputcontexts xcbglintegrations; do
  src="${WS_QT}/plugins/${plug_dir}"
  if [[ -d "$src" ]]; then
    mkdir -p "${PREFIX_DIR}/lib/qt/plugins/${plug_dir}"
    # Prefer the commonly needed plugins; copy whole dir if small enough.
    rsync -a --include='*.so' --exclude='*' "${src}/" "${PREFIX_DIR}/lib/qt/plugins/${plug_dir}/" 2>/dev/null \
      || rsync -a "${src}/" "${PREFIX_DIR}/lib/qt/plugins/${plug_dir}/"
  fi
done

# qt.conf for the installed layout (plugins relative to prefix).
cat > "${PREFIX_DIR}/bin/qt.conf" <<EOF
[Paths]
Prefix = ..
Libraries = lib
Plugins = lib/qt/plugins
Translations = translations
EOF

# dumpcap often has file capabilities; glibc then ignores LD_LIBRARY_PATH and
# $ORIGIN in RPATH (AT_SECURE). Register an absolute private lib path via
# ld.so.conf.d in postinst. Also keep bin/ symlinks for non-cap binaries.
echo "=== symlink private libs into bin/ (non-cap RPATH helper) ==="
for f in "${PREFIX_DIR}/lib"/lib*.so*; do
  base="$(basename "$f")"
  ln -sfn "../lib/${base}" "${PREFIX_DIR}/bin/${base}"
done
if command -v patchelf >/dev/null 2>&1; then
  echo "=== patchelf RPATH=\$ORIGIN:\$ORIGIN/../lib (extra) ==="
  for elf in "${PREFIX_DIR}/bin/wireshark" "${PREFIX_DIR}/bin/tshark" "${PREFIX_DIR}/bin/dumpcap"; do
    [[ -f "$elf" && ! -L "$elf" ]] || continue
    patchelf --set-rpath '$ORIGIN:$ORIGIN/../lib' "$elf" 2>/dev/null || true
  done
fi
# Staged ld.so.conf snippet (activated by postinst ldconfig).
mkdir -p "${STAGE}/etc/ld.so.conf.d"
echo "${INSTALL_ROOT}/lib" > "${STAGE}/etc/ld.so.conf.d/${PKG_NAME}.conf"

# Launch wrappers: set LD_LIBRARY_PATH / QT_PLUGIN_PATH / data dir.
# /usr/bin names must NOT collide with distro packages (wireshark-qt, tshark, …).
write_wrapper() {
  local bin_name="$1"   # real binary under $PREFIX/bin
  local cmd_name="$2"   # public command under /usr/bin
  cat > "${PREFIX_DIR}/bin/${bin_name}.sh" <<EOF
#!/bin/sh
PREFIX="${INSTALL_ROOT}"
export LD_LIBRARY_PATH="\${PREFIX}/lib\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}"
export QT_PLUGIN_PATH="\${PREFIX}/lib/qt/plugins"
export QT_QPA_PLATFORM_PLUGIN_PATH="\${PREFIX}/lib/qt/plugins/platforms"
# Prefer packaged data; allow override.
export WIRESHARK_DATA_DIR="\${WIRESHARK_DATA_DIR:-\${PREFIX}/share/wireshark}"
exec "\${PREFIX}/bin/${bin_name}" "\$@"
EOF
  chmod 755 "${PREFIX_DIR}/bin/${bin_name}.sh"
  cat > "${STAGE}/usr/bin/${cmd_name}" <<EOF
#!/bin/sh
exec ${INSTALL_ROOT}/bin/${bin_name}.sh "\$@"
EOF
  chmod 755 "${STAGE}/usr/bin/${cmd_name}"
}

write_wrapper wireshark binyao-wireshark
write_wrapper tshark binyao-tshark
write_wrapper dumpcap binyao-dumpcap

# Desktop entry
cat > "${STAGE}/usr/share/applications/${PKG_NAME}.desktop" <<EOF
[Desktop Entry]
Name=Binyao Wireshark
Comment=Industrial protocol analyzer (minimal build)
Exec=${INSTALL_ROOT}/bin/wireshark.sh %f
Icon=wireshark
Terminal=false
Type=Application
Categories=Network;Monitor;Qt;
MimeType=application/vnd.tcpdump.pcap;application/x-pcap;
StartupNotify=true
EOF

# Debian control / scripts
INSTALLED_SIZE="$(du -sk "${STAGE}" | awk '{print $1}')"
cat > "${STAGE}/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}-${PKG_REV}
Section: net
Priority: optional
Architecture: ${PKG_ARCH}
Maintainer: Binyao Industrial <noreply@localhost>
Installed-Size: ${INSTALLED_SIZE}
Depends: libpcap0.8, libx11-6, libxcb1, libgl1-mesa-glx | libgl1, libdbus-1-3, zlib1g, libexpat1
Recommends: libcap2-bin
Homepage: https://www.wireshark.org/
Description: Industrial minimal Wireshark (Qt 5.14, Ubuntu 16.04)
 Self-contained industrial Wireshark build with MMS/GOOSE/SV focus.
 Bundles private Qt 5.14 and GLib under ${INSTALL_ROOT}.
 Provides binyao-wireshark / binyao-tshark / binyao-dumpcap and does
 not replace distro /usr/bin/wireshark or tshark.
EOF

cat > "${STAGE}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
# Absolute private lib path — required when dumpcap has file capabilities
# (AT_SECURE ignores LD_LIBRARY_PATH and $ORIGIN RPATH).
if [ -f /etc/ld.so.conf.d/binyao-wireshark.conf ]; then
  ldconfig || true
fi
DUMPCAP="/opt/binyao-wireshark/bin/dumpcap"
if command -v setcap >/dev/null 2>&1 && [ -x "$DUMPCAP" ]; then
  setcap cap_net_raw,cap_net_admin=eip "$DUMPCAP" 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "${STAGE}/DEBIAN/postinst"

cat > "${STAGE}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
DUMPCAP="/opt/binyao-wireshark/bin/dumpcap"
if command -v setcap >/dev/null 2>&1 && [ -e "$DUMPCAP" ]; then
  setcap -r "$DUMPCAP" 2>/dev/null || true
fi
exit 0
EOF
chmod 755 "${STAGE}/DEBIAN/prerm"

cat > "${STAGE}/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
if [ "$1" = remove ] || [ "$1" = purge ]; then
  rm -f /etc/ld.so.conf.d/binyao-wireshark.conf
  ldconfig || true
fi
exit 0
EOF
chmod 755 "${STAGE}/DEBIAN/postrm"

# Permissions: binaries executable; DEBIAN owned by root for dpkg-deb
chmod 755 "${PREFIX_DIR}/bin/wireshark" "${PREFIX_DIR}/bin/tshark" "${PREFIX_DIR}/bin/dumpcap"

echo "=== dpkg-deb ==="
# Prefer root ownership inside the archive.
if command -v fakeroot >/dev/null 2>&1; then
  fakeroot dpkg-deb --build "${STAGE}" "${DEB_FILE}"
else
  dpkg-deb --build "${STAGE}" "${DEB_FILE}"
fi

echo "DEB_OK=${DEB_FILE}"
ls -lh "${DEB_FILE}"
dpkg-deb -I "${DEB_FILE}" | sed -n '1,40p'
echo "Install: sudo dpkg -i ${DEB_FILE}"
echo "Run:    binyao-wireshark   # or ${INSTALL_ROOT}/bin/wireshark.sh"
