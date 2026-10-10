#!/usr/bin/env bash
# Build Python + required libraries into /opt/ws-toolchain and /opt/ws-deps only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/env-linux.sh"

SRC_CACHE="${SRC_CACHE:-/tmp/ws-deps-src}"
WIN_CACHE="${WIN_CACHE:-/mnt/c/Development/ws-bootstrap/deps}"
mkdir -p "$SRC_CACHE" "$WS_DEPS" "$WS_TOOLCHAIN"
# Copy Windows-downloaded tarballs into SRC_CACHE when present (WSL proxy often broken).
if [[ -d "$WIN_CACHE" ]]; then
  echo "Sync cache from $WIN_CACHE"
  cp -n "$WIN_CACHE"/* "$SRC_CACHE"/ 2>/dev/null || true
fi
export PATH="${WS_TOOLCHAIN}/bin:${WS_DEPS}/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export CC="${WS_TOOLCHAIN}/bin/gcc"
export CXX="${WS_TOOLCHAIN}/bin/g++"
export CPPFLAGS="-I${WS_DEPS}/include"
export LDFLAGS="-L${WS_DEPS}/lib -L${WS_DEPS}/lib64 -Wl,-rpath,${WS_DEPS}/lib"
export PKG_CONFIG_PATH="${WS_DEPS}/lib/pkgconfig:${WS_DEPS}/lib64/pkgconfig"
export LD_LIBRARY_PATH="${WS_DEPS}/lib:${WS_DEPS}/lib64"
export ACLOCAL_PATH="${WS_DEPS}/share/aclocal${ACLOCAL_PATH:+:${ACLOCAL_PATH}}"
NPROC="$(nproc 2>/dev/null || echo 4)"
echo "PATH=$PATH"

fetch() {
  local url="$1" out="$2"
  if [[ -f "$out" ]]; then
    echo "cached: $out"
    return 0
  fi
  echo "download: $url"
  wget -O "$out.partial" "$url"
  mv "$out.partial" "$out"
}

echo "=== Miniconda Python 3.8 -> ${WS_TOOLCHAIN}/miniconda ==="
MC_SH="${SRC_CACHE}/Miniconda3-py38_23.11.0-2-Linux-x86_64.sh"
if [[ ! -x "${WS_TOOLCHAIN}/miniconda/bin/python3" ]]; then
  fetch "https://repo.anaconda.com/miniconda/Miniconda3-py38_23.11.0-2-Linux-x86_64.sh" "$MC_SH"
  bash "$MC_SH" -b -p "${WS_TOOLCHAIN}/miniconda"
  ln -sfn "${WS_TOOLCHAIN}/miniconda/bin/python3" "${WS_TOOLCHAIN}/bin/python3"
  ln -sfn "${WS_TOOLCHAIN}/miniconda/bin/python3" "${WS_TOOLCHAIN}/bin/python"
fi
"${WS_TOOLCHAIN}/bin/python3" --version

build_autotools() {
  local name="$1" url="$2" conf_extra="${3:-}"
  local tarball="${SRC_CACHE}/$(basename "$url")"
  local srcdir="${SRC_CACHE}/${name}"
  if pkg-config --exists "$name" 2>/dev/null; then
    local ver
    ver="$(pkg-config --modversion "$name")"
    echo "skip $name (pkg-config $ver)"
    return 0
  fi
  # name may be pkg name different from tarball; always rebuild marker
  local marker="${WS_DEPS}/.built-${name}"
  if [[ -f "$marker" ]]; then
    echo "skip $name (marker $marker)"
    return 0
  fi
  fetch "$url" "$tarball"
  rm -rf "$srcdir"
  mkdir -p "$srcdir"
  tar -xf "$tarball" -C "$srcdir" --strip-components=1
  pushd "$srcdir" >/dev/null
  # shellcheck disable=SC2086
  ./configure --prefix="$WS_DEPS" --disable-static $conf_extra
  make -j"$NPROC"
  make install
  popd >/dev/null
  touch "$marker"
  echo "built $name"
}

echo "=== build libraries into ${WS_DEPS} ==="
# pcre2 (pkg libpcre2-8)
if [[ ! -f "${WS_DEPS}/.built-libpcre2-8" ]]; then
  fetch "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.42/pcre2-10.42.tar.bz2" "${SRC_CACHE}/pcre2-10.42.tar.bz2"
  rm -rf "${SRC_CACHE}/pcre2-10.42"
  tar -xf "${SRC_CACHE}/pcre2-10.42.tar.bz2" -C "$SRC_CACHE"
  pushd "${SRC_CACHE}/pcre2-10.42" >/dev/null
  ./configure --prefix="$WS_DEPS" --disable-static --enable-pcre2-8
  make -j"$NPROC" && make install
  popd >/dev/null
  touch "${WS_DEPS}/.built-libpcre2-8"
fi

# libgpg-error + libgcrypt
if [[ ! -f "${WS_DEPS}/.built-libgpg-error" ]]; then
  fetch "https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.47.tar.bz2" "${SRC_CACHE}/libgpg-error-1.47.tar.bz2"
  rm -rf "${SRC_CACHE}/libgpg-error-1.47"
  tar -xf "${SRC_CACHE}/libgpg-error-1.47.tar.bz2" -C "$SRC_CACHE"
  pushd "${SRC_CACHE}/libgpg-error-1.47" >/dev/null
  ./configure --prefix="$WS_DEPS" --disable-static --disable-doc
  make -j"$NPROC" && make install
  popd >/dev/null
  # libgpg-error 1.47 ships gpgrt-config; older libgcrypt looks for gpg-error-config.
  if [[ -x "${WS_DEPS}/bin/gpgrt-config" && ! -e "${WS_DEPS}/bin/gpg-error-config" ]]; then
    ln -sfn gpgrt-config "${WS_DEPS}/bin/gpg-error-config"
  fi
  touch "${WS_DEPS}/.built-libgpg-error"
fi
if [[ ! -f "${WS_DEPS}/.built-libgcrypt" ]]; then
  fetch "https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.8.11.tar.bz2" "${SRC_CACHE}/libgcrypt-1.8.11.tar.bz2"
  if [[ -x "${WS_DEPS}/bin/gpgrt-config" && ! -e "${WS_DEPS}/bin/gpg-error-config" ]]; then
    ln -sfn gpgrt-config "${WS_DEPS}/bin/gpg-error-config"
  fi
  test -x "${WS_DEPS}/bin/gpg-error-config"
  "${WS_DEPS}/bin/gpg-error-config" --version
  rm -rf "${SRC_CACHE}/libgcrypt-1.8.11"
  tar -xf "${SRC_CACHE}/libgcrypt-1.8.11.tar.bz2" -C "$SRC_CACHE"
  pushd "${SRC_CACHE}/libgcrypt-1.8.11" >/dev/null
  ./configure --prefix="$WS_DEPS" --disable-static \
    --with-libgpg-error-prefix="$WS_DEPS" \
    GPG_ERROR_CONFIG="${WS_DEPS}/bin/gpg-error-config"
  make -j"$NPROC" && make install
  popd >/dev/null
  touch "${WS_DEPS}/.built-libgcrypt"
fi

# c-ares
if [[ ! -f "${WS_DEPS}/.built-libcares" ]]; then
  fetch "https://github.com/c-ares/c-ares/releases/download/cares-1_19_1/c-ares-1.19.1.tar.gz" "${SRC_CACHE}/c-ares-1.19.1.tar.gz"
  rm -rf "${SRC_CACHE}/c-ares-1.19.1"
  tar -xf "${SRC_CACHE}/c-ares-1.19.1.tar.gz" -C "$SRC_CACHE"
  pushd "${SRC_CACHE}/c-ares-1.19.1" >/dev/null
  ./configure --prefix="$WS_DEPS" --disable-static
  make -j"$NPROC" && make install
  popd >/dev/null
  touch "${WS_DEPS}/.built-libcares"
fi

# libxml2 2.9.14
if [[ ! -f "${WS_DEPS}/.built-libxml-2.0" ]]; then
  fetch "https://download.gnome.org/sources/libxml2/2.9/libxml2-2.9.14.tar.xz" "${SRC_CACHE}/libxml2-2.9.14.tar.xz"
  rm -rf "${SRC_CACHE}/libxml2-2.9.14"
  tar -xf "${SRC_CACHE}/libxml2-2.9.14.tar.xz" -C "$SRC_CACHE"
  pushd "${SRC_CACHE}/libxml2-2.9.14" >/dev/null
  ./configure --prefix="$WS_DEPS" --disable-static --without-python
  make -j"$NPROC" && make install
  popd >/dev/null
  touch "${WS_DEPS}/.built-libxml-2.0"
fi

# GLib 2.56.4 (autotools; meets >=2.54). GCC 9+ needs -Wno-error for old gio/dbus code.
if [[ ! -f "${WS_DEPS}/lib/pkgconfig/glib-2.0.pc" ]]; then
  fetch "https://download.gnome.org/sources/glib/2.56/glib-2.56.4.tar.xz" "${SRC_CACHE}/glib-2.56.4.tar.xz"
  rm -rf "${SRC_CACHE}/glib-2.56.4"
  tar -xf "${SRC_CACHE}/glib-2.56.4.tar.xz" -C "$SRC_CACHE"
  pushd "${SRC_CACHE}/glib-2.56.4" >/dev/null
  export CFLAGS="-O2 -g -Wno-error -Wno-error=format-overflow -Wno-error=format-truncation"
  export CXXFLAGS="${CFLAGS}"
  ./configure --prefix="$WS_DEPS" --disable-static --disable-gtk-doc --disable-libmount \
    --with-pcre=internal
  make -j"$NPROC" && make install
  popd >/dev/null
  test -f "${WS_DEPS}/lib/pkgconfig/glib-2.0.pc"
  touch "${WS_DEPS}/.built-glib-2.0"
fi

echo "=== verify prefix pkgs ==="
export PKG_CONFIG_PATH="${WS_DEPS}/lib/pkgconfig:${WS_DEPS}/lib64/pkgconfig"
for p in glib-2.0 libxml-2.0 libgcrypt libcares libpcre2-8; do
  echo "$p=$(pkg-config --modversion "$p")"
done
"${WS_TOOLCHAIN}/bin/python3" --version
echo "=== system defaults unchanged ==="
/usr/bin/g++ --version | head -1
/usr/bin/cmake --version | head -1
echo "BOOTSTRAP_DEPS_OK"
