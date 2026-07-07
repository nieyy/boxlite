#!/bin/sh
# Build statically-linked OpenSSH sshd + ssh-keygen using Alpine musl.
#
# Usage: build-static-sshd.sh [OUTPUT_DIR]
#   OUTPUT_DIR  Directory to write boxlite-sshd and boxlite-ssh-keygen (default: dist)
#
# Requires Docker. The resulting binaries are pure static ELFs that work inside
# any Linux container image regardless of the image's libc.
#
# Update OPENSSH_VERSION and OPENSSH_SHA256 together when upgrading OpenSSH.
# The SHA256 can be verified at https://www.openssh.com/portable.html.
set -e

if ! command -v docker >/dev/null 2>&1; then
  echo "❌ docker is required but not found in PATH" >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "❌ docker daemon is not reachable (is Docker running?)" >&2
  exit 1
fi

OUTPUT="${1:-dist}"
mkdir -p "$OUTPUT"
if [ ! -w "$OUTPUT" ]; then
  echo "❌ output directory '$OUTPUT' is not writable" >&2
  exit 1
fi

OPENSSH_VERSION=9.7p1
OPENSSH_SHA256=490426f766d82a2763fcacd8d83ea3d70798750c7bd2aff2e57dc5660f773ffd

echo "🔨 Building static OpenSSH ${OPENSSH_VERSION} via Alpine Docker..."

docker run --rm \
  -v "$(pwd)/${OUTPUT}:/output" \
  alpine:3.19 sh -c "
    set -ex
    apk add --no-cache \
      build-base linux-headers \
      openssl-dev openssl-libs-static \
      zlib-dev zlib-static
    wget -q 'https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz'
    echo '${OPENSSH_SHA256}  openssh-${OPENSSH_VERSION}.tar.gz' | sha256sum -c -
    tar xf 'openssh-${OPENSSH_VERSION}.tar.gz'
    cd 'openssh-${OPENSSH_VERSION}'
    ./configure \
      --prefix=/usr \
      --sysconfdir=/etc/ssh \
      --without-pam \
      --without-kerberos5 \
      --without-gssapi \
      LDFLAGS='-static -Wl,--no-dynamic-linker' \
      CFLAGS='-Os'
    make -j\$(nproc) sshd ssh-keygen
    strip sshd ssh-keygen
    cp sshd /output/boxlite-sshd
    cp ssh-keygen /output/boxlite-ssh-keygen
  "

echo "✅ Static sshd built: ${OUTPUT}/boxlite-sshd, ${OUTPUT}/boxlite-ssh-keygen"
