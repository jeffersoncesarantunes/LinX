#!/bin/sh
set -e

PREFIX="${PREFIX:-/usr/local}"
BINDIR="${PREFIX}/bin"
MANDIR="${PREFIX}/share/man/man1"

echo "Building LinX..."
make clean all

echo "Installing to ${DESTDIR}${BINDIR}..."
install -m 0755 -d "${DESTDIR}${BINDIR}"
install -m 0755 linx "${DESTDIR}${BINDIR}/linx"

echo "Installing man page to ${DESTDIR}${MANDIR}..."
install -m 0755 -d "${DESTDIR}${MANDIR}"
install -m 644 man/linx.1 "${DESTDIR}${MANDIR}/linx.1"

echo "Installation complete."
