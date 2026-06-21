#!/usr/bin/env bash
#
# build-local.sh — build a PDS Arch package from the current working tree.
#
# This is a local TESTING convenience: it tars the working tree (including any
# uncommitted changes) into a source tarball that the PKGBUILD consumes with
# integrity checks disabled (sha256sums=SKIP), then runs makepkg.
#
# Usage:
#   ./build-local.sh            # build the package
#   ./build-local.sh -i         # build and install (pacman -U)
#   ./build-local.sh <args...>  # any extra args are passed through to makepkg
#
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"

# Derive a version from git. Prefer the most recent v* tag; fall back to a
# tagless commit-count scheme, then to a date stamp outside a git checkout.
# pacman versions may not contain '-', so describe's "v<tag>-<n>-g<hash>" is
# rewritten to a dotted form: the leading "v" is stripped, an exact tag match
# (n=0) becomes just "<tag>", and commits past a tag become "<tag>.r<n>.g<hash>".
if git -C "$repo_root" rev-parse --git-dir >/dev/null 2>&1; then
	if describe="$(git -C "$repo_root" describe --tags --long --match 'v*' 2>/dev/null)"; then
		# e.g. v0.1.1-0-gd77fbf8 -> 0.1.1 ; v0.1.1-3-gd77fbf8 -> 0.1.1.r3.gd77fbf8
		pkgver="$(printf '%s' "$describe" \
			| sed -E 's/^v//; s/-0-g[0-9a-f]+$//; s/-([0-9]+)-g/.r\1.g/')"
	else
		count="$(git -C "$repo_root" rev-list --count HEAD 2>/dev/null || echo 0)"
		short="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
		pkgver="0.0.0.r${count}.g${short}"
	fi
else
	pkgver="0.0.0.$(date +%Y%m%d)"
fi
export PDS_PKGVER="$pkgver"

tarball="$here/pds-${pkgver}.tar.gz"

echo ">> packaging working tree as pds-${pkgver}.tar.gz"
# Archive the working tree under a top-level pds-<ver>/ prefix, excluding the
# VCS dir, build output, and local/release artifacts.
tar --create --gzip --file "$tarball" \
	--directory "$repo_root" \
	--transform "s,^[.],pds-${pkgver}," \
	--exclude='./.git' \
	--exclude='./bin' \
	--exclude='./dist' \
	--exclude='./packaging/arch/pkg' \
	--exclude='./packaging/arch/src' \
	--exclude='./packaging/arch/pds-*.tar.gz' \
	--exclude='./packaging/arch/*.pkg.tar.*' \
	--exclude='./.toby.yaml' \
	--exclude='*.out' --exclude='coverage.*' \
	.

echo ">> running makepkg (PDS_PKGVER=${pkgver})"
cd "$here"
exec makepkg -f "$@"
