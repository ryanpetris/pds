# Reproducible, minimal-dependency build of the PDS Arch package.
#
# Builds pds-<ver>-1-x86_64.pkg.tar.zst inside a clean archlinux:base-devel
# container, so the host needs nothing but Docker. base-devel already supplies
# makepkg, fakeroot, and the build toolchain; we add only the package's extra
# makedepends (go to compile, git for the version stamp). Driven by
# `make arch-pkg` at the repo root, which copies the finished package out.

FROM docker.io/archlinux/archlinux:base-devel

# These images ship with the pacman lsign key stripped, so the keyring must be
# initialised before pacman can verify anything. Then do the recommended full
# refresh (Arch is rolling release) while pulling in the extra makedepends, and
# drop the package cache to keep the image lean.
RUN pacman-key --init \
    && pacman-key --populate archlinux \
    && pacman -Syu --noconfirm --needed go git \
    && pacman -Scc --noconfirm

# makepkg refuses to run as root, so build under an unprivileged user that owns
# its tree (passwordless sudo lets makepkg install build deps if ever invoked
# with -s; the deps above are already present for the default -f build).
RUN useradd -m -s /bin/bash build \
    && printf 'build ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/build \
    && chmod 0440 /etc/sudoers.d/build

USER build
WORKDIR /home/build/pds

# Bring in the working tree (including .git — build-local.sh derives the package
# version from the git revision). .dockerignore keeps build output, local state,
# and previous package artifacts out of the context.
COPY --chown=build:build . .

# Tar the working tree, stamp PDS_PKGVER from git, and run makepkg (integrity
# checks skipped — the tarball is regenerated every build). Collect the finished
# package under a fixed path so `make arch-pkg` can copy it out by directory.
RUN cd packaging/arch \
    && bash ./build-local.sh \
    && mkdir -p /home/build/out \
    && cp pds-*-*-x86_64.pkg.tar.zst /home/build/out/
