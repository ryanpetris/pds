#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
rust_sysroot=$(rustc --print sysroot)
rust_host=$(rustc -vV | sed -n 's/^host: //p')
linker="$rust_sysroot/lib/rustlib/$rust_host/bin/rust-lld"

if [[ ! -v CARGO_ENCODED_RUSTFLAGS ]]; then
    CARGO_ENCODED_RUSTFLAGS=
    # Cargo splits RUSTFLAGS on spaces and trims each argument.
    while IFS= read -r -d ' ' flag || [[ -n $flag ]]; do
        flag=${flag#"${flag%%[![:space:]]*}"}
        flag=${flag%"${flag##*[![:space:]]}"}
        if [[ -n $flag ]]; then
            CARGO_ENCODED_RUSTFLAGS+="${CARGO_ENCODED_RUSTFLAGS:+$'\x1f'}$flag"
        fi
    done <<< "${RUSTFLAGS:-}"
fi

for arch in x86_64 arm64; do
    target=x86_64-unknown-linux-musl
    if [[ $arch == arm64 ]]; then
        target=aarch64-unknown-linux-musl
    fi
    target_env=${target//-/_}
    env "CC_$target_env=clang" \
        "CARGO_TARGET_${target_env^^}_LINKER=$linker" \
        "CARGO_ENCODED_RUSTFLAGS=${CARGO_ENCODED_RUSTFLAGS:+$CARGO_ENCODED_RUSTFLAGS$'\x1f'}--remap-path-prefix=$PWD=."$'\x1f'"--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"$'\x1f'"--remap-path-prefix=$rust_sysroot=/rust" \
        cargo build --locked --release --bins --target "$target" --target-dir target

    mkdir -p "dist/linux-$arch"
    install -m 755 "target/$target/release/pds" "target/$target/release/pdsd" "dist/linux-$arch/"
    tar -C "dist/linux-$arch" --mtime="@${SOURCE_DATE_EPOCH:-0}" \
        --owner=0 --group=0 --numeric-owner -cf - pds pdsd |
        gzip -n > "dist/pds-linux-$arch.tar.gz"
done
