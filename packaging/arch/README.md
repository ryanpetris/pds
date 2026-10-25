# Arch packaging

Build a local PDS package from the current working tree, including uncommitted
changes. The source tarball uses `sha256sums=('SKIP')` because each build creates
it again. This recipe is not ready for the AUR without a fixed source and checksum.

## Build with Docker

Run from the repository root:

```sh
make arch-pkg
```

Only Docker is required on the host. The `archlinux:base-devel` image installs
`rust` and `git`, then runs `makepkg` as an unprivileged user. The finished
`pds-<ver>-1-x86_64.pkg.tar.zst` is copied to the repository root.

## Build on Arch Linux

Install `rust`, `git`, and `base-devel`, then run from the repository root:

```sh
packaging/arch/build-local.sh
```

The wrapper creates `packaging/arch/pds-<ver>.tar.gz` and runs `makepkg` there.
Extra arguments pass through to `makepkg`, including `-i` to install the package.
The package depends on `glibc` and `gcc-libs` at runtime.

The version comes from the most recent `v*` Git tag. An exact `v0.1.1` tag becomes
`0.1.1`; later commits become `0.1.1.r<count>.g<hash>`. Without a tag, the version
is `0.0.0.r<count>.g<hash>`. Outside a checkout, it uses a date stamp.
`build-local.sh` exports `PDS_PKGVER`; invoking `makepkg` directly defaults to
`0.0.0`.

`make build` uses `cargo build --locked --release --bins` and copies both binaries
to `bin/`. The release profile strips symbols. The package remaps source paths
and generates Bash and Zsh completions from the built client.

## Package contents

- `/usr/bin/pds` and `/usr/bin/pdsd`
- `/usr/share/bash-completion/completions/pds`
- `/usr/share/zsh/site-functions/_pds`
- `/usr/lib/systemd/system/pds@.service`
- `/usr/lib/systemd/user/pds.service`
- `/usr/share/pds/config.server.example.yaml`
- `/usr/share/pds/config.client.example.yaml`
- `/usr/share/doc/pds/README.md`
- `/usr/share/licenses/pds/LICENSE`

## Run the server

`pdsd` runs as a normal user. It reads host keys from `~/.ssh/id_*` and merges
configuration from `/usr/lib/pds/server`, `/etc/pds/server`, and
`~/.config/pds/server`.

To prepare the current user's configuration:

```sh
mkdir -p ~/.config/pds/server
cp /usr/share/pds/config.server.example.yaml ~/.config/pds/server/config.yaml
```

Edit the configuration and ensure `~/.ssh` contains a host key. Start the user
service with:

```sh
systemctl --user enable --now pds
```

For a system service, prepare that account's configuration and host key, then
use its account name as the instance, for example:

```sh
sudo systemctl enable --now pds@pdsuser
```

The system unit uses `ProtectSystem=full`, so put writable bucket paths under
`/srv`, `/var`, or the account's home. For a listen port below 1024, add
`AmbientCapabilities=CAP_NET_BIND_SERVICE` and
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE` in a systemd drop-in.
