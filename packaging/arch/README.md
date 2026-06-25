# Arch packaging (local testing)

A `PKGBUILD` plus a wrapper script for building a PDS `pacman` package from the
**current working tree** — intended for local testing, not distribution.

## Build

### In Docker (no host build deps)

```sh
make arch-pkg       # from the repo root
```

Builds the package inside a clean `archlinux:base-devel` container — the host
needs nothing but Docker — and copies the resulting
`pds-<ver>-1-x86_64.pkg.tar.zst` to the repo root. The image
(`packaging/arch/Dockerfile`) initialises the pacman keyring, does a full
`pacman -Syu` while installing only the extra makedepends (`go`, `git`), then
runs `build-local.sh` (below) as an unprivileged user.

### On the host

```sh
./build-local.sh        # produces pds-<ver>-1-x86_64.pkg.tar.zst
./build-local.sh -i     # build and install via pacman
```

`build-local.sh` tars the working tree (including uncommitted changes) into
`pds-<ver>.tar.gz`, where `<ver>` is derived from git (most recent `v*` tag, e.g.
`v0.1.1` → `0.1.1`, or `0.1.1.r<n>.g<shorthash>` past it; `0.0.0.r<count>.g<hash>`
with no tag), then runs `makepkg`. Extra args pass straight through. Requires
`go` and `base-devel` on the host.

## Package contents

| Path | Source |
| --- | --- |
| `/usr/bin/pds`, `/usr/bin/pdsd` | `make build` output |
| `/usr/share/bash-completion/completions/pds` | `pds completion bash` |
| `/usr/share/zsh/site-functions/_pds` | `pds completion zsh` |
| `/usr/lib/systemd/system/pds@.service` | `packaging/systemd/pds@.service` |
| `/usr/lib/systemd/user/pds.service` | `packaging/systemd/pds.service` |
| `/usr/share/pds/config.server.example.yaml` | `examples/server/config.yaml` |
| `/usr/share/pds/config.client.example.yaml` | `examples/client/config.yaml` |
| `/usr/share/doc/pds/README.md` | `README.md` |
| `/usr/share/licenses/pds/LICENSE` | `LICENSE` |

## Running pdsd

`pdsd` runs as a normal user (never root): its SSH host keys are that user's
`~/.ssh/id_*`, and config is read from the layered tiers
(`/usr/lib/pds/server`, `/etc/pds/server`, `~/.config/pds/server`).

- **System-wide, instanced by user** — `pds@<user>.service`:

  ```sh
  cp /usr/share/pds/config.server.example.yaml /home/petris/.config/pds/server/config.yaml
  # edit it; ensure /home/petris/.ssh holds an id_* host key
  sudo systemctl enable --now pds@petris
  ```

  `User=%i` runs the daemon as that user. `ProtectSystem=full` keeps `/usr` and
  `/etc` read-only, so put writable bucket paths under `/srv`, `/var`, or the
  user's home. For a privileged listen port (<1024) add
  `AmbientCapabilities=CAP_NET_BIND_SERVICE` via a drop-in.

- **Per-user session** — `systemctl --user`:

  ```sh
  systemctl --user enable --now pds
  ```

## Notes

- **Integrity is intentionally skipped** (`sha256sums=('SKIP')`): the source
  tarball is regenerated on every run, so a pinned checksum would only get in the
  way. This is why the recipe is *not* suitable for the AUR as-is.
- The version is injected via the `PDS_PKGVER` environment variable the script
  exports; running `makepkg` directly without it falls back to `0.0.0`.
