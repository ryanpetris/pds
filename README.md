# PDS — Petris Distribution System

PDS distributes files (notably runnable scripts) and collects validated uploads from
many hosts over SSH/SFTP. Authenticity comes from the **SSH transport** — clients pin
the server's host key(s); the server authenticates clients by public key — so there
is no PGP/GPG signing.

Two binaries:

- **`pdsd`** — the server daemon. Runs as a normal user (not root). Serves read-only
  and read-write **buckets** and accepts validated **pushes**. Host keys are the
  user's `~/.ssh/id_*`.
- **`pds`** — the client. Pulls files, lists buckets, pushes data, and runs scripts.

## Concepts

### Buckets

A bucket is a named storage area mapped to a filesystem path (a leading `~` expands
to the home of the user `pdsd` runs as). `mode: ro` (default) is read-only;
`mode: rw` also accepts pushes. Writable buckets have two independent flags:

- **`versioned`** — every push is stored as `yyyyMMddHHmmss.<ext>` and `latest.<ext>`
  is repointed at it. **Nothing is ever pruned.** Non-versioned buckets overwrite a
  single `latest.<ext>`.
- **`byHost`** — data is filed under the connecting host's subdirectory
  (`<path>/<host>/…`).

Writable buckets require an `extension` and a `validator` (`yaml` | `json` | `jsonl` |
`none`),
which runs server-side before the data is committed.

### Paths

There is one virtual filesystem and **the first path segment is the bucket** — there
is no `--bucket` flag:

```
pds pull metrics/.self/latest.yaml
pds ls   scripts
pds push metrics data.yaml
```

Reserved virtual names:

| Name              | Where        | Meaning                                                        |
|-------------------|--------------|---------------------------------------------------------------|
| `.push`           | bucket root  | write-only push target (hidden from `ls`)                     |
| `.meta`           | bucket root  | read-only YAML describing the bucket                          |
| `.self`           | bucket root  | on `byHost` buckets, alias for the caller's own host dir      |
| `.pds/exec`       | top level    | alias for the configured `execBucket` (drives `pds exec`)     |

`.meta` looks like:

```yaml
mode: rw
versioned: true
byHost: true
extension: yaml     # rw buckets only
validator: yaml     # rw buckets only
```

### Host identity

Each authorized client public key maps to a **host name** in the server config. On a
`byHost` bucket the server files a push under that host automatically — a host cannot
push anywhere else. Reads are open: any authorized client may read any path.

### Anonymous (read-only) access

Setting `allowAnonymous: true` on the server lets clients connect **without a key**.
Anonymous clients are strictly read-only: they may read any bucket but cannot push and
have no `.self` host directory. They connect as the reserved SSH user `anonymous`.
Authenticated clients are unaffected — they keep using their key and host identity. With
`allowAnonymous` set, `authorizedKeys` becomes optional (a server can be
anonymous-read-only only).

`pds` reaches this automatically: it tries key authentication first and, if the server
**rejects the credentials** (or no key is configured), retries read-only as `anonymous`
on that same endpoint. The anonymous fallback fires *only* on a credentials rejection.
A network or protocol failure tries the next configured endpoint without downgrading;
a host-key mismatch (possible MITM) aborts the entire sequence.

### HTTP read access

Setting `httpListen` on the server starts a second listener (its own port; SSH is
untouched) that serves the same buckets **read-only over plain HTTP** — `GET`/`HEAD`
only, no pushes, no `.self`. Directories return a JSON listing; files stream with `Range`
support; `<bucket>/.meta` returns the bucket's metadata. This is the anonymous tier over a
different transport, so `httpListen` **requires `allowAnonymous: true`** (otherwise `pdsd`
exits at startup).

```
curl http://pds.example.com:8080/scripts/hello.sh     # a file
curl http://pds.example.com:8080/scripts              # JSON directory listing
```

**Security:** HTTP has no host-key pinning and no client authentication, so enabling it
makes every bucket's contents publicly readable by anyone who can reach the port — a
deliberate, opt-in downgrade of the read-side guarantees. Writes and host identity remain
SSH-only. For authenticated/encrypted HTTP, front it with a reverse proxy (TLS is out of
scope). `pds endpoint --http` prints each configured `http://host:httpPort` URL in
endpoint order.

## Configuration

Config is loaded systemd-style from three tiers, lowest to highest precedence:

```
/usr/lib/pds/<role>          (vendor/package defaults)
/etc/pds/<role>              (system administrator)
$XDG_CONFIG_HOME/pds/<role>  (per-user; default ~/.config)
```

where `<role>` is `client` (for `pds`) or `server` (for `pdsd`). Within each tier,
`config.yaml` is applied first, then every `config.d/*.yaml` in lexical order (so
drop-ins override the tier's base). Nothing is required to exist; the merged result
must simply contain everything required. Maps merge by key, lists are unioned, and
scalars are overridden by the higher tier. The client's ordered `endpoints` list is the
exception: a higher layer replaces it so that layer can choose a new primary. An optional
`--config FILE` is merged last, at the highest precedence.

On-disk keys are camelCase.

### `pds` (client) — `pds/client/config.yaml`

```yaml
endpoints:                       # attempted from first to last
  - host: pds-a.example.com      # name, IPv4, or IPv6 literal (e.g. ::1)
    sshPort: 2222
    httpPort: 8080               # optional; only for `pds endpoint --http`
  - host: pds-b.example.com
    sshPort: 2202
    httpPort: 8081
dialTimeout: 10s                 # optional; total setup budget for each endpoint
trustedKeys:                     # pinned server host keys; any match is accepted
  - ssh-ed25519 AAAA... node1    #   (list every node in a cluster + old keys for rotation)
  - ssh-ed25519 AAAA... node2
identities:                      # optional; defaults to ~/.ssh/id_*
  - ~/.ssh/id_ed25519
```

The client tries endpoints sequentially and uses the first one that completes TCP, SSH
authentication, and SFTP setup. DNS/TCP failures, timeouts, interrupted SSH setup, and a
missing or broken SFTP subsystem advance to the next endpoint. An untrusted host key or
an exhausted authentication rejection is terminal: those prove a server was reached and
must not be hidden as an availability problem. If every endpoint is unavailable, the
final error identifies each address and its failure. `PDS_ENDPOINT=host:port` remains a
singular hard override and disables configured failover for that invocation.

`trustedKeys` remains a union across configuration layers and every accumulated key is
trusted for every endpoint. Replacing `endpoints` in a higher layer does not revoke keys
from a lower layer; remove a retired or compromised key from the layer that introduced it.

Failover applies only while establishing the session. Once connected, an operation error
is returned to the caller; operations—especially `push`—are never replayed on another
node after an ambiguous disconnect.

### `pdsd` (server) — `pds/server/config.yaml`

```yaml
sshListen: ":2222"               # ":port" (all), an IP literal, a hostname, or "iface:<name>:port"
httpListen: ":8080"              # optional; read-only HTTP on its own port (requires allowAnonymous)
execBucket: scripts              # optional; exposed as .pds/exec — MUST be a mode:ro bucket
allowAnonymous: false            # optional; allow keyless read-only clients (user "anonymous")
authorizedKeys:               # client public key -> host name
  - host: web01
    keys:
      - ssh-ed25519 AAAA...      # multiple keys per host allowed
  - host: web02
    keys: [ssh-ed25519 BBBB...]
buckets:
  scripts:
    path: /srv/pds/scripts
    mode: ro
  metrics:
    path: /data/metrics
    mode: rw
    versioned: true
    byHost: true
    extension: yaml
    validator: yaml              # yaml | json | jsonl | none
```

`sshListen` and `httpListen` accept four forms: `":2222"` (all interfaces), an IP
literal (`"127.0.0.1:2222"`, `"[::1]:2222"`), a hostname (`"host.example:2222"`),
or `"iface:<name>:<port>"` to track a network interface. The first three are
bound once and pdsd exits if the bind fails. The `iface:` form binds the named
interface's current addresses and keeps them in sync as addresses come and go
(e.g. a VPN like `tailscale0` coming up); link-local addresses are skipped. If the
interface has no usable address — missing, down, or not yet assigned at startup —
pdsd waits up to 60 seconds for one to appear, then exits. The explicit `iface:`
marker is required because an interface name can also be a valid hostname.
Tracking interface addresses requires the systemd unit to allow `AF_NETLINK` (the
shipped `packaging/systemd/pds@.service` already does).

Server host keys are read from `~/.ssh/id_*` (override the directory with
`--ssh-dir`). Passphrase-protected keys are skipped with a warning.

## Usage

```
pds [--config FILE] pull <path> [-o FILE]    # default: stdout
pds [--config FILE] ls   [path]              # default: root
pds [--config FILE] push <bucket> [FILE|-]   # default: stdin
pds [--config FILE] meta <bucket>
pds [--config FILE] exec <name> [args...]
pds [--config FILE] endpoint [--ssh|--http]  # print ordered SSH endpoints or configured HTTP URLs
```

Flags are GNU-style: `--config` (or `-c`) and `-o`/`--output` for `pull`. A global
flag must come before the subcommand (e.g. `pds --config c.yaml ls`); everything
after `exec <name>` is passed to the script untouched.

`pds exec <name> [args...]` pulls `<name>` from the exec bucket, writes it to a temp
file with the execute bit set, and runs it with `argv[0]` = `<name>` and the given
arguments. `PDS_ENDPOINT` is exported with the endpoint that supplied the script so it
can re-invoke `pds` against the same node. This intentionally pins nested commands rather
than re-running configured failover. The file is assumed executable — there are no extra
checks.

Example script-driven workflow:

```sh
#!/bin/sh
# fetched and run via: pds exec collect web01
config="$(pds pull configs/.self/latest.yaml)"   # PDS_ENDPOINT is already set
generate_metrics > /tmp/m.yaml
pds push metrics /tmp/m.yaml
```

### Shell completion

`pds` generates bash/zsh completion scripts and completes commands with **live
data** from the server — bucket names, paths (descending as you type), and `exec`
script names are fetched over SSH at completion time, so each `<TAB>` opens a brief
connection.

```sh
source <(pds completion bash)        # bash, current shell
pds completion bash > /etc/bash_completion.d/pds   # system-wide

pds completion zsh > "${fpath[1]}/_pds"            # zsh (then restart the shell)
```

`pds completion --help` lists fish and powershell too.

## Building

```
go build ./...
go test ./...
```

## Security notes

- Clients pin server host keys; an untrusted host key aborts the connection.
- Client failover handles unavailable endpoints only. It never bypasses an untrusted
  host key or a server that rejects both configured and anonymous authentication.
- By default every connection requires an authorized client key; reads and pushes both
  require it. Enabling `allowAnonymous` opens reads to keyless clients but never writes —
  anonymous connections cannot push and have no host identity.
- `httpListen` exposes reads over unauthenticated plain HTTP (no host-key pinning); it is
  read-only and requires `allowAnonymous`. Treat it as making bucket contents public.
- All paths are confined to their bucket; symlinks that escape are rejected.
- A pushed file's extension is dictated by the bucket, never the client.
- Pushes are validated, written to a temp file, and atomically renamed, so a partial
  or invalid upload never becomes `latest`. Validation (json/yaml) is serialized
  through a single worker so concurrent pushes can't multiply validation memory.
- Pushes are capped at 5 MiB — PDS is for small files. Validators read from the temp
  file: `json` requires exactly one document, `jsonl` requires one JSON value per
  line, `yaml` decodes per document.
- `byHost` push isolation is inherent: the host comes from the auth key and only
  `.push` is writable.
