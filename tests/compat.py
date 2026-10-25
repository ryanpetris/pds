#!/usr/bin/env python3
"""Executable compatibility contract, using Python's standard library and ssh-keygen.

Run with explicit paths to built client and server executables:
    PDS_BIN=./target/debug/pds PDSD_BIN=./target/debug/pdsd python3 tests/compat.py

Optionally set PDS_REFERENCE_BIN and PDSD_REFERENCE_BIN to existing external
reference executables. Every supplied client runs against every supplied server,
including mixed pairs. No Go toolchain or source tree is required.
Candidate servers follow operator-created symlinks outside buckets; reference
servers retain their original rejection of external read symlinks.

Select checks with unittest's -k option, for example python3 tests/compat.py -k http,
with the same binary environment variables.
Tests use temporary HOME, XDG_CONFIG_HOME, keys, storage, and loopback ports.
User layers reset inherited system configuration without changing system files.
Metadata checks read its flat scalar mapping; no general YAML parser is needed.
"""

import datetime
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest


CLIENT_RESET = dict(endpoints=None, dialTimeout=None, trustedKeys=None, identities=None)
SERVER_RESET = dict(sshListen="", httpListen="", allowAnonymous=False,
                    authorizedKeys=None, execBucket="", buckets=None)
SCRIPT = b'''#!/bin/sh
printf 'name=%s\\n' "${0##*/}"
printf 'endpoint=%s\\n' "$PDS_ENDPOINT"
printf 'custom=%s\\n' "$PDS_TEST_VALUE"
printf 'cwd=%s\\n' "$PWD"
for arg do printf 'arg=<%s>\\n' "$arg"; done
cat
printf 'script stderr\\n' >&2
exit 23
'''


def write_config(path, config):
    path.parent.mkdir(parents=True, exist_ok=True)
    # JSON is a YAML subset and keeps disposable paths and key strings quoted.
    path.write_text(json.dumps(config), encoding="ascii")
    return path


def environment(root):
    root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    for name in ("PDS_ENDPOINT", "SSH_AUTH_SOCK"):
        env.pop(name, None)
    for name, directory in (("HOME", "home"), ("XDG_CONFIG_HOME", "config"),
                            ("TMPDIR", "tmp")):
        path = root / directory
        path.mkdir()
        env[name] = str(path)
    env.update(USER="pds-test", LOGNAME="pds-test")
    for role, reset in (("client", CLIENT_RESET), ("server", SERVER_RESET)):
        write_config(Path(env["XDG_CONFIG_HOME"]) / "pds" / role / "config.yaml", reset)
    return env


def generate_key(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "compat",
                    "-f", str(path)], check=True, capture_output=True, timeout=10)
    return path.with_suffix(".pub").read_text(encoding="ascii").strip()


def metadata(data):
    """Read the generated flat metadata mapping, allowing block YAML or JSON."""
    text = data.decode("utf-8").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    if text.startswith("{") and text.endswith("}"):
        lines = text[1:-1].split(",")
    else:
        lines = text.splitlines()
    result = {}
    for line in lines:
        line = line.strip()
        if not line or line in ("---", "...") or line.startswith("#"):
            continue
        key, value = line.split(":", 1)
        key = key.strip().strip("\"'")
        value = value.strip()
        if value.lower() in ("true", "false"):
            value = value.lower() == "true"
        elif value.startswith('"'):
            value = json.loads(value)
        elif value.startswith("'") and value.endswith("'"):
            value = value[1:-1].replace("''", "'")
        if key in result:
            raise ValueError("duplicate metadata key: " + key)
        result[key] = value
    return result


class Server:
    def __init__(self, case, *, anonymous=False, http=False, authorized=None,
                 host_key=None, overrides=None, umask=-1):
        self.root = case.root / ("server-" + str(case.server_count))
        case.server_count += 1
        self.env = environment(self.root)
        self.binary = case.server_binary
        self.umask = umask
        self.process = None
        self.log = None
        self.ssh_dir = Path(self.env["HOME"]) / ".ssh"
        self.ssh_dir.mkdir()
        source = host_key or case.host_key
        shutil.copyfile(source, self.ssh_dir / "id_ed25519")
        (self.ssh_dir / "id_ed25519").chmod(0o600)
        self.public_key = source.with_suffix(".pub").read_text(encoding="ascii").strip()
        self.buckets = {}
        for name in ("scripts", "metrics", "raw", "json", "jsonl", "versioned", "hosts"):
            path = self.root / "data" / name
            path.mkdir(parents=True)
            self.buckets[name] = path
        (self.buckets["scripts"] / "check.sh").write_bytes(SCRIPT)
        (self.buckets["scripts"] / "bytes.bin").write_bytes(bytes(range(256)) * 3)
        (self.buckets["scripts"] / "nested").mkdir()
        (self.buckets["scripts"] / "nested" / "file.txt").write_bytes(b"nested\n")
        self.config = {
            "sshListen": "", "httpListen": "", "allowAnonymous": anonymous,
            "execBucket": "scripts",
            "authorizedKeys": authorized if authorized is not None else [
                {"host": "node-a", "keys": [case.client_public]}],
            "buckets": {"scripts": {"path": str(self.buckets["scripts"])}},
        }
        for name, validator, extension, versioned, by_host in (
            ("metrics", "yaml", "yaml", True, True),
            ("raw", "none", "bin", False, False),
            ("json", "json", "json", False, False),
            ("jsonl", "jsonl", "jsonl", False, False),
            ("versioned", "none", "tar.gz", True, False),
            ("hosts", "none", "txt", False, True),
        ):
            self.config["buckets"][name] = dict(
                path=str(self.buckets[name]), mode="rw", validator=validator,
                extension=extension, versioned=versioned, byHost=by_host)
        # Both ports are allocated together so HTTP and SSH cannot share a port.
        with socket.socket() as ssh_sock, socket.socket() as http_sock:
            ssh_sock.bind(("127.0.0.1", 0))
            http_sock.bind(("127.0.0.1", 0))
            self.ssh_port = ssh_sock.getsockname()[1]
            self.http_port = http_sock.getsockname()[1] if http else None
        self.config["sshListen"] = self.endpoint
        if http:
            self.config["httpListen"] = "127.0.0.1:" + str(self.http_port)
        if overrides:
            self.config.update(overrides)
        self.config_path = self.root / "server.yaml"
        case.addCleanup(self.close)

    @property
    def endpoint(self):
        return "127.0.0.1:" + str(self.ssh_port)

    @property
    def client_endpoint(self):
        endpoint = dict(host="127.0.0.1", sshPort=self.ssh_port)
        if self.http_port:
            endpoint["httpPort"] = self.http_port
        return endpoint

    def start(self, *, explicit_config=True, explicit_keys=True):
        write_config(self.config_path, self.config)
        args = [self.binary]
        if explicit_config:
            args += ["--config", str(self.config_path)]
        if explicit_keys:
            args += ["--ssh-dir", str(self.ssh_dir)]
        self.log = (self.root / "server.log").open("w+b")
        self.process = subprocess.Popen(args, env=self.env, cwd=self.root,
                                        stdin=subprocess.DEVNULL, stdout=self.log,
                                        stderr=subprocess.STDOUT, umask=self.umask)
        deadline = time.monotonic() + 10
        ports = [self.ssh_port] + ([self.http_port] if self.http_port else [])
        while ports and time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", ports[0]), timeout=0.1):
                    ports.pop(0)
            except OSError:
                time.sleep(0.02)
        if ports or self.process.poll() is not None:
            self.log.seek(0)
            raise AssertionError("server did not start: " + self.log.read().decode(errors="replace"))
        return self

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log is not None:
            self.log.close()


class Compat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix="pds-compat-keys-")
        cls.addClassCleanup(cls.keys.cleanup)
        root = Path(cls.keys.name)
        cls.host_key = root / "host"
        cls.client_key = root / "client"
        cls.other_key = root / "other"
        cls.host_public = generate_key(cls.host_key)
        cls.client_public = generate_key(cls.client_key)
        cls.other_public = generate_key(cls.other_key)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="pds-compat-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.env = environment(self.root / "client")
        self.server_count = 0
        self.config_count = 0

    def server(self, **kwargs):
        return Server(self, **kwargs).start()

    def config(self, server=None, **updates):
        config = dict(endpoints=[server.client_endpoint] if server else [],
                      trustedKeys=[server.public_key] if server else [],
                      identities=[str(self.client_key)], dialTimeout="1s")
        config.update(updates)
        path = self.root / ("client-" + str(self.config_count) + ".yaml")
        self.config_count += 1
        return write_config(path, config)

    def run_client(self, *args, config=None, data=b"", env=None, code=0):
        argv = [self.client_binary]
        if config is not None:
            argv += ["--config", str(config)]
        result = subprocess.run(argv + list(map(str, args)), input=data,
                                capture_output=True, env=env or self.env,
                                cwd=self.root, timeout=15)
        message = "{} exited {}\nstdout: {!r}\nstderr: {!r}".format(
            args, result.returncode, result.stdout[:2000], result.stderr[:2000])
        if code is None:
            self.assertGreater(result.returncode, 0, message)
        else:
            self.assertEqual(result.returncode, code, message)
        return result

    def names(self, *args, **kwargs):
        return set(self.run_client("ls", *args, **kwargs).stdout.decode().splitlines())

    def default_config(self, config):
        role = Path(self.env["XDG_CONFIG_HOME"]) / "pds" / "client"
        write_config(role / "config.d" / "99-command.yaml", json.loads(config.read_text()))

    def http(self, server, path, method="GET", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", server.http_port, timeout=5)
        try:
            conn.request(method, path, headers=headers or {})
            response = conn.getresponse()
            headers = {key.lower(): value for key, value in response.getheaders()}
            return response.status, headers, response.read()
        finally:
            conn.close()

    def test_endpoint_order_and_ipv6_without_dial_or_trust(self):
        config = self.config(endpoints=[
            dict(host="primary.example", sshPort=22, httpPort=8080),
            dict(host="[::1]", sshPort=2222),
            dict(host="::2", sshPort=2223, httpPort=8081)], trustedKeys=[], identities=[])
        expected = b"primary.example:22\n[::1]:2222\n[::2]:2223\n"
        self.assertEqual(self.run_client("endpoint", config=config).stdout, expected)
        self.assertEqual(self.run_client("endpoint", "--ssh", config=config).stdout, expected)
        self.assertEqual(self.run_client("endpoint", "--http", config=config).stdout,
                         b"http://primary.example:8080\nhttp://[::2]:8081\n")

    def test_endpoint_environment_is_singular_and_http_must_match(self):
        config = self.config(endpoints=[dict(host="PRIMARY.example", sshPort=22, httpPort=8080),
                                        dict(host="backup.example", sshPort=2222, httpPort=8081)])
        env = dict(self.env, PDS_ENDPOINT="primary.EXAMPLE:00022")
        self.assertEqual(self.run_client("endpoint", config=config, env=env).stdout,
                         b"primary.EXAMPLE:00022\n")
        self.assertEqual(self.run_client("endpoint", "--http", config=config, env=env).stdout,
                         b"http://PRIMARY.example:8080\n")
        env["PDS_ENDPOINT"] = "unknown.example:22"
        self.run_client("endpoint", "--http", config=config, env=env, code=None)
        self.assertEqual(self.run_client("endpoint", config=config, env=env).stdout,
                         b"unknown.example:22\n")

    def test_endpoint_http_requires_a_port_but_not_ssh_fields(self):
        config = self.config(endpoints=[dict(host="localhost", httpPort=8080)])
        self.assertEqual(self.run_client("endpoint", "--http", config=config).stdout,
                         b"http://localhost:8080\n")
        self.run_client("endpoint", config=config, code=None)
        config = self.config(endpoints=[dict(host="localhost", sshPort=22)])
        self.run_client("endpoint", "--http", config=config, code=None)

    def test_client_layers_replace_endpoints_in_lexical_order(self):
        role = Path(self.env["XDG_CONFIG_HOME"]) / "pds" / "client"
        write_config(role / "config.yaml", dict(CLIENT_RESET, endpoints=[
            dict(host="base.example", sshPort=22)]))
        (role / "config.d").mkdir()
        (role / "config.d" / "20-last.yml").write_text(
            "endpoints:\n  - host: last.example\n    sshPort: 2222\n", encoding="ascii")
        write_config(role / "config.d" / "10-first.yaml", dict(endpoints=[
            dict(host="first.example", sshPort=2221)]))
        (role / "config.d" / "99-ignored.txt").write_text("invalid: [", encoding="ascii")
        (role / "config.d" / "99-directory.yaml").mkdir()
        self.assertEqual(self.run_client("endpoint").stdout, b"last.example:2222\n")
        override = self.config(endpoints=[dict(host="override.example", sshPort=2223)])
        self.assertEqual(self.run_client("endpoint", config=override).stdout,
                         b"override.example:2223\n")

    def test_config_defaults_to_home_dot_config(self):
        env = self.env.copy()
        env.pop("XDG_CONFIG_HOME")
        root = Path(env["HOME"]) / ".config" / "pds" / "client"
        write_config(root / "config.yaml", dict(CLIENT_RESET, endpoints=[
            dict(host="home.example", sshPort=2222)]))
        self.assertEqual(self.run_client("endpoint", env=env).stdout, b"home.example:2222\n")

    def test_client_lists_union_and_empty_list_preserves_entries(self):
        server = self.server()
        role = Path(self.env["XDG_CONFIG_HOME"]) / "pds" / "client"
        write_config(role / "config.d" / "10-base.yaml", dict(
            endpoints=[server.client_endpoint], trustedKeys=[server.public_key],
            identities=[str(self.client_key)]))
        override = write_config(self.root / "override.yaml", dict(
            trustedKeys=[self.other_public, self.other_public], identities=[str(self.other_key)]))
        self.assertIn("scripts/", self.names(config=override))
        write_config(override, dict(trustedKeys=[], identities=[]))
        self.assertIn("scripts/", self.names(config=override))

    def test_server_layers_deep_merge_and_expand_home(self):
        server = Server(self)
        role = Path(server.env["XDG_CONFIG_HOME"]) / "pds" / "server"
        server.config["buckets"]["scripts"]["path"] = "~/scripts"
        scripts = Path(server.env["HOME"]) / "scripts"
        scripts.mkdir()
        (scripts / "home.txt").write_bytes(b"home expansion\n")
        write_config(role / "config.d" / "10-base.yaml", server.config)
        (role / "config.d" / "20-extra.yml").write_text(
            "authorizedKeys:\n  - host: node-b\n    keys:\n      - " + self.other_public +
            "\nbuckets:\n  metrics:\n    mode: RW\n    versioned: false\n", encoding="ascii")
        server.config = dict(buckets=dict(metrics=dict(extension="yml")))
        server.start(explicit_keys=False)
        for identity in (self.client_key, self.other_key):
            config = self.config(server, identities=[str(identity)])
            self.assertEqual(self.run_client("pull", "scripts/home.txt", config=config).stdout,
                             b"home expansion\n")
        config = self.config(server)
        self.assertEqual(metadata(self.run_client("meta", "metrics", config=config).stdout),
                         dict(mode="rw", versioned=False, byHost=True,
                              extension="yml", validator="yaml"))

    def test_server_discovers_user_config_and_default_host_key(self):
        server = Server(self)
        role = Path(server.env["XDG_CONFIG_HOME"]) / "pds" / "server"
        write_config(role / "config.d" / "10-server.yaml", server.config)
        server.start(explicit_config=False, explicit_keys=False)
        self.assertIn("scripts/", self.names(config=self.config(server)))

    def test_default_client_identity_is_discovered(self):
        server = self.server()
        ssh_dir = Path(self.env["HOME"]) / ".ssh"
        ssh_dir.mkdir()
        shutil.copyfile(self.client_key, ssh_dir / "id_ed25519")
        config = self.config(server, identities=[])
        self.run_client("push", "hosts", data=b"discovered", config=config)
        self.assertEqual((server.buckets["hosts"] / "node-a" / "latest.txt").read_bytes(),
                         b"discovered")
        config = self.config(server, identities=["~/.ssh/id_ed25519"])
        self.assertIn("scripts/", self.names(config=config))

    def test_pull_alias_listing_and_output_options(self):
        server = self.server()
        config = self.config(server)
        self.assertEqual(self.names(config=config),
                         {name + "/" for name in server.buckets} | {".pds/"})
        self.assertEqual(self.names(".pds", config=config), {"exec/"})
        self.assertEqual(self.names("scripts/nested", config=config), {"file.txt"})
        self.assertIn(".meta", self.names("scripts", config=config))
        expected = (server.buckets["scripts"] / "bytes.bin").read_bytes()
        for remote in ("scripts/bytes.bin", "/scripts/bytes.bin", ".pds/exec/bytes.bin"):
            self.assertEqual(self.run_client("pull", remote, config=config).stdout, expected)
        for option in ("-o", "--output"):
            output = self.root / "copy.bin"
            output.write_bytes(b"old content")
            self.assertEqual(self.run_client("pull", "scripts/bytes.bin", option, output,
                                             config=config).stdout, b"")
            self.assertEqual(output.read_bytes(), expected)

    def test_metadata_schema_and_read_only_defaults(self):
        server = self.server()
        config = self.config(server)
        for name in server.buckets:
            with self.subTest(bucket=name):
                bucket = server.config["buckets"][name]
                expected = dict(mode=bucket.get("mode", "ro"),
                                versioned=bucket.get("versioned", False),
                                byHost=bucket.get("byHost", False))
                if expected["mode"] == "rw":
                    expected.update(extension=bucket["extension"], validator=bucket["validator"])
                self.assertEqual(metadata(self.run_client("meta", name, config=config).stdout),
                                 expected)
                self.assertEqual(metadata(self.run_client("pull", name + "/.meta",
                                                          config=config).stdout), expected)

    def test_versioned_by_host_storage_and_self(self):
        server = self.server()
        config = self.config(server)
        directory = server.buckets["metrics"] / "node-a"
        payloads = (b"# retain bytes\r\na:  1\r\n", b"---\nb: 2\n---\nc: 3\n")
        for payload in payloads:
            self.run_client("push", "metrics", "-", config=config, data=payload)
            latest = directory / "latest.yaml"
            self.assertTrue(latest.is_symlink())
            target = os.readlink(latest)
            self.assertRegex(target, r"^\d{14}(?:-[1-9]\d*)?\.yaml$")
            datetime.datetime.strptime(target[:14], "%Y%m%d%H%M%S")
            self.assertEqual(latest.read_bytes(), payload)
            self.assertEqual(self.run_client("pull", "metrics/.self/latest.yaml",
                                             config=config).stdout, payload)
        self.assertEqual(len(list(directory.iterdir())), 3)
        stored = [p.read_bytes() for p in directory.iterdir() if not p.is_symlink()]
        self.assertCountEqual(stored, payloads)
        self.assertIn(".self/", self.names("metrics", config=config))
        self.assertEqual(self.names("metrics/.self", config=config),
                         {p.name for p in directory.iterdir()})

    def test_other_storage_layouts_and_file_push(self):
        server = self.server()
        config = self.config(server)
        payload = bytes(range(256)) * 400
        source = self.root / "upload.bin"
        source.write_bytes(payload)
        self.run_client("push", "raw", source, config=config)
        self.assertEqual((server.buckets["raw"] / "latest.bin").read_bytes(), payload)
        self.assertFalse((server.buckets["raw"] / "latest.bin").is_symlink())
        self.run_client("push", "raw", data=b"replacement\x00\xff", config=config)
        self.assertEqual(list(p.name for p in server.buckets["raw"].iterdir()), ["latest.bin"])
        self.assertEqual(self.run_client("pull", "raw/latest.bin", config=config).stdout,
                         b"replacement\x00\xff")
        self.run_client("push", "versioned", data=payload, config=config)
        latest = server.buckets["versioned"] / "latest.tar.gz"
        self.assertTrue(latest.is_symlink())
        self.assertRegex(os.readlink(latest), r"^\d{14}(?:-[1-9]\d*)?\.tar\.gz$")
        self.assertEqual(latest.read_bytes(), payload)
        self.run_client("push", "hosts", data=payload, config=config)
        latest = server.buckets["hosts"] / "node-a" / "latest.txt"
        self.assertFalse(latest.is_symlink())
        self.assertEqual(latest.read_bytes(), payload)

    def test_validators_preserve_bytes_and_reject_invalid_data(self):
        server = self.server()
        config = self.config(server)
        cases = {
            "raw": ([b"", b"\x00\xff"], []),
            "metrics": ([b"", b"a: 1\n", b"---\na: 1\n---\nb: 2\n"], [b"foo: [bar"]),
            "json": ([b'{ "a" : [1, 2] }\r\n', b"null", b"3", b"true"],
                     [b"", b'{"a":}', b"{} {}", b"1 2", b"{}garbage"]),
            "jsonl": ([b'{"a":1}\n\n{"b":2}', b"  1\r\nfalse\n", b"{}"],
                      [b"", b"  \n", b"{} {}\n", b'{\n"a":1\n}\n', b"{\n"]),
        }
        for bucket, (valid, invalid) in cases.items():
            ext = server.config["buckets"][bucket]["extension"]
            directory = server.buckets[bucket]
            if bucket == "metrics":
                directory /= "node-a"
            for payload in valid:
                with self.subTest(bucket=bucket, valid=payload):
                    self.run_client("push", bucket, data=payload, config=config)
                    self.assertEqual((directory / ("latest." + ext)).read_bytes(), payload)
            before = {p.name: p.read_bytes() for p in directory.iterdir()}
            for payload in invalid:
                with self.subTest(bucket=bucket, invalid=payload):
                    self.run_client("push", bucket, data=payload, config=config, code=None)
                    self.assertEqual({p.name: p.read_bytes() for p in directory.iterdir()}, before)

    def test_storage_creation_uses_umask(self):
        for mask in (0o022, 0o077, 0o002):
            with self.subTest(umask=oct(mask)):
                server = Server(self, umask=mask)
                for bucket in ("hosts", "metrics"):
                    server.buckets[bucket].chmod(0o750)
                server.start()
                config = self.config(server)
                for bucket, extension in (("hosts", "txt"), ("metrics", "yaml")):
                    self.run_client("push", bucket, config=config, data=b"value: 1\n")
                    root = server.buckets[bucket]
                    directory = root / "node-a"
                    latest = directory / ("latest." + extension)
                    self.assertEqual(root.stat().st_mode & 0o777, 0o750)
                    directory_mode = 0o755 if self.reference else 0o777
                    file_mode = 0o600 if self.reference else 0o666
                    self.assertEqual(directory.stat().st_mode & 0o777, directory_mode & ~mask)
                    self.assertEqual(latest.stat().st_mode & 0o777, file_mode & ~mask)

    def test_upload_size_limit_preserves_previous_file(self):
        server = self.server()
        config = self.config(server)
        payload = b"x" * (5 * 1024 * 1024)
        self.run_client("push", "raw", data=payload, config=config)
        self.run_client("push", "raw", data=payload + b"x", config=config, code=None)
        self.assertEqual((server.buckets["raw"] / "latest.bin").read_bytes(), payload)
        self.assertEqual({p.name for p in server.buckets["raw"].iterdir()}, {"latest.bin"})

    def test_missing_paths_and_write_only_or_read_only_targets(self):
        server = self.server()
        config = self.config(server)
        self.default_config(config)
        for args in (("pull", "missing/file"), ("pull", "scripts/missing"),
                     ("pull", "raw/.push"), ("meta", "missing"),
                     ("ls", "missing"), ("ls", "raw/.meta"),
                     ("push", "scripts"), ("push", "missing"),
                     ("push", "raw/subdirectory"), ("exec", "missing")):
            with self.subTest(args=args):
                self.run_client(*args, data=b"x", code=None)

    def test_operator_created_symlinks_over_ssh_and_http(self):
        server = self.server(anonymous=True, http=True)
        config = self.config(server)
        outside = server.root / "outside"
        outside.mkdir()
        payload = b"outside bucket\x00\xff\r\n"
        (outside / "file.txt").write_bytes(payload)
        scripts = server.buckets["scripts"]
        (scripts / "internal-file").symlink_to("nested/file.txt")
        (scripts / "internal-dir").symlink_to("nested")
        (scripts / "external-file").symlink_to(outside / "file.txt")
        (scripts / "external-dir").symlink_to(outside)
        for path, expected, external in (
            ("internal-file", b"nested\n", False),
            ("internal-dir/file.txt", b"nested\n", False),
            ("external-file", payload, True),
            ("external-dir/file.txt", payload, True),
        ):
            with self.subTest(path=path):
                remote = "scripts/" + path
                if self.reference and external:
                    self.run_client("pull", remote, config=config, code=None)
                    status, _, body = self.http(server, "/" + remote)
                    self.assertEqual(status, 500)
                    self.assertNotIn(expected, body)
                else:
                    self.assertEqual(self.run_client("pull", remote, config=config).stdout,
                                     expected)
                    self.assertEqual(self.http(server, "/" + remote)[::2], (200, expected))
        for path in ("internal-dir", "external-dir"):
            with self.subTest(directory=path):
                remote = "scripts/" + path
                if self.reference and path == "external-dir":
                    self.run_client("ls", remote, config=config, code=None)
                    self.assertEqual(self.http(server, "/" + remote)[0], 500)
                else:
                    self.assertEqual(self.names(remote, config=config), {"file.txt"})
                    status, _, body = self.http(server, "/" + remote)
                    self.assertEqual(status, 200)
                    self.assertEqual({entry["name"] for entry in json.loads(body)}, {"file.txt"})

    def test_by_host_upload_directory_symlinks(self):
        server = self.server()
        config = self.config(server)
        for bucket, payload in (("metrics", b"a:  1\r\n# retain bytes\r\n"),
                                ("hosts", b"host bytes\x00\xff\r\n")):
            for external in (False, True):
                with self.subTest(bucket=bucket, external=external):
                    directory = (server.root if external else server.buckets[bucket]) / "uploads"
                    directory.mkdir()
                    link = server.buckets[bucket] / "node-a"
                    link.symlink_to(directory if external else "uploads")
                    self.run_client("push", bucket, config=config, data=payload)
                    latest = directory / ("latest." + server.config["buckets"][bucket]["extension"])
                    self.assertTrue(link.is_symlink())
                    self.assertEqual(latest.read_bytes(), payload)
                    self.assertEqual(latest.is_symlink(), bucket == "metrics")
                    if bucket == "metrics":
                        target = os.readlink(latest)
                        self.assertRegex(target, r"^\d{14}(?:-[1-9]\d*)?\.yaml$")
                        self.assertEqual({p.name for p in directory.iterdir()}, {"latest.yaml", target})
                    else:
                        self.assertEqual({p.name for p in directory.iterdir()}, {"latest.txt"})
                    link.unlink()
                    shutil.rmtree(directory)

    def test_lexical_path_normalization(self):
        server = self.server(anonymous=True, http=True)
        config = self.config(server)
        (server.buckets["scripts"].parent / "outside.txt").write_bytes(b"outside bucket")
        for remote in ("scripts/nested/../nested/file.txt",
                       "/scripts/../../scripts/nested/file.txt"):
            with self.subTest(path=remote):
                self.assertEqual(self.run_client("pull", remote, config=config).stdout, b"nested\n")
                self.assertEqual(self.http(server, "/" + remote.lstrip("/"))[::2], (200, b"nested\n"))
        self.run_client("pull", "scripts/../outside.txt", config=config, code=None)
        self.assertEqual(self.http(server, "/scripts/../outside.txt")[0], 404)

    def test_anonymous_and_unknown_key_fallback_are_read_only(self):
        server = self.server(anonymous=True)
        for identities in ([], [str(self.other_key)]):
            with self.subTest(identities=bool(identities)):
                config = self.config(server, identities=identities)
                self.assertEqual(self.run_client("pull", ".pds/exec/check.sh",
                                                 config=config).stdout, SCRIPT)
                self.assertIn("scripts/", self.names(config=config))
                self.assertNotIn(".self/", self.names("metrics", config=config))
                self.run_client("push", "metrics", data=b"a: 1\n", config=config, code=None)
                self.run_client("pull", "metrics/.self/latest.yaml", config=config, code=None)
        config = self.config(server)
        self.run_client("push", "metrics", data=b"a: 1\n", config=config)
        self.assertEqual((server.buckets["metrics"] / "node-a" / "latest.yaml").read_bytes(),
                         b"a: 1\n")

    def test_anonymous_server_can_run_without_authorized_keys(self):
        server = self.server(anonymous=True, authorized=[])
        self.assertIn("scripts/", self.names(config=self.config(server, identities=[])))

    def test_anonymous_is_disabled_by_default_and_unknown_key_is_rejected(self):
        server = Server(self)
        server.config.pop("allowAnonymous")
        server.start()
        for identities in ([], [str(self.other_key)]):
            self.run_client("ls", config=self.config(server, identities=identities), code=None)

    def test_exec_arguments_environment_streams_exit_and_cleanup(self):
        server = self.server()
        config = self.config(server)
        self.default_config(config)
        env = dict(self.env, PDS_TEST_VALUE="a value with spaces")
        result = self.run_client("exec", "check.sh", "--config", "value with spaces", "",
                                 "-x", "--", "-", data=b"script stdin\n",
                                 env=env, code=23)
        expected = ("name=check.sh\nendpoint=" + server.endpoint +
                    "\ncustom=a value with spaces\ncwd=" + str(self.root) +
                    "\narg=<--config>\narg=<value with spaces>\narg=<>\narg=<-x>\n"
                    "arg=<-->\narg=<->\nscript stdin\n").encode()
        self.assertEqual(result.stdout, expected)
        self.assertEqual(result.stderr, b"script stderr\n")
        self.assertEqual(list(Path(env["TMPDIR"]).iterdir()), [])

    def test_exec_child_can_reinvoke_client_with_selected_endpoint(self):
        server = self.server()
        config = self.config(server, endpoints=[self.unavailable_endpoint(), server.client_endpoint])
        self.default_config(config)
        (server.buckets["scripts"] / "again.sh").write_bytes(
            b'#!/bin/sh\npds endpoint\npds pull scripts/nested/file.txt\n')
        tools = self.root / "tools"
        tools.mkdir()
        (tools / "pds").symlink_to(self.client_binary)
        env = dict(self.env, PATH=str(tools) + os.pathsep + self.env.get("PATH", ""))
        result = self.run_client("exec", "again.sh", env=env)
        self.assertEqual(result.stdout, (server.endpoint + "\nnested\n").encode())

    def test_cli_standard_options_and_standalone_dash(self):
        server = self.server()
        config = self.config(server)
        self.assertIn("scripts/", self.names(config=config))
        for prefix in (("-c", str(config)), ("--config=" + str(config),)):
            self.assertIn(b"scripts/\n", self.run_client(*prefix, "ls").stdout)
        self.assertIn(b"scripts/\n", self.run_client("ls", "-c", config).stdout)
        self.assertIn(b"scripts/\n", self.run_client("ls", "--config", config).stdout)
        dash = server.buckets["scripts"] / "-"
        dash.write_bytes(b"dash file\n")
        self.assertEqual(self.run_client("pull", "--", "scripts/-", config=config).stdout,
                         b"dash file\n")
        self.run_client("pull", "scripts/-", "-o", "-", config=config)
        self.assertEqual((self.root / "-").read_bytes(), b"dash file\n")
        source = self.root / "-upload"
        source.write_bytes(b"dash filename\n")
        self.run_client("push", "--", "raw", "-upload", config=config)
        self.assertEqual((server.buckets["raw"] / "latest.bin").read_bytes(), b"dash filename\n")
        self.run_client("push", "raw", "-", config=config, data=b"stdin dash\n")
        self.assertEqual((server.buckets["raw"] / "latest.bin").read_bytes(), b"stdin dash\n")

    def test_cli_usage_and_invalid_options_fail(self):
        self.run_client(code=2)
        for args in (("--help",), ("-h",), ("pull", "--help"),
                     ("ls", "--help"), ("endpoint", "--help")):
            self.run_client(*args)
        for args in (("unknown-command",), ("pull",), ("pull", "a", "b"),
                     ("push",), ("push", "a", "b", "c"), ("ls", "a", "b"),
                     ("meta",), ("meta", "a", "b"), ("exec",),
                     ("endpoint", "extra"), ("endpoint", "--ssh", "--http"),
                     ("--unknown",), ("ls", "--unknown"), ("-config", "x", "ls")):
            with self.subTest(args=args):
                self.run_client(*args, code=None)

    def test_http_get_head_range_and_conditional_read(self):
        server = self.server(anonymous=True, http=True)
        expected = (server.buckets["scripts"] / "bytes.bin").read_bytes()
        status, headers, body = self.http(server, "/scripts/bytes.bin")
        self.assertEqual((status, body), (200, expected))
        self.assertEqual(int(headers["content-length"]), len(expected))
        self.assertEqual(headers["accept-ranges"], "bytes")
        status, head, body = self.http(server, "/scripts/bytes.bin", "HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(int(head["content-length"]), len(expected))
        for value, chunk, content_range in (
            ("bytes=2-5", expected[2:6], "bytes 2-5/768"),
            ("bytes=-4", expected[-4:], "bytes 764-767/768"),
            ("bytes=764-", expected[764:], "bytes 764-767/768"),
        ):
            with self.subTest(range=value):
                status, ranged, body = self.http(server, "/scripts/bytes.bin",
                                                 headers={"Range": value})
                self.assertEqual((status, body), (206, chunk))
                self.assertEqual(ranged["content-range"], content_range)
        status, _, _ = self.http(server, "/scripts/bytes.bin", headers={"Range": "bytes=900-"})
        self.assertEqual(status, 416)
        status, _, body = self.http(server, "/scripts/bytes.bin",
                                    headers={"If-Modified-Since": headers["last-modified"]})
        self.assertEqual((status, body), (304, b""))

    def test_http_listing_metadata_alias_and_anonymous_policy(self):
        server = self.server(anonymous=True, http=True)
        for path, names in (("/", set(server.buckets) | {".pds"}),
                            ("/.pds", {"exec"}),
                            ("/scripts/nested", {"file.txt"})):
            with self.subTest(path=path):
                status, headers, body = self.http(server, path)
                self.assertEqual(status, 200)
                self.assertEqual(headers["content-type"].split(";")[0], "application/json")
                entries = json.loads(body)
                self.assertEqual({entry["name"] for entry in entries}, names)
                for entry in entries:
                    self.assertEqual(set(entry), {"name", "size", "isDir", "modTime"})
                    self.assertIsInstance(entry["size"], int)
                    self.assertIsInstance(entry["isDir"], bool)
                    datetime.datetime.fromisoformat(entry["modTime"].replace("Z", "+00:00"))
        status, _, body = self.http(server, "/metrics")
        self.assertEqual(status, 200)
        entries = json.loads(body)
        self.assertIn(".meta", {entry["name"] for entry in entries})
        self.assertNotIn(".self", {entry["name"] for entry in entries})
        self.assertEqual(self.http(server, "/.pds/exec/check.sh")[2], SCRIPT)
        status, headers, body = self.http(server, "/metrics/.meta")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"].split(";")[0], "application/yaml")
        self.assertEqual(metadata(body), dict(mode="rw", versioned=True, byHost=True,
                                              extension="yaml", validator="yaml"))
        for path in ("/", "/scripts", "/metrics/.meta"):
            self.assertEqual(self.http(server, path, "HEAD")[::2], (200, b""))
        for path in ("/missing", "/scripts/missing", "/metrics/.self/latest.yaml",
                     "/metrics/.push", "/.pds/missing"):
            self.assertEqual(self.http(server, path)[0], 404, path)
        for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
            self.assertEqual(self.http(server, "/metrics", method)[0], 405, method)
        self.run_client("push", "raw", data=b"shared bytes\x00", config=self.config(server))
        self.assertEqual(self.http(server, "/raw/latest.bin")[::2], (200, b"shared bytes\x00"))

    def unavailable_endpoint(self, *, stall=False):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        stop = threading.Event()
        connections = []

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                if stall:
                    connections.append(conn)
                else:
                    conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        def close():
            stop.set()
            thread.join(timeout=2)
            listener.close()
            for conn in connections:
                conn.close()
            self.assertFalse(thread.is_alive(), "endpoint fixture did not stop")

        self.addCleanup(close)
        return dict(host="127.0.0.1", sshPort=listener.getsockname()[1])

    def test_failover_handles_closed_and_stalled_ssh_handshakes(self):
        server = self.server()
        for stall in (False, True):
            with self.subTest(stall=stall):
                config = self.config(server, endpoints=[self.unavailable_endpoint(stall=stall),
                                                        server.client_endpoint])
                started = time.monotonic()
                self.assertIn("scripts/", self.names(config=config))
                self.assertLess(time.monotonic() - started, 5)
                if stall:
                    self.assertGreaterEqual(time.monotonic() - started, 1)
                self.default_config(config)
                result = self.run_client("exec", "check.sh", code=23)
                self.assertIn(("endpoint=" + server.endpoint + "\n").encode(), result.stdout)

    def test_first_usable_endpoint_and_environment_override(self):
        primary = self.server()
        backup = self.server()
        (primary.buckets["scripts"] / "marker").write_bytes(b"primary")
        (backup.buckets["scripts"] / "marker").write_bytes(b"backup")
        config = self.config(primary, endpoints=[primary.client_endpoint, backup.client_endpoint])
        self.assertEqual(self.run_client("pull", "scripts/marker", config=config).stdout, b"primary")
        env = dict(self.env, PDS_ENDPOINT=backup.endpoint)
        self.assertEqual(self.run_client("pull", "scripts/marker", config=config, env=env).stdout,
                         b"backup")
        failed = self.unavailable_endpoint()
        env["PDS_ENDPOINT"] = "127.0.0.1:" + str(failed["sshPort"])
        self.run_client("ls", config=config, env=env, code=None)

    def test_untrusted_primary_is_terminal_before_healthy_backup(self):
        primary = self.server()
        backup = self.server(host_key=self.other_key)
        trusted = [backup.public_key]
        self.assertIn("scripts/", self.names(config=self.config(backup, trustedKeys=trusted)))
        config = self.config(backup, endpoints=[primary.client_endpoint, backup.client_endpoint],
                             trustedKeys=trusted)
        self.run_client("ls", config=config, code=None)

    def test_authentication_failure_is_terminal_before_healthy_backup(self):
        primary = self.server(authorized=[dict(host="node-b", keys=[self.other_public])])
        backup = self.server()
        self.assertIn("scripts/", self.names(config=self.config(backup)))
        config = self.config(backup, endpoints=[primary.client_endpoint, backup.client_endpoint])
        self.run_client("ls", config=config, code=None)

    def test_all_unavailable_endpoints_fail(self):
        config = self.config(endpoints=[self.unavailable_endpoint(), self.unavailable_endpoint()],
                             trustedKeys=[self.host_public])
        self.run_client("ls", config=config, code=None)

    def test_client_config_validation_and_unknown_fields(self):
        server = self.server()
        valid_endpoint = server.client_endpoint
        cases = [dict(endpoints=[]), dict(endpoints=[dict(host="", sshPort=22)]),
                 dict(endpoints=[dict(host="localhost", sshPort=0)]),
                 dict(endpoints=[dict(host="localhost", sshPort=65536)]),
                 dict(endpoints=[dict(host="localhost", sshPort=22, httpPort=-1)]),
                 dict(endpoints=[dict(host="localhost", sshPort=22, httpPort=65536)]),
                 dict(endpoints=[dict(valid_endpoint, typo=True)]),
                 dict(endpoints=[dict(host="LOCALHOST", sshPort=22),
                                 dict(host="localhost", sshPort=22)]),
                 dict(endpoints=[dict(host="::1", sshPort=22), dict(host="[::1]", sshPort=22)]),
                 dict(trustedKeys=[]), dict(trustedKeys=["bad key"]),
                 dict(identities=[str(self.root / "missing-key")]),
                 dict(dialTimeout="0s"), dict(dialTimeout="-1s"), dict(dialTimeout="invalid"),
                 dict(host="legacy.example"), dict(sshPort=22), dict(unknown=True)]
        for updates in cases:
            with self.subTest(updates=updates):
                self.run_client("ls", config=self.config(server, **updates), code=None)
        invalid = self.root / "invalid.yaml"
        invalid.write_text("endpoints: [", encoding="ascii")
        self.run_client("endpoint", config=invalid, code=None)
        write_config(invalid, {"unknown": True})
        self.run_client("endpoint", config=invalid, code=None)
        self.run_client("endpoint", config=self.root / "absent.yaml", code=None)

    def test_server_config_validation_and_missing_host_keys(self):
        server = Server(self)
        cases = [dict(sshListen=""), dict(sshListen="localhost"),
                 dict(sshListen="iface::22"), dict(sshListen="iface:bad/name:22"),
                 dict(httpListen="127.0.0.1:0", allowAnonymous=False),
                 dict(authorizedKeys=[], allowAnonymous=False),
                 dict(authorizedKeys=[dict(host="", keys=[self.client_public])]),
                 dict(authorizedKeys=[dict(host="node", keys=[])]),
                 dict(authorizedKeys=[dict(host="node", keys=["bad key"])]),
                 dict(execBucket="missing"), dict(execBucket="raw"), dict(unknown=True)]
        for bucket in (dict(path=""), dict(path="x", mode="bad"), dict(path="x", typo=True),
                       dict(path="x", mode="rw", extension="yaml"),
                       dict(path="x", mode="rw", extension="yaml", validator="unknown"),
                       *[dict(path="x", mode="rw", extension=ext, validator="none")
                         for ext in ("", "../x", "/x", ".", "..", "a/b", "x..")]):
            cases.append(dict(buckets=dict(bad=bucket)))
        cases.append(dict(buckets={".hidden": dict(path="x")}))
        for updates in cases:
            with self.subTest(updates=updates):
                config = dict(server.config, **updates)
                if "buckets" in updates:
                    config["buckets"] = dict(server.config["buckets"], **updates["buckets"])
                path = write_config(server.root / "invalid.yaml", config)
                result = subprocess.run([self.server_binary, "--config", str(path),
                                         "--ssh-dir", str(server.ssh_dir)], env=server.env,
                                        capture_output=True, timeout=5)
                self.assertGreater(result.returncode, 0, result.stderr)
        empty = server.root / "empty-keys"
        empty.mkdir()
        write_config(server.config_path, server.config)
        result = subprocess.run([self.server_binary, "--config", str(server.config_path),
                                 "--ssh-dir", str(empty)], env=server.env,
                                capture_output=True, timeout=5)
        self.assertGreater(result.returncode, 0, result.stderr)


def binaries(required, optional):
    result = []
    for label, variable in (("candidate", required), ("reference", optional)):
        value = os.environ.get(variable)
        if not value:
            if label == "candidate":
                raise SystemExit(variable + " must name an executable")
            continue
        path = Path(value).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise SystemExit(variable + " is not an executable file: " + str(path))
        result.append((label, str(path)))
    return result


def load_tests(loader, tests, pattern):
    if not shutil.which("ssh-keygen"):
        raise SystemExit("ssh-keygen is required to generate disposable Ed25519 keys")
    clients = binaries("PDS_BIN", "PDS_REFERENCE_BIN")
    servers = binaries("PDSD_BIN", "PDSD_REFERENCE_BIN")
    suite = unittest.TestSuite()
    for client_label, client_binary in clients:
        for server_label, server_binary in servers:
            case = type("Compat_" + client_label + "_client_" + server_label + "_server",
                        (Compat,), dict(client_binary=client_binary, server_binary=server_binary,
                                        reference=server_label == "reference"))
            suite.addTests(loader.loadTestsFromTestCase(case))
    return suite


if __name__ == "__main__":
    unittest.main(verbosity=2)
