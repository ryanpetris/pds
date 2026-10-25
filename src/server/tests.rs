use std::{collections::BTreeMap, sync::Arc, time::Duration};

use http_body_util::BodyExt;
use hyper::{Request, StatusCode};
use russh::{
    ChannelMsg, client,
    keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate},
};
use russh_sftp::client::SftpSession;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::TcpListener,
};
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{
    config::{self, Bucket, ClientEntry, Mode},
    keys::{Algorithm, PrivateKey},
    validate::Validator,
};

fn key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

struct Fixture {
    dir: tempfile::TempDir,
    server: Server,
    client_key: PrivateKey,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let client_key = key();
        let config = config::Server {
            ssh_listen: "127.0.0.1:0".into(),
            allow_anonymous: true,
            exec_bucket: "scripts".into(),
            authorized_keys: vec![ClientEntry {
                host: "writer".into(),
                keys: vec![client_key.public_key().to_openssh().unwrap()],
            }],
            buckets: BTreeMap::from([
                (
                    "data".into(),
                    Bucket {
                        path: dir.path().join("data"),
                        mode: Mode::ReadWrite,
                        by_host: true,
                        versioned: true,
                        extension: "json".into(),
                        validator: Validator::Json,
                    },
                ),
                (
                    "raw".into(),
                    Bucket {
                        path: dir.path().join("raw"),
                        mode: Mode::ReadWrite,
                        by_host: false,
                        versioned: false,
                        extension: "bin".into(),
                        validator: Validator::None,
                    },
                ),
                (
                    "scripts".into(),
                    Bucket {
                        path: dir.path().join("scripts"),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        for bucket in config.buckets.values() {
            std::fs::create_dir_all(&bucket.path).unwrap();
        }
        std::fs::write(dir.path().join("scripts/run"), b"#!/bin/sh\necho ok\n").unwrap();
        std::fs::write(dir.path().join("raw/sample"), b"0123456789").unwrap();
        std::fs::write(dir.path().join("raw/empty"), b"").unwrap();
        let server = Server::new(config, vec![key()]).unwrap();
        Self {
            dir,
            server,
            client_key,
        }
    }

    async fn start(
        &self,
    ) -> (
        std::net::SocketAddr,
        CancellationToken,
        tokio::task::JoinHandle<Result<()>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stop = CancellationToken::new();
        let task = tokio::spawn(self.server.clone().serve(listener, stop.clone()));
        (addr, stop, task)
    }
}

struct Pinned(crate::keys::PublicKey);
impl client::Handler for Pinned {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(matches!(key, PublicKeyOrCertificate::PublicKey { key, .. } if *key == self.0))
    }
}

async fn connect(
    fixture: &Fixture,
    addr: std::net::SocketAddr,
    anonymous: bool,
) -> (client::Handle<Pinned>, SftpSession) {
    let mut config = client::Config::default();
    config.preferred.key = std::borrow::Cow::Owned(vec![Algorithm::Ed25519]);
    let mut client = client::connect(
        Arc::new(config),
        addr,
        Pinned(fixture.server.ssh.keys[0].public_key().clone()),
    )
    .await
    .unwrap();
    if anonymous {
        assert!(!client.authenticate_none("someone").await.unwrap().success());
        assert!(
            client
                .authenticate_none(config::ANONYMOUS_USER)
                .await
                .unwrap()
                .success()
        );
    } else {
        assert!(
            client
                .authenticate_publickey(
                    "pds",
                    PrivateKeyWithHashAlg::new(Arc::new(fixture.client_key.clone()), None)
                )
                .await
                .unwrap()
                .success()
        );
    }
    let mut channel = client.channel_open_session().await.unwrap();
    channel.request_subsystem(true, "sftp").await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Success)));
    let sftp = SftpSession::new(channel.into_stream()).await.unwrap();
    (client, sftp)
}

#[test]
fn host_keys_and_anonymous_configuration() {
    let ec = PrivateKey::random(
        &mut rand::rng(),
        Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let config = config::Server {
        allow_anonymous: true,
        ..Default::default()
    };
    assert!(Server::new(config.clone(), vec![]).is_err());
    assert!(Server::new(config.clone(), vec![ec.clone()]).is_err());
    let last = key();
    let server = Server::new(config.clone(), vec![key(), ec.clone(), last.clone()]).unwrap();
    assert_eq!(server.ssh.keys.len(), 1);
    assert_eq!(server.ssh.keys[0].public_key(), last.public_key());
    assert_eq!(server.ssh.inactivity_timeout, None);
    let mut config = config::Server {
        authorized_keys: vec![ClientEntry {
            host: "writer".into(),
            keys: vec![ec.public_key().to_openssh().unwrap()],
        }],
        ..config
    };
    assert!(Server::new(config.clone(), vec![key()]).is_ok());
    config.allow_anonymous = false;
    assert!(Server::new(config, vec![key()]).is_err());
}

#[tokio::test]
async fn sftp_push_validation_offsets_reads_and_anonymous_permissions() {
    let fixture = Fixture::new();
    let (addr, stop, task) = fixture.start().await;
    let (client, sftp) = connect(&fixture, addr, false).await;
    let bytes = b"{\"value\":  12}\n";
    let mut upload = sftp.create("data/.push").await.unwrap();
    upload.seek(std::io::SeekFrom::Start(8)).await.unwrap();
    upload.write_all(&bytes[8..]).await.unwrap();
    upload.seek(std::io::SeekFrom::Start(0)).await.unwrap();
    upload.write_all(&bytes[..8]).await.unwrap();
    upload.close().await.unwrap();
    assert_eq!(
        std::fs::read(fixture.dir.path().join("data/writer/latest.json")).unwrap(),
        bytes
    );
    assert_eq!(sftp.read("data/.self/latest.json").await.unwrap(), bytes);
    assert_eq!(
        sftp.read("/.pds/exec/run").await.unwrap(),
        b"#!/bin/sh\necho ok\n"
    );
    let meta: serde_yaml_ng::Value =
        serde_yaml_ng::from_slice(&sftp.read("data/.meta").await.unwrap()).unwrap();
    assert_eq!(meta["byHost"], true);
    assert_eq!(meta["extension"], "json");
    let mut bad = sftp.create("data/.push").await.unwrap();
    bad.write_all(b"{").await.unwrap();
    assert!(bad.close().await.is_err());
    assert_eq!(
        std::fs::read(fixture.dir.path().join("data/writer/latest.json")).unwrap(),
        bytes
    );
    for path in ["data/file", "scripts/.push", "data/writer/latest.json"] {
        assert!(sftp.create(path).await.is_err());
    }
    assert!(sftp.create_dir("data/new").await.is_err());
    assert!(sftp.remove_file("data/.self/latest.json").await.is_err());
    assert!(sftp.rename("raw/sample", "raw/new").await.is_err());
    assert!(sftp.symlink("raw/new", "raw/sample").await.is_err());
    assert!(sftp.read_link("data/writer/latest.json").await.is_err());
    assert_eq!(
        sftp.canonicalize("/data/../raw/./sample").await.unwrap(),
        "/raw/sample"
    );
    let entries: Vec<_> = sftp
        .read_dir("data")
        .await
        .unwrap()
        .map(|e| e.file_name())
        .collect();
    assert!(entries.contains(&".self".into()));
    assert!(entries.contains(&".meta".into()));
    assert!(!entries.contains(&".push".into()));
    let (anon_client, anon) = connect(&fixture, addr, true).await;
    assert_eq!(anon.read("data/writer/latest.json").await.unwrap(), bytes);
    assert!(anon.read("data/.self/latest.json").await.is_err());
    assert!(anon.create("raw/.push").await.is_err());
    assert!(matches!(
        anon.create("missing/.push").await,
        Err(russh_sftp::client::error::Error::Status(status))
            if status.status_code == russh_sftp::protocol::StatusCode::PermissionDenied
    ));
    let entries: Vec<_> = anon
        .read_dir("data")
        .await
        .unwrap()
        .map(|e| e.file_name())
        .collect();
    assert!(!entries.contains(&".self".into()));
    sftp.close().await.unwrap();
    anon.close().await.unwrap();
    client
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    anon_client
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await
        .unwrap();
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn disconnect_discards_unclosed_valid_upload() {
    let fixture = Fixture::new();
    let (addr, stop, task) = fixture.start().await;
    let (client, sftp) = connect(&fixture, addr, false).await;
    let mut upload = sftp.create("raw/.push").await.unwrap();
    upload.write_all(b"partial valid bytes").await.unwrap();
    upload.flush().await.unwrap();
    client
        .disconnect(russh::Disconnect::ByApplication, "source read failed", "")
        .await
        .unwrap();
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!fixture.dir.path().join("raw/latest.bin").exists());
    assert!(
        !std::fs::read_dir(fixture.dir.path().join("raw"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".tmp-"))
    );
    drop(upload);
    drop(sftp);
}

#[tokio::test]
async fn sparse_offsets_and_sticky_oversize_errors() {
    let fixture = Fixture::new();
    let (mut handler, done) = sftp::Sftp::new(
        fs::View {
            config: fixture.server.config.clone(),
            host: Some("writer".into()),
        },
        fixture.server.committer.clone(),
    );
    use russh_sftp::{
        protocol::{FileAttributes, OpenFlags},
        server::Handler,
    };
    let handle = handler
        .open(
            1,
            "raw/.push".into(),
            OpenFlags::WRITE,
            FileAttributes::default(),
        )
        .await
        .unwrap()
        .handle;
    handler
        .write(2, handle.clone(), 5, b"end".to_vec())
        .await
        .unwrap();
    handler.close(3, handle.clone()).await.unwrap();
    assert_eq!(
        std::fs::read(fixture.dir.path().join("raw/latest.bin")).unwrap(),
        b"\0\0\0\0\0end"
    );
    assert!(handler.close(4, handle).await.is_err());
    let handle = handler
        .open(
            5,
            "raw/.push".into(),
            OpenFlags::WRITE,
            FileAttributes::default(),
        )
        .await
        .unwrap()
        .handle;
    assert!(
        handler
            .write(6, handle.clone(), store::MAX_PUSH, vec![1])
            .await
            .is_err()
    );
    handler
        .write(7, handle.clone(), 0, b"ok".to_vec())
        .await
        .unwrap();
    assert!(handler.close(8, handle).await.is_err());
    let handle = handler
        .open(
            9,
            "raw/.push".into(),
            OpenFlags::WRITE,
            FileAttributes::default(),
        )
        .await
        .unwrap()
        .handle;
    assert!(
        handler
            .write(10, handle.clone(), u64::MAX, vec![1])
            .await
            .is_err()
    );
    assert!(handler.close(11, handle).await.is_err());
    assert_eq!(
        std::fs::read(fixture.dir.path().join("raw/latest.bin")).unwrap(),
        b"\0\0\0\0\0end"
    );
    drop(handler);
    let _ = done.await;
}

async fn http(
    server: &Server,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, hyper::HeaderMap, Bytes) {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = server.http_response(request.body(()).unwrap()).await;
    let (parts, body) = response.into_parts();
    (
        parts.status,
        parts.headers,
        body.collect().await.unwrap().to_bytes(),
    )
}
use bytes::Bytes;

#[tokio::test]
async fn http_ranges_head_preconditions_and_virtual_entries() {
    let fixture = Fixture::new();
    let (status, headers, bytes) = http(&fixture.server, "GET", "/raw/sample", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bytes, "0123456789");
    assert_eq!(headers["content-type"], "text/plain; charset=utf-8");
    assert_eq!(headers["accept-ranges"], "bytes");
    let modified = headers["last-modified"].to_str().unwrap();
    for (range, expected) in [
        ("bytes=2-5", "2345"),
        ("bytes=-3", "789"),
        ("bytes=8-", "89"),
        ("bytes=20-,0-1", "01"),
    ] {
        let (status, headers, bytes) =
            http(&fixture.server, "GET", "/raw/sample", &[("range", range)]).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(bytes, expected);
        assert_eq!(headers["content-length"], expected.len().to_string());
    }
    let (status, headers, bytes) = http(
        &fixture.server,
        "GET",
        "/raw/sample",
        &[("range", "bytes=0-1,8-9")],
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert!(
        headers["content-type"]
            .to_str()
            .unwrap()
            .starts_with("multipart/byteranges; boundary=")
    );
    assert_eq!(headers["content-length"], bytes.len().to_string());
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("Content-Range: bytes 0-1/10\r\n"));
    assert!(text.contains("\r\n\r\n01\r\n"));
    assert!(text.contains("\r\n\r\n89\r\n"));
    let (status, headers, bytes) = http(
        &fixture.server,
        "HEAD",
        "/raw/sample",
        &[("range", "bytes=2-5")],
    )
    .await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers["content-length"], "4");
    assert!(bytes.is_empty());
    let (status, headers, _) = http(
        &fixture.server,
        "GET",
        "/raw/sample",
        &[("range", "bytes=99-")],
    )
    .await;
    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(headers["content-range"], "bytes */10");
    assert!(!headers.contains_key("last-modified"));
    assert_eq!(
        http(
            &fixture.server,
            "GET",
            "/raw/empty",
            &[("range", "bytes=0-")]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        http(
            &fixture.server,
            "GET",
            "/raw/sample",
            &[("range", "bytes=0-9,0-9")]
        )
        .await
        .0,
        StatusCode::OK
    );
    for headers in [
        vec![("if-none-match", "*")],
        vec![("if-modified-since", modified)],
    ] {
        let (status, headers, bytes) = http(&fixture.server, "GET", "/raw/sample", &headers).await;
        assert_eq!(status, StatusCode::NOT_MODIFIED);
        assert!(!headers.contains_key("content-type"));
        assert!(bytes.is_empty());
    }
    assert_eq!(
        http(
            &fixture.server,
            "GET",
            "/raw/sample",
            &[("if-match", "\"missing\"")]
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        http(
            &fixture.server,
            "GET",
            "/raw/sample",
            &[("if-unmodified-since", "Thu, 01 Jan 1970 00:00:01 GMT")]
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        http(
            &fixture.server,
            "GET",
            "/raw/sample",
            &[
                ("if-none-match", "\"missing\""),
                ("if-modified-since", modified)
            ]
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        http(
            &fixture.server,
            "GET",
            "/raw/sample",
            &[("range", "bytes=0-1"), ("if-range", modified)]
        )
        .await
        .0,
        StatusCode::PARTIAL_CONTENT
    );
    assert_eq!(
        http(
            &fixture.server,
            "GET",
            "/raw/sample",
            &[
                ("range", "bytes=0-1"),
                ("if-range", "Thu, 01 Jan 2099 00:00:00 GMT")
            ]
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, headers, bytes) = http(
        &fixture.server,
        "GET",
        "/data/.meta",
        &[("range", "bytes=0-1"), ("if-none-match", "*")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/yaml");
    assert!(bytes.len() > 2);
    let (_, _, bytes) = http(&fixture.server, "GET", "/data", &[]).await;
    let entries: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(entries[0]["name"], ".meta");
    assert_eq!(entries[0]["modTime"], "1970-01-01T00:00:00Z");
    assert_eq!(entries[0].as_object().unwrap().len(), 4);
    for path in ["/data/.self", "/data/.push", "/.pds/missing", "/missing"] {
        assert_eq!(
            http(&fixture.server, "GET", path, &[]).await.0,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        http(&fixture.server, "POST", "/raw/sample", &[]).await.0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        http(&fixture.server, "GET", "/.pds/exec/run", &[]).await.2,
        "#!/bin/sh\necho ok\n"
    );
}

#[tokio::test]
async fn ordinary_symlinks_follow_outside_buckets() {
    let fixture = Fixture::new();
    std::fs::write(fixture.dir.path().join("external"), b"outside").unwrap();
    std::os::unix::fs::symlink("../external", fixture.dir.path().join("raw/link")).unwrap();
    assert_eq!(
        http(&fixture.server, "GET", "/raw/link", &[]).await.2,
        "outside"
    );
    let (addr, stop, task) = fixture.start().await;
    let (_, sftp) = connect(&fixture, addr, true).await;
    assert_eq!(sftp.read("raw/link").await.unwrap(), b"outside");
    assert_eq!(sftp.symlink_metadata("raw/link").await.unwrap().len(), 7);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn ssh_rejects_other_requests_and_channels() {
    let fixture = Fixture::new();
    let (addr, stop, task) = fixture.start().await;
    let (client, _) = connect(&fixture, addr, false).await;
    let mut channel = client.channel_open_session().await.unwrap();
    channel.exec(true, b"id".as_slice()).await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
    channel.request_shell(true).await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
    channel.request_subsystem(true, "other").await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
    channel.set_env(true, "PATH", "/").await.unwrap();
    assert!(matches!(channel.wait().await, Some(ChannelMsg::Failure)));
    assert!(
        client
            .channel_open_direct_tcpip("localhost", 1, "localhost", 1)
            .await
            .is_err()
    );
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test(start_paused = true)]
async fn pre_auth_deadline_covers_idle_auth_and_clears_on_success() {
    let fixture = Fixture::new();
    let (addr, stop, task) = fixture.start().await;
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut identification = [0; 128];
    assert!(socket.read(&mut identification).await.unwrap() > 0);
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(socket.read(&mut identification).await.unwrap(), 0);
    tokio::time::resume();
    let client = client::connect(
        Arc::new(client::Config::default()),
        addr,
        Pinned(fixture.server.ssh.keys[0].public_key().clone()),
    )
    .await
    .unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::time::resume();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !client.is_closed() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (client, sftp) = connect(&fixture, addr, true).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(1200)).await;
    tokio::time::resume();
    assert_eq!(sftp.read("raw/sample").await.unwrap(), b"0123456789");
    assert!(!client.is_closed());
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn shared_connection_limit_rejects_without_waiting() {
    let fixture = Fixture::new();
    let (addr, stop, task) = fixture.start().await;
    let permits = fixture
        .server
        .connections
        .clone()
        .acquire_many_owned(MAX_CONNECTIONS as u32)
        .await
        .unwrap();
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut byte = [0];
    let read = tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0)) || read.is_err());
    drop(permits);
    let (_, sftp) = connect(&fixture, addr, true).await;
    assert_eq!(sftp.read("raw/sample").await.unwrap(), b"0123456789");
    stop.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn http_listener_close_ends_active_connections() {
    let fixture = Fixture::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let server = fixture.server.clone();
    let child_stop = stop.clone();
    let task = tokio::spawn(async move { server.accept_http(listener, child_stop).await });
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(b"GET /raw/sample HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut buffer = [0; 1024];
    while !response.ends_with(b"0123456789") {
        let n = tokio::time::timeout(Duration::from_secs(2), socket.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(n, 0);
        response.extend_from_slice(&buffer[..n]);
    }
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    stop.cancel();
    task.await.unwrap().unwrap();
    assert_eq!(socket.read(&mut buffer).await.unwrap(), 0);
}

#[tokio::test]
async fn file_bucket_uses_its_filename_for_mime() {
    let fixture = Fixture::new();
    let path = fixture.dir.path().join("single.json");
    std::fs::write(&path, b"{}\n").unwrap();
    let mut config = (*fixture.server.config).clone();
    config.buckets.insert(
        "single".into(),
        Bucket {
            path,
            ..Default::default()
        },
    );
    let server = Server::new(config, vec![key()]).unwrap();
    let (status, headers, bytes) = http(&server, "GET", "/single", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(bytes, "{}\n");
}

#[tokio::test]
async fn http_streams_files_larger_than_the_upload_limit() {
    let fixture = Fixture::new();
    let server = &fixture.server;
    let mut file = std::fs::File::create(fixture.dir.path().join("raw/large")).unwrap();
    file.set_len(12 << 20).unwrap();
    use std::io::{Seek, Write};
    file.seek(std::io::SeekFrom::End(-3)).unwrap();
    file.write_all(b"end").unwrap();
    let (status, headers, bytes) =
        http(server, "GET", "/raw/large", &[("range", "bytes=-3")]).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers["content-range"], "bytes 12582909-12582911/12582912");
    assert_eq!(bytes, "end");
    let (status, headers, bytes) = http(server, "GET", "/raw/large", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-length"], "12582912");
    assert_eq!(bytes.len(), 12 << 20);
    assert!(bytes.ends_with(b"end"));
}
