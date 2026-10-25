use super::*;
use russh::{Channel, ChannelId, server};
use russh_sftp::protocol::{Data, Handle as FileHandle, Name, Status, Version};
use russh_sftp::server::StatusReply;
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::net::TcpListener;
use std::os::unix::ffi::OsStringExt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

struct PendingDial<'a>(&'a AtomicUsize);

impl Drop for PendingDial<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[tokio::test(start_paused = true)]
async fn alternate_family_connects_after_300ms_and_cancels_stalled_dial() {
    for addresses in [
        ["[2001:db8::1]:22", "[2001:db8::2]:22", "192.0.2.1:22"],
        ["192.0.2.1:22", "192.0.2.2:22", "[2001:db8::1]:22"],
    ] {
        let addresses: Vec<SocketAddr> = addresses.map(|a| a.parse().unwrap()).into();
        let attempts = Mutex::new(Vec::new());
        let active = AtomicUsize::new(0);
        let start = Instant::now();
        let deadline = start + Duration::from_secs(1);
        let connected = timeout_at(
            deadline,
            dial_addresses(addresses.clone(), deadline, |address| {
                let attempts = &attempts;
                let active = &active;
                let primary = addresses[0];
                async move {
                    attempts.lock().unwrap().push(address);
                    if address == primary {
                        active.fetch_add(1, Ordering::SeqCst);
                        let _pending = PendingDial(active);
                        std::future::pending::<()>().await;
                    }
                    Ok(address)
                }
            }),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(connected, addresses[2]);
        assert_eq!(start.elapsed(), Duration::from_millis(300));
        assert_eq!(*attempts.lock().unwrap(), [addresses[0], addresses[2]]);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn serial_dial_splits_deadline_with_two_second_minimum() {
    for addresses in [
        ["192.0.2.1:22", "192.0.2.2:22"],
        ["[2001:db8::1]:22", "[2001:db8::2]:22"],
    ] {
        let addresses: Vec<SocketAddr> = addresses.map(|a| a.parse().unwrap()).into();
        for (budget, first_timeout) in [(10, 5), (3, 2)] {
            let attempts = Mutex::new(Vec::new());
            let active = AtomicUsize::new(0);
            let start = Instant::now();
            let connected = dial_addresses(
                addresses.clone(),
                start + Duration::from_secs(budget),
                |address| {
                    let attempts = &attempts;
                    let active = &active;
                    let first = addresses[0];
                    async move {
                        attempts.lock().unwrap().push((address, start.elapsed()));
                        if address == first {
                            active.fetch_add(1, Ordering::SeqCst);
                            let _pending = PendingDial(active);
                            std::future::pending::<()>().await;
                        }
                        assert_eq!(active.load(Ordering::SeqCst), 0);
                        Ok(address)
                    }
                },
            )
            .await
            .unwrap();
            assert_eq!(connected, addresses[1]);
            assert_eq!(start.elapsed(), Duration::from_secs(first_timeout));
            assert_eq!(
                *attempts.lock().unwrap(),
                [
                    (addresses[0], Duration::ZERO),
                    (addresses[1], Duration::from_secs(first_timeout)),
                ]
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn alternate_family_splits_time_remaining_after_head_start() {
    let addresses: Vec<SocketAddr> = ["[2001:db8::1]:22", "192.0.2.1:22", "192.0.2.2:22"]
        .map(|a| a.parse().unwrap())
        .into();
    let attempts = Mutex::new(Vec::new());
    let active = AtomicUsize::new(0);
    let start = Instant::now();
    let connected = dial_addresses(
        addresses.clone(),
        start + Duration::from_millis(10_300),
        |address| {
            let attempts = &attempts;
            let active = &active;
            let winner = addresses[2];
            async move {
                attempts.lock().unwrap().push((address, start.elapsed()));
                if address != winner {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _pending = PendingDial(active);
                    std::future::pending::<()>().await;
                }
                Ok(address)
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(connected, addresses[2]);
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(
        *attempts.lock().unwrap(),
        [
            (addresses[0], Duration::ZERO),
            (addresses[1], Duration::from_millis(300)),
            (addresses[2], Duration::from_millis(5_300)),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn serial_dial_recalculates_time_after_an_early_failure() {
    let addresses: Vec<SocketAddr> = ["192.0.2.1:22", "192.0.2.2:22", "192.0.2.3:22"]
        .map(|a| a.parse().unwrap())
        .into();
    let attempts = Mutex::new(Vec::new());
    let start = Instant::now();
    let connected = dial_addresses(
        addresses.clone(),
        start + Duration::from_secs(12),
        |address| {
            let attempts = &attempts;
            let addresses = &addresses;
            async move {
                attempts.lock().unwrap().push((address, start.elapsed()));
                if address == addresses[0] {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    return Err(io::ErrorKind::ConnectionRefused.into());
                }
                if address == addresses[1] {
                    std::future::pending::<()>().await;
                }
                Ok(address)
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(connected, addresses[2]);
    assert_eq!(
        *attempts.lock().unwrap(),
        [
            (addresses[0], Duration::ZERO),
            (addresses[1], Duration::from_secs(2)),
            (addresses[2], Duration::from_secs(7)),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn serial_dial_caps_minimum_at_deadline_and_skips_expired_attempts() {
    let addresses: Vec<SocketAddr> = ["192.0.2.1:22", "192.0.2.2:22", "192.0.2.3:22"]
        .map(|a| a.parse().unwrap())
        .into();
    for (budget, expected_attempts) in [(0, 0), (1, 1), (3, 2)] {
        let attempts = AtomicUsize::new(0);
        let active = AtomicUsize::new(0);
        let start = Instant::now();
        let error = dial_addresses(
            addresses.clone(),
            start + Duration::from_secs(budget),
            |_| async {
                attempts.fetch_add(1, Ordering::SeqCst);
                active.fetch_add(1, Ordering::SeqCst);
                let _pending = PendingDial(&active);
                std::future::pending::<io::Result<()>>().await
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), Duration::from_secs(budget));
        assert_eq!(attempts.load(Ordering::SeqCst), expected_attempts);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn family_dial_preserves_order_and_starts_fallback_on_primary_failure() {
    let addresses: Vec<SocketAddr> = ["[2001:db8::1]:22", "192.0.2.1:22", "[2001:db8::2]:22"]
        .map(|a| a.parse().unwrap())
        .into();
    for winner in [addresses[2], addresses[1]] {
        let attempts = Mutex::new(Vec::new());
        let start = Instant::now();
        let connected = dial_addresses(
            addresses.clone(),
            start + Duration::from_secs(10),
            |address| {
                attempts.lock().unwrap().push(address);
                std::future::ready(if address == winner {
                    Ok(address)
                } else {
                    Err(io::Error::from(io::ErrorKind::ConnectionRefused))
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(connected, winner);
        let mut expected = vec![addresses[0], addresses[2]];
        if winner == addresses[1] {
            expected.push(addresses[1]);
        }
        assert_eq!(*attempts.lock().unwrap(), expected);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }
    let error = dial_addresses(
        addresses.clone(),
        Instant::now() + Duration::from_secs(10),
        |address| std::future::ready(Err::<(), _>(io::Error::other(address.to_string()))),
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), addresses[0].to_string());
}

#[tokio::test(start_paused = true)]
async fn failed_fallback_leaves_primary_running_and_deadline_bounds_both() {
    let addresses: Vec<SocketAddr> = ["[2001:db8::1]:22", "192.0.2.1:22"]
        .map(|a| a.parse().unwrap())
        .into();
    let start = Instant::now();
    let connected = dial_addresses(
        addresses.clone(),
        start + Duration::from_secs(10),
        |address| async move {
            if address.is_ipv4() {
                return Err(io::Error::from(io::ErrorKind::ConnectionRefused));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            Ok(address)
        },
    )
    .await
    .unwrap();
    assert_eq!(connected, addresses[0]);
    assert_eq!(start.elapsed(), Duration::from_millis(500));

    for millis in [100, 400] {
        let attempts = Mutex::new(Vec::new());
        let active = AtomicUsize::new(0);
        let start = Instant::now();
        let error = dial_addresses(
            addresses.clone(),
            start + Duration::from_millis(millis),
            |address| {
                attempts.lock().unwrap().push(address);
                let active = &active;
                async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _pending = PendingDial(active);
                    std::future::pending::<io::Result<()>>().await
                }
            },
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(start.elapsed(), Duration::from_millis(millis));
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(
            attempts.lock().unwrap().len(),
            if millis < 300 { 1 } else { 2 }
        );
    }
}

#[tokio::test]
async fn tcp_dial_resolves_hostname_and_connects_to_ipv4_listener() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let stream = timeout_at(
        deadline,
        dial_tcp(&format!("localhost:{}", address.port()), deadline),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(stream.peer_addr().unwrap(), address);
    listener.accept().await.unwrap();
}

fn private_key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

fn endpoint(address: &str) -> config::ClientEndpoint {
    let (host, port) = address.rsplit_once(':').unwrap();
    config::ClientEndpoint {
        host: norm_host(host).into(),
        ssh_port: port.parse().unwrap(),
        http_port: 0,
    }
}

fn cfg(servers: &[&TestServer]) -> config::Client {
    config::Client {
        endpoints: servers
            .iter()
            .map(|server| endpoint(&server.address))
            .collect(),
        identities: vec![
            servers[0]
                .key_dir
                .path()
                .join("identity")
                .to_str()
                .unwrap()
                .into(),
        ],
        trusted_keys: servers
            .iter()
            .map(|server| server.key.public_key().to_openssh().unwrap())
            .collect(),
        dial_timeout: Some(config::GoDuration(2_000_000_000)),
    }
}

fn write_key(path: &std::path::Path, key: &PrivateKey) {
    fs::write(
        path,
        key.to_openssh(russh::keys::ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
}

#[test]
fn endpoint_resolution_matches_go() {
    let config = config::Client {
        endpoints: vec![
            config::ClientEndpoint {
                host: "PDS.example".into(),
                ssh_port: 2222,
                http_port: 8080,
            },
            config::ClientEndpoint {
                host: "::1".into(),
                ssh_port: 2200,
                http_port: 0,
            },
            config::ClientEndpoint {
                host: " [2001:db8::1] ".into(),
                ssh_port: 2022,
                http_port: 8081,
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        resolve_endpoints_with_override(&config, "").unwrap(),
        ["PDS.example:2222", "[::1]:2200", "[2001:db8::1]:2022"]
    );
    assert_eq!(
        resolve_http_urls_with_override(&config, "").unwrap(),
        ["http://PDS.example:8080", "http://[2001:db8::1]:8081"]
    );
    assert_eq!(
        resolve_endpoints_with_override(&config, "other:22").unwrap(),
        ["other:22"]
    );
    assert_eq!(
        resolve_http_urls_with_override(&config, "pds.EXAMPLE:02222").unwrap(),
        ["http://PDS.example:8080"]
    );
    assert_eq!(
        resolve_http_urls_with_override(&config, "[2001:db8::1]:2022").unwrap(),
        ["http://[2001:db8::1]:8081"]
    );
    assert!(resolve_http_urls_with_override(&config, "[::1]:2200").is_err());
    assert!(resolve_http_urls_with_override(&config, "other:22").is_err());
    for endpoints in [
        vec![],
        vec![config::ClientEndpoint::default()],
        vec![config::ClientEndpoint {
            host: "host".into(),
            ssh_port: 65536,
            http_port: -1,
        }],
    ] {
        let cfg = config::Client {
            endpoints,
            ..Default::default()
        };
        assert!(resolve_endpoints_with_override(&cfg, "").is_err());
        assert!(resolve_http_urls_with_override(&cfg, "").is_err());
    }
    let http_only = config::Client {
        endpoints: vec![config::ClientEndpoint {
            host: "::1".into(),
            http_port: 80,
            ..Default::default()
        }],
        ..Default::default()
    };
    assert_eq!(
        resolve_http_urls_with_override(&http_only, "").unwrap(),
        ["http://[::1]:80"]
    );
    assert!(resolve_http_urls_with_override(&http_only, "[::1]:0").is_err());
    for (input, expected) in [
        ("", "/"),
        ("a/../b//./x", "/b/x"),
        ("../../x", "/x"),
        ("/a/b/", "/a/b"),
    ] {
        assert_eq!(remote_path(&[input]), expected);
    }
    assert_eq!(
        remote_path(&["/bucket/../raw", config::NAME_PUSH]),
        "/raw/.push"
    );
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Good,
    RejectSubsystem,
    StallSubsystem,
    StallInit,
    DropAuth,
    RejectAuth,
    DropOpen,
    RejectClose,
    RejectWrite,
    SlowFallback,
}

struct State {
    mode: Mode,
    accepts: AtomicUsize,
    closed: AtomicUsize,
    opens: Mutex<Vec<String>>,
    closes: AtomicUsize,
    writes: Mutex<Vec<(u64, Vec<u8>)>>,
    users: Mutex<Vec<String>>,
    accepted_key: russh::keys::PublicKey,
    anonymous: bool,
}

struct TestServer {
    address: String,
    key: PrivateKey,
    state: Arc<State>,
    key_dir: tempfile::TempDir,
    _runtime: Runtime,
}

impl TestServer {
    fn new(mode: Mode, accepted_key: Option<russh::keys::PublicKey>) -> Self {
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let key = private_key();
        let key_dir = tempfile::tempdir().unwrap();
        write_key(&key_dir.path().join("identity"), &key);
        let anonymous = accepted_key.is_none();
        let accepted_key = accepted_key.unwrap_or_else(|| key.public_key().clone());
        let state = Arc::new(State {
            mode,
            accepts: AtomicUsize::new(0),
            closed: AtomicUsize::new(0),
            opens: Mutex::new(Vec::new()),
            closes: AtomicUsize::new(0),
            writes: Mutex::new(Vec::new()),
            users: Mutex::new(Vec::new()),
            accepted_key,
            anonymous,
        });
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server_cfg = Arc::new(server::Config {
            keys: vec![key.clone()],
            // Keep handshake cost below the short endpoint deadline.
            preferred: russh::Preferred {
                kex: Cow::Borrowed(&[russh::kex::CURVE25519]),
                ..Default::default()
            },
            auth_rejection_time: Duration::ZERO,
            auth_rejection_time_initial: Some(Duration::ZERO),
            inactivity_timeout: None,
            ..Default::default()
        });
        let state_clone = state.clone();
        runtime.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                state_clone.accepts.fetch_add(1, Ordering::SeqCst);
                let cfg = server_cfg.clone();
                let state = state_clone.clone();
                tokio::spawn(async move {
                    if let Ok(session) = server::run_stream(
                        cfg,
                        stream,
                        Ssh {
                            channels: HashMap::new(),
                            state: state.clone(),
                        },
                    )
                    .await
                    {
                        let _ = session.await;
                    }
                    state.closed.fetch_add(1, Ordering::SeqCst);
                });
            }
        });
        Self {
            address,
            key,
            state,
            key_dir,
            _runtime: runtime,
        }
    }
}

struct Ssh {
    channels: HashMap<ChannelId, Channel<server::Msg>>,
    state: Arc<State>,
}

impl server::Handler for Ssh {
    type Error = russh::Error;
    async fn auth_none(&mut self, user: &str) -> Result<server::Auth, Self::Error> {
        self.state.users.lock().unwrap().push(user.into());
        if self.state.mode == Mode::SlowFallback {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        if self.state.mode == Mode::DropAuth {
            return Err(russh::Error::Disconnect);
        }
        Ok(
            if self.state.mode != Mode::RejectAuth
                && self.state.anonymous
                && user == config::ANONYMOUS_USER
            {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn auth_publickey(
        &mut self,
        _: &str,
        key: server::VerifiedPublicKey<'_>,
    ) -> Result<server::Auth, Self::Error> {
        Ok(
            if !matches!(self.state.mode, Mode::RejectAuth | Mode::SlowFallback)
                && &self.state.accepted_key == key.public_key
            {
                server::Auth::Accept
            } else {
                server::Auth::reject()
            },
        )
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<server::Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut server::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }
    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        _: &str,
        session: &mut server::Session,
    ) -> Result<(), Self::Error> {
        if self.state.mode == Mode::SlowFallback {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
        match self.state.mode {
            Mode::RejectSubsystem => session.channel_failure(id)?,
            Mode::StallSubsystem => {}
            _ => {
                session.channel_success(id)?;
                let stream = self.channels.remove(&id).unwrap().into_stream();
                russh_sftp::server::run(
                    stream,
                    Sftp {
                        state: self.state.clone(),
                        batch: 0,
                        ssh: session.handle(),
                    },
                )
                .await;
            }
        }
        Ok(())
    }
}

struct Sftp {
    state: Arc<State>,
    batch: u32,
    ssh: server::Handle,
}

fn status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}

impl russh_sftp::server::Handler for Sftp {
    type Error = StatusReply;
    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported.into()
    }
    async fn init(&mut self, _: u32, _: HashMap<String, String>) -> Result<Version, Self::Error> {
        if self.state.mode == Mode::StallInit {
            std::future::pending::<()>().await;
        }
        Ok(Version::new())
    }
    async fn open(
        &mut self,
        id: u32,
        filename: String,
        _: OpenFlags,
        _: FileAttributes,
    ) -> Result<FileHandle, Self::Error> {
        self.state.opens.lock().unwrap().push(filename);
        if self.state.mode == Mode::DropOpen {
            self.ssh
                .disconnect(
                    Disconnect::ByApplication,
                    "operation disconnect".into(),
                    "".into(),
                )
                .await
                .unwrap();
            return Err(StatusCode::NoConnection.into());
        }
        Ok(FileHandle {
            id,
            handle: "file".into(),
        })
    }
    async fn read(&mut self, id: u32, _: String, offset: u64, _: u32) -> Result<Data, Self::Error> {
        if offset == 0 {
            Ok(Data {
                id,
                data: b"data".to_vec(),
            })
        } else {
            Err(StatusCode::Eof.into())
        }
    }
    async fn write(
        &mut self,
        id: u32,
        _: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        if self.state.mode == Mode::RejectWrite {
            return Err(StatusCode::Failure.with_message("write failed"));
        }
        self.state.writes.lock().unwrap().push((offset, data));
        Ok(status(id))
    }
    async fn close(&mut self, id: u32, _: String) -> Result<Status, Self::Error> {
        self.state.closes.fetch_add(1, Ordering::SeqCst);
        if self.state.mode == Mode::RejectClose {
            return Err(StatusCode::Failure.with_message("validation rejected"));
        }
        Ok(status(id))
    }
    async fn opendir(&mut self, id: u32, _: String) -> Result<FileHandle, Self::Error> {
        self.batch = 0;
        Ok(FileHandle {
            id,
            handle: "dir".into(),
        })
    }
    async fn readdir(&mut self, id: u32, _: String) -> Result<Name, Self::Error> {
        self.batch += 1;
        let filename = match self.batch {
            1 => "first",
            2 => "second",
            _ => return Err(StatusCode::Eof.into()),
        };
        Ok(Name {
            id,
            files: vec![russh_sftp::protocol::File {
                filename: filename.into(),
                longname: String::new(),
                attrs: FileAttributes::empty(),
            }],
        })
    }
}

fn wait_until(check: impl Fn() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !check() {
        assert!(
            std::time::Instant::now() < deadline,
            "fixture did not complete"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn startup_failures_fail_over_and_timeout_closes_socket() {
    let healthy = TestServer::new(Mode::Good, None);
    for mode in [
        Mode::RejectSubsystem,
        Mode::StallSubsystem,
        Mode::StallInit,
        Mode::DropAuth,
        Mode::SlowFallback,
    ] {
        let first = TestServer::new(mode, None);
        let mut config = cfg(&[&first, &healthy]);
        // SlowFallback fits separate connection budgets, but not one shared deadline.
        config.dial_timeout = Some(config::GoDuration(1_000_000_000));
        let started = std::time::Instant::now();
        let client = Client::dial(&config).unwrap();
        assert!(started.elapsed() < Duration::from_secs(3));
        if matches!(
            mode,
            Mode::StallSubsystem | Mode::StallInit | Mode::SlowFallback
        ) {
            assert!(started.elapsed() >= Duration::from_secs(1));
        }
        assert_eq!(client.endpoint(), healthy.address);
        if mode == Mode::SlowFallback {
            assert_eq!(first.state.accepts.load(Ordering::SeqCst), 2);
        }
        client.close().unwrap();
        wait_until(|| {
            first.state.closed.load(Ordering::SeqCst) == first.state.accepts.load(Ordering::SeqCst)
        });
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let ended = Arc::new(AtomicBool::new(false));
    let ended_clone = ended.clone();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut bytes = Vec::new();
        assert!(stream.read_to_end(&mut bytes).is_ok());
        ended_clone.store(true, Ordering::SeqCst);
    });
    let mut config = cfg(&[&healthy]);
    config.endpoints.insert(0, endpoint(&address));
    config.dial_timeout = Some(config::GoDuration(1_000_000_000));
    let started = std::time::Instant::now();
    let client = Client::dial(&config).unwrap();
    assert_eq!(client.endpoint(), healthy.address);
    assert!(started.elapsed() < Duration::from_secs(3));
    assert!(started.elapsed() >= Duration::from_secs(1));
    wait_until(|| ended.load(Ordering::SeqCst));
    server.join().unwrap();
}

#[test]
fn trust_and_authentication_failures_are_terminal() {
    let healthy = TestServer::new(Mode::Good, None);
    let first = TestServer::new(Mode::Good, None);
    let mut config = cfg(&[&first, &healthy]);
    config.trusted_keys.remove(0);
    let error = Client::dial(&config).err().unwrap();
    assert!(
        error
            .to_string()
            .contains("untrusted server host key SHA256:"),
        "{error:#}"
    );
    assert_eq!(healthy.state.accepts.load(Ordering::SeqCst), 0);
    let first = TestServer::new(Mode::RejectAuth, None);
    let error = Client::dial(&cfg(&[&first, &healthy])).err().unwrap();
    assert!(error.is::<AuthenticationRejected>(), "{error:#}");
    assert_eq!(healthy.state.accepts.load(Ordering::SeqCst), 0);
    let bad = private_key();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity");
    write_key(&path, &bad);
    let mut config = cfg(&[&first, &healthy]);
    config.identities = vec![path.to_str().unwrap().into()];
    assert!(
        Client::dial(&config)
            .err()
            .unwrap()
            .is::<AuthenticationRejected>()
    );
    assert_eq!(healthy.state.accepts.load(Ordering::SeqCst), 0);
    assert_eq!(first.state.accepts.load(Ordering::SeqCst), 4);
}

#[test]
fn identities_and_fresh_anonymous_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let bad = private_key();
    let good = private_key();
    for (name, key) in [("bad", &bad), ("good", &good)] {
        write_key(&dir.path().join(name), key);
    }
    let server = TestServer::new(Mode::Good, Some(good.public_key().clone()));
    let mut config = cfg(&[&server]);
    config.identities = vec![
        dir.path().join("bad").to_str().unwrap().into(),
        dir.path().join("good").to_str().unwrap().into(),
    ];
    Client::dial(&config).unwrap().close().unwrap();
    assert_eq!(server.state.accepts.load(Ordering::SeqCst), 1);
    let server = TestServer::new(Mode::Good, None);
    let mut config = cfg(&[&server]);
    config.identities = vec![dir.path().join("bad").to_str().unwrap().into()];
    Client::dial(&config).unwrap().close().unwrap();
    assert_eq!(server.state.accepts.load(Ordering::SeqCst), 2);
    assert_eq!(
        server.state.users.lock().unwrap().last().unwrap(),
        config::ANONYMOUS_USER
    );
    config.identities = vec![dir.path().join("missing").to_str().unwrap().into()];
    assert!(format!("{:#}", Client::dial(&config).err().unwrap()).contains("identity"));
    fs::write(dir.path().join("invalid"), b"invalid").unwrap();
    assert!(load_identities(&[dir.path().join("invalid").to_str().unwrap().into()]).is_err());
    let encrypted = good.encrypt(&mut rand::rng(), "secret").unwrap();
    write_key(&dir.path().join("encrypted"), &encrypted);
    assert!(load_identities(&[dir.path().join("encrypted").to_str().unwrap().into()]).is_err());
    let mut pkcs8 = Vec::new();
    russh::keys::encode_pkcs8_pem(&good, &mut pkcs8).unwrap();
    fs::write(dir.path().join("pkcs8"), pkcs8).unwrap();
    assert_eq!(
        load_identities(&[dir.path().join("pkcs8").to_str().unwrap().into()]).unwrap()[0]
            .public_key(),
        good.public_key()
    );
}

#[test]
fn operations_stream_in_order_report_close_errors_and_never_replay() {
    let first = TestServer::new(Mode::Good, None);
    let backup = TestServer::new(Mode::Good, None);
    let client = Client::dial(&cfg(&[&first, &backup])).unwrap();
    let mut data = Vec::new();
    client.pull("a/../b", &mut data).unwrap();
    assert_eq!(data, b"data");
    assert_eq!(*first.state.opens.lock().unwrap(), ["/b"]);
    assert_eq!(
        client
            .read_dir("/")
            .unwrap()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    let input: Vec<_> = (0..100_000).map(|i| i as u8).collect();
    client.push("raw", &mut input.as_slice()).unwrap();
    let writes = first.state.writes.lock().unwrap();
    let mut offset = 0;
    let mut actual = Vec::new();
    for (at, data) in writes.iter() {
        assert_eq!(*at, offset);
        offset += data.len() as u64;
        actual.extend_from_slice(data);
    }
    assert_eq!(actual, input);
    assert_eq!(backup.state.accepts.load(Ordering::SeqCst), 0);
    drop(writes);
    client.close().unwrap();
    let first = TestServer::new(Mode::RejectClose, None);
    let client = Client::dial(&cfg(&[&first, &backup])).unwrap();
    let error = client.push("raw", &mut &b"data"[..]).unwrap_err();
    assert!(
        format!("{error:#}").contains("push rejected: Failure: validation rejected"),
        "{error:#}"
    );
    assert_eq!(first.state.closes.load(Ordering::SeqCst), 1);
    assert_eq!(backup.state.accepts.load(Ordering::SeqCst), 0);
    let first = TestServer::new(Mode::DropOpen, None);
    let client = Client::dial(&cfg(&[&first, &backup])).unwrap();
    assert!(client.pull("file", &mut Vec::new()).is_err());
    assert_eq!(first.state.opens.lock().unwrap().len(), 1);
    assert_eq!(backup.state.accepts.load(Ordering::SeqCst), 0);
}

struct BrokenInput(bool);
impl Read for BrokenInput {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.0 {
            return Err(io::Error::other("input failed"));
        }
        self.0 = true;
        buffer[..4].copy_from_slice(b"part");
        Ok(4)
    }
}

#[test]
fn upload_io_errors_end_session_without_close() {
    let server = TestServer::new(Mode::Good, None);
    let client = Client::dial(&cfg(&[&server])).unwrap();
    assert!(
        client
            .push("raw", &mut BrokenInput(false))
            .unwrap_err()
            .to_string()
            .contains("input failed")
    );
    wait_until(|| server.state.closed.load(Ordering::SeqCst) == 1);
    assert_eq!(server.state.closes.load(Ordering::SeqCst), 0);
    assert_eq!(
        *server.state.writes.lock().unwrap(),
        [(0, b"part".to_vec())]
    );
    let server = TestServer::new(Mode::RejectWrite, None);
    let client = Client::dial(&cfg(&[&server])).unwrap();
    assert!(client.push("raw", &mut &b"part"[..]).is_err());
    wait_until(|| server.state.closed.load(Ordering::SeqCst) == 1);
    assert_eq!(server.state.closes.load(Ordering::SeqCst), 0);
}

struct NativeServer {
    root: tempfile::TempDir,
    stop: CancellationToken,
    thread: Option<thread::JoinHandle<()>>,
    config: config::Client,
}

impl Drop for NativeServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl NativeServer {
    fn shutdown(&mut self) {
        self.stop.cancel();
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }

    fn start() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path();
        for name in ["scripts", "raw", "json", "hosts", "versioned"] {
            fs::create_dir_all(path.join(name)).unwrap();
        }
        let host = private_key();
        let identity = private_key();
        write_key(&path.join("identity"), &identity);
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let config = serde_json::from_value(serde_json::json!({
            "sshListen": address, "allowAnonymous": true, "execBucket": "scripts",
            "authorizedKeys": [{"host": "node-a", "keys": [format!("no-pty {} comment", identity.public_key().to_openssh().unwrap())]}],
            "buckets": {
                "scripts": {"path": path.join("scripts")},
                "raw": {"path": path.join("raw"), "mode": "rw", "extension": "bin", "validator": "none"},
                "json": {"path": path.join("json"), "mode": "rw", "extension": "json", "validator": "json"},
                "hosts": {"path": path.join("hosts"), "mode": "rw", "extension": "bin", "validator": "none", "byHost": true},
                "versioned": {"path": path.join("versioned"), "mode": "rw", "extension": "bin", "validator": "none", "versioned": true}
            }
        }))
        .unwrap();
        let server = crate::server::Server::new(config, vec![host.clone()]).unwrap();
        let stop = CancellationToken::new();
        let server_stop = stop.clone();
        let thread = thread::spawn(move || {
            runtime.block_on(async {
                let task = tokio::spawn(server.serve(listener, server_stop.clone()));
                server_stop.cancelled().await;
                tokio::time::timeout(Duration::from_secs(3), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            });
        });
        let config = config::Client {
            endpoints: vec![endpoint(&address)],
            trusted_keys: vec![format!(
                "command=\"echo hello\",no-pty {} comment",
                host.public_key().to_openssh().unwrap()
            )],
            identities: vec![path.join("identity").to_str().unwrap().into()],
            dial_timeout: Some(config::GoDuration(2_000_000_000)),
        };
        Self {
            root,
            stop,
            thread: Some(thread),
            config,
        }
    }
}

#[test]
fn native_server_streaming_metadata_exec_and_validation() {
    let mut server = NativeServer::start();
    let root = server.root.path().to_owned();
    let data: Vec<_> = (0..120_000).map(|i| i as u8).collect();
    fs::write(root.join("scripts/bytes"), &data).unwrap();
    fs::write(root.join("scripts/check.sh"), b"#!/bin/sh\nout=$1\nshift\nprintf '%s\\n' \"${0##*/}\" \"$0\" \"$PDS_ENDPOINT\" \"$PWD\" > \"$out\"\nprintf '%s\\000' \"$@\" >> \"$out\"\nexit 23\n").unwrap();
    fs::write(
        root.join("scripts/signal.sh"),
        b"#!/bin/sh\nkill -TERM $$\n",
    )
    .unwrap();
    fs::create_dir(root.join("scripts/nested")).unwrap();
    let client = Client::dial(&server.config).unwrap();
    let mut pulled = Vec::new();
    client
        .pull("scripts//nested/../bytes", &mut pulled)
        .unwrap();
    assert_eq!(pulled, data);
    let entries = client.read_dir("scripts").unwrap();
    assert!(entries.contains(&DirEntry {
        name: "nested".into(),
        is_dir: true
    }));
    assert!(entries.contains(&DirEntry {
        name: "bytes".into(),
        is_dir: false
    }));
    let entries = client.read_dir("").unwrap();
    assert!(entries.contains(&DirEntry {
        name: ".pds".into(),
        is_dir: true
    }));
    let mut meta = Vec::new();
    client.meta("hosts", &mut meta).unwrap();
    let meta: serde_yaml_ng::Value = serde_yaml_ng::from_slice(&meta).unwrap();
    assert_eq!(meta["byHost"].as_bool(), Some(true));
    client.push("raw", &mut data.as_slice()).unwrap();
    assert_eq!(fs::read(root.join("raw/latest.bin")).unwrap(), data);
    client.push("hosts", &mut &b"node bytes"[..]).unwrap();
    let mut pulled = Vec::new();
    client.pull("hosts/.self/latest.bin", &mut pulled).unwrap();
    assert_eq!(pulled, b"node bytes");
    let valid = b"{\"value\":1}\n";
    client.push("json", &mut &valid[..]).unwrap();
    assert_eq!(fs::read(root.join("json/latest.json")).unwrap(), valid);
    let error = client.push("json", &mut &b"invalid json"[..]).unwrap_err();
    assert!(format!("{error:#}").contains("push rejected"));
    assert_eq!(fs::read(root.join("json/latest.json")).unwrap(), valid);
    assert!(
        client
            .push("raw", &mut io::repeat(b'x').take(5 * 1024 * 1024 + 1))
            .is_err()
    );
    // A failed write ends this session, so reconnect for the remaining operations.
    let client = Client::dial(&server.config).unwrap();
    let output = root.join("exec-output");
    let args = vec![
        output.as_os_str().to_owned(),
        "--".into(),
        "--option=value".into(),
        OsString::from_vec(vec![b'a', 0xff]),
    ];
    assert_eq!(client.exec("check.sh", &args).unwrap(), 23);
    let output = fs::read(output).unwrap();
    let mut fields = output.splitn(5, |byte| *byte == b'\n');
    assert_eq!(fields.next().unwrap(), b"check.sh");
    let script_path = PathBuf::from(OsString::from_vec(fields.next().unwrap().to_vec()));
    assert_eq!(fields.next().unwrap(), client.endpoint().as_bytes());
    assert_eq!(
        fields.next().unwrap(),
        env::current_dir().unwrap().as_os_str().as_encoded_bytes()
    );
    assert_eq!(fields.next().unwrap(), b"--\0--option=value\0a\xff\0");
    assert!(!script_path.parent().unwrap().exists());
    assert_eq!(client.exec("signal.sh", &[]).unwrap(), 255);
    assert!(client.exec("missing", &[]).is_err());
    client.close().unwrap();

    let files = |bucket: &str| {
        fs::read_dir(root.join(bucket))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>()
    };
    let client = Client::dial(&server.config).unwrap();
    client.push("versioned", &mut data.as_slice()).unwrap();
    client.close().unwrap();
    let latest = fs::read_link(root.join("versioned/latest.bin")).unwrap();
    let before = [BTreeSet::from(["latest.bin".into()]), files("versioned")];
    for (bucket, expected) in ["raw", "versioned"].into_iter().zip(before) {
        let client = Client::dial(&server.config).unwrap();
        let error = client.push(bucket, &mut BrokenInput(false)).unwrap_err();
        assert!(error.to_string().contains("input failed"), "{error:#}");
        wait_until(|| files(bucket) == expected);
        assert_eq!(
            fs::read(root.join(bucket).join("latest.bin")).unwrap(),
            data
        );
    }
    assert_eq!(
        fs::read_link(root.join("versioned/latest.bin")).unwrap(),
        latest
    );
    server.shutdown();
}

#[test]
fn all_unavailable_endpoints_report_every_address() {
    let trusted = TestServer::new(Mode::Good, None);
    let one = TcpListener::bind("127.0.0.1:0").unwrap();
    let two = TcpListener::bind("127.0.0.1:0").unwrap();
    let addresses = [
        one.local_addr().unwrap().to_string(),
        two.local_addr().unwrap().to_string(),
    ];
    drop((one, two));
    let mut config = cfg(&[&trusted]);
    config.endpoints = addresses.iter().map(|address| endpoint(address)).collect();
    let error = format!("{:#}", Client::dial(&config).err().unwrap());
    for expected in [
        "unable to contact any configured endpoint",
        &addresses[0],
        &addresses[1],
    ] {
        assert!(error.contains(expected), "{error}");
    }
    assert_eq!(trusted.state.accepts.load(Ordering::SeqCst), 0);
}
