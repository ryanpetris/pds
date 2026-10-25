use std::borrow::Cow;
use std::env;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail, ensure};
use russh::client::{self, Handle};
use russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use russh::{ChannelMsg, Disconnect};
use russh_sftp::client::{RawSftpSession, error::Error as SftpError};
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::runtime::{Builder, Runtime};
use tokio::time::{Instant, timeout_at};

use crate::{config, keys};

/// A connected SSH/SFTP session with a blocking interface.
pub struct Client {
    endpoint: String,
    runtime: Runtime,
    connection: Connection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
}

/// Return configured SSH addresses in attempt order, honoring PDS_ENDPOINT.
pub fn resolve_endpoints(cfg: &config::Client) -> Result<Vec<String>> {
    resolve_endpoints_with_override(cfg, &endpoint_override())
}

fn resolve_endpoints_with_override(cfg: &config::Client, override_: &str) -> Result<Vec<String>> {
    if !override_.is_empty() {
        return Ok(vec![override_.into()]);
    }
    ensure!(!cfg.endpoints.is_empty(), "no endpoints are configured");
    cfg.endpoints
        .iter()
        .enumerate()
        .map(|(i, endpoint)| {
            resolve_address(endpoint, false).with_context(|| format!("endpoint {}", i + 1))
        })
        .collect()
}

/// Return HTTP base URLs, restricting overrides to the matching SSH endpoint.
pub fn resolve_http_urls(cfg: &config::Client) -> Result<Vec<String>> {
    resolve_http_urls_with_override(cfg, &endpoint_override())
}

fn resolve_http_urls_with_override(cfg: &config::Client, override_: &str) -> Result<Vec<String>> {
    ensure!(!cfg.endpoints.is_empty(), "no endpoints are configured");
    let mut urls = Vec::new();
    for (i, endpoint) in cfg.endpoints.iter().enumerate() {
        if !override_.is_empty() {
            if endpoint.host.trim().is_empty() || !(1..=65535).contains(&endpoint.ssh_port) {
                continue;
            }
            if !same_endpoint(override_, &resolve_address(endpoint, false)?) {
                continue;
            }
        } else if endpoint.http_port == 0 {
            continue;
        }
        urls.push(
            resolve_address(endpoint, true)
                .map(|address| format!("http://{address}"))
                .with_context(|| format!("endpoint {}", i + 1))?,
        );
        if !override_.is_empty() {
            return Ok(urls);
        }
    }
    if !override_.is_empty() {
        bail!("PDS_ENDPOINT {override_:?} does not match a configured endpoint");
    }
    ensure!(
        !urls.is_empty(),
        "httpPort is not configured for any endpoint"
    );
    Ok(urls)
}

fn endpoint_override() -> String {
    env::var("PDS_ENDPOINT").unwrap_or_default()
}

fn norm_host(host: &str) -> &str {
    let host = host.trim();
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host)
}

fn resolve_address(endpoint: &config::ClientEndpoint, http: bool) -> Result<String> {
    ensure!(!endpoint.host.trim().is_empty(), "host is not configured");
    let (port, field) = if http {
        (endpoint.http_port, "httpPort")
    } else {
        (endpoint.ssh_port, "sshPort")
    };
    ensure!(
        (1..=65535).contains(&port),
        "{field} must be between 1 and 65535"
    );
    let host = norm_host(&endpoint.host);
    if host.contains(':') {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn same_endpoint(a: &str, b: &str) -> bool {
    fn split(input: &str) -> Option<(&str, i64)> {
        let (host, port) = if let Some(rest) = input.strip_prefix('[') {
            let (host, port) = rest.split_once("]:")?;
            if host.contains(['[', ']']) {
                return None;
            }
            (host, port)
        } else {
            let (host, port) = input.split_once(':')?;
            if host.contains(['[', ']']) || port.contains(':') {
                return None;
            }
            (host, port)
        };
        Some((norm_host(host), port.parse().ok()?))
    }
    match (split(a), split(b)) {
        (Some((ah, ap)), Some((bh, bp))) => ah.eq_ignore_ascii_case(bh) && ap == bp,
        _ => false,
    }
}

fn remote_path(parts: &[&str]) -> String {
    let mut segments = Vec::new();
    for part in parts {
        for segment in part.split('/') {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop();
                }
                segment => segments.push(segment),
            }
        }
    }
    format!("/{}", segments.join("/"))
}

fn load_identities(paths: &[String]) -> Result<Vec<Arc<PrivateKey>>> {
    let signers = if paths.is_empty() {
        keys::load_signers(keys::default_ssh_dir())?.0
    } else {
        paths
            .iter()
            .map(|path| {
                let path = expand_home(path);
                russh::keys::load_secret_key(&path, None)
                    .with_context(|| format!("identity {}", path.display()))
                    .and_then(|key| {
                        ensure!(
                            !key.is_encrypted(),
                            "identity {}: private key is passphrase protected",
                            path.display()
                        );
                        Ok(key)
                    })
            })
            .collect::<Result<Vec<_>>>()?
    };
    Ok(signers.into_iter().map(Arc::new).collect())
}

fn expand_home(path: &str) -> PathBuf {
    let home = || PathBuf::from(env::var_os("HOME").unwrap_or_default());
    if path == "~" {
        home()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home().join(rest)
    } else {
        path.into()
    }
}

#[derive(Debug)]
struct AuthenticationRejected;

impl std::fmt::Display for AuthenticationRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SSH authentication rejected")
    }
}

impl std::error::Error for AuthenticationRejected {}

struct HostKeyCheck {
    trusted: Arc<keys::TrustedSet>,
    rejected: Arc<Mutex<Option<String>>>,
}

impl client::Handler for HostKeyCheck {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if let PublicKeyOrCertificate::PublicKey { key, .. } = key
            && key.algorithm() == Algorithm::Ed25519
            && keys::trusted(&self.trusted, key)
        {
            return Ok(true);
        }
        *self.rejected.lock().unwrap() = Some(match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => {
                key.fingerprint(HashAlg::Sha256).to_string()
            }
            PublicKeyOrCertificate::Certificate(_) => "certificate".into(),
        });
        Ok(false)
    }
}

// Cancelling russh's connect future leaves its spawned connection running.
// Shutting down the cloned socket also stops that task on timeout and setup errors.
struct Socket(TcpStream);

impl Drop for Socket {
    fn drop(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

struct Connection {
    ssh: Handle<HostKeyCheck>,
    sftp: RawSftpSession,
    socket: Socket,
}

async fn dial_addresses<T, F>(
    addresses: Vec<SocketAddr>,
    deadline: Instant,
    connect: impl Fn(SocketAddr) -> F,
) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    let first = addresses
        .first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no addresses to connect to"))?;
    let (primary, fallback): (Vec<_>, Vec<_>) = addresses
        .iter()
        .copied()
        .partition(|address| address.is_ipv4() == first.is_ipv4());
    let serial = async |addresses: Vec<SocketAddr>| {
        let mut first_error = None;
        for (i, address) in addresses.iter().enumerate() {
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                first_error.get_or_insert_with(|| io::ErrorKind::TimedOut.into());
                break;
            }
            // Go divides time within each family, reserving two seconds when available.
            let timeout = (remaining / (addresses.len() - i) as u32)
                .max(std::time::Duration::from_secs(2))
                .min(remaining);
            match timeout_at(now + timeout, connect(*address))
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
            {
                Ok(stream) => return Ok(stream),
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error.unwrap())
    };
    if fallback.is_empty() {
        return serial(primary).await;
    }
    let primary = serial(primary);
    tokio::pin!(primary);
    // Go's dialer gives the first address family a 300 ms head start.
    tokio::select! {
        result = &mut primary => return match result {
            Ok(stream) => Ok(stream),
            Err(error) => serial(fallback).await.map_err(|_| error),
        },
        _ = tokio::time::sleep(std::time::Duration::from_millis(300)) => {}
    }
    let fallback = serial(fallback);
    tokio::pin!(fallback);
    tokio::select! {
        result = &mut primary => match result {
            Ok(stream) => Ok(stream),
            Err(error) => fallback.await.map_err(|_| error),
        },
        result = &mut fallback => match result {
            Ok(stream) => Ok(stream),
            Err(_) => primary.await,
        },
    }
}

async fn dial_tcp(endpoint: &str, deadline: Instant) -> io::Result<AsyncTcpStream> {
    let addresses = tokio::net::lookup_host(endpoint).await?.collect();
    dial_addresses(addresses, deadline, AsyncTcpStream::connect).await
}

async fn dial_connection(
    endpoint: &str,
    deadline: Instant,
    signers: &[Arc<PrivateKey>],
    trusted: Arc<keys::TrustedSet>,
    rejected: Arc<Mutex<Option<String>>>,
    username: &str,
) -> Result<Connection> {
    let stream = dial_tcp(endpoint, deadline).await.context("TCP dial")?;
    let stream = stream.into_std()?;
    let socket = Socket(stream.try_clone()?);
    let stream = AsyncTcpStream::from_std(stream)?;
    let mut cfg = client::Config::default();
    cfg.preferred.key = Cow::Owned(vec![Algorithm::Ed25519]);
    let mut ssh = client::connect_stream(Arc::new(cfg), stream, HostKeyCheck { trusted, rejected })
        .await
        .context("SSH handshake")?;
    let mut authenticated = ssh.authenticate_none(username).await?.success();
    if !authenticated && ssh.is_closed() {
        (&mut ssh).await.context("SSH authentication transport")?;
        bail!("SSH transport closed during authentication");
    }
    for signer in signers {
        if authenticated {
            break;
        }
        let hash = if signer.algorithm().is_rsa() {
            ssh.best_supported_rsa_hash().await?.flatten()
        } else {
            None
        };
        authenticated = ssh
            .authenticate_publickey(username, PrivateKeyWithHashAlg::new(signer.clone(), hash))
            .await
            .context("SSH public key authentication")?
            .success();
        if !authenticated && ssh.is_closed() {
            (&mut ssh).await.context("SSH authentication transport")?;
            bail!("SSH transport closed during authentication");
        }
    }
    if !authenticated {
        return Err(AuthenticationRejected.into());
    }
    let mut channel = ssh
        .channel_open_session()
        .await
        .context("starting SFTP channel")?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .context("requesting SFTP")?;
    loop {
        match channel.wait().await {
            Some(ChannelMsg::Success) => break,
            Some(ChannelMsg::Failure | ChannelMsg::Eof | ChannelMsg::Close) | None => {
                bail!("starting SFTP: subsystem rejected or connection closed");
            }
            _ => {}
        }
    }
    let sftp = RawSftpSession::new_with_config(
        channel.into_stream(),
        russh_sftp::client::Config {
            request_timeout_secs: u64::MAX,
            ..Default::default()
        },
    );
    sftp.init().await.context("starting SFTP")?;
    Ok(Connection { ssh, sftp, socket })
}

impl Client {
    pub fn dial(cfg: &config::Client) -> Result<Self> {
        cfg.validate()?;
        let endpoints = resolve_endpoints(cfg)?;
        let trusted = Arc::new(keys::trusted_set(&cfg.trusted_keys)?);
        let signers = load_identities(&cfg.identities)?;
        let runtime = Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;
        let username = env::var("USER")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "pds".into());
        let mut errors = Vec::new();
        for endpoint in endpoints {
            let rejected = Arc::new(Mutex::new(None));
            let result = runtime.block_on(async {
                let deadline = Instant::now() + cfg.effective_dial_timeout();
                timeout_at(deadline, async {
                    if !signers.is_empty() {
                        match dial_connection(
                            &endpoint,
                            deadline,
                            &signers,
                            trusted.clone(),
                            rejected.clone(),
                            &username,
                        )
                        .await
                        {
                            Ok(connection) => return Ok(connection),
                            Err(error) if error.is::<AuthenticationRejected>() => {}
                            Err(error) => return Err(error),
                        }
                    }
                    dial_connection(
                        &endpoint,
                        deadline,
                        &[],
                        trusted.clone(),
                        rejected.clone(),
                        config::ANONYMOUS_USER,
                    )
                    .await
                })
                .await
                .context("endpoint deadline exceeded")?
            });
            if let Some(fingerprint) = rejected.lock().unwrap().as_ref() {
                bail!("{endpoint}: untrusted server host key {fingerprint}");
            }
            match result {
                Ok(connection) => {
                    return Ok(Self {
                        endpoint,
                        runtime,
                        connection,
                    });
                }
                Err(error) if error.is::<AuthenticationRejected>() => {
                    return Err(error.context(endpoint));
                }
                Err(error) => errors.push(format!("{endpoint}: {error:#}")),
            }
        }
        bail!(
            "unable to contact any configured endpoint: {}",
            errors.join("\n")
        )
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn pull(&self, remote: &str, out: &mut dyn Write) -> Result<()> {
        self.runtime.block_on(async {
            let handle = self
                .connection
                .sftp
                .open(
                    remote_path(&[remote]),
                    OpenFlags::READ,
                    FileAttributes::empty(),
                )
                .await?
                .handle;
            let result = self.copy_from(&handle, out).await;
            let _ = self.connection.sftp.close(handle).await;
            result
        })
    }

    async fn copy_from(&self, handle: &str, out: &mut dyn Write) -> Result<()> {
        let mut offset = 0;
        loop {
            match self.connection.sftp.read(handle, offset, 32768).await {
                Ok(data) => {
                    if data.data.is_empty() {
                        return Ok(());
                    }
                    out.write_all(&data.data)?;
                    offset += data.data.len() as u64;
                }
                Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => {
                    return Ok(());
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    pub fn read_dir(&self, remote: &str) -> Result<Vec<DirEntry>> {
        self.runtime.block_on(async {
            let handle = self
                .connection
                .sftp
                .opendir(remote_path(&[remote]))
                .await?
                .handle;
            let result = async {
                let mut entries = Vec::new();
                loop {
                    match self.connection.sftp.readdir(&handle).await {
                        Ok(batch) => entries.extend(
                            batch
                                .files
                                .into_iter()
                                .filter(|file| file.filename != "." && file.filename != "..")
                                .map(|file| DirEntry {
                                    name: file
                                        .filename
                                        .trim_end_matches('/')
                                        .rsplit('/')
                                        .next()
                                        .unwrap_or("")
                                        .into(),
                                    is_dir: file.attrs.is_dir(),
                                }),
                        ),
                        Err(SftpError::Status(status)) if status.status_code == StatusCode::Eof => {
                            return Ok(entries);
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            .await;
            let _ = self.connection.sftp.close(handle).await;
            result
        })
    }

    /// Stream an upload and wait for server validation on close.
    /// An input or write error ends the connection without closing the upload handle.
    pub fn push(&self, bucket: &str, input: &mut dyn Read) -> Result<()> {
        self.runtime.block_on(async {
            let handle = self
                .connection
                .sftp
                .open(
                    remote_path(&[bucket, config::NAME_PUSH]),
                    OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                    FileAttributes::empty(),
                )
                .await?
                .handle;
            let result: Result<()> = async {
                let mut buffer = [0; 32768];
                let mut offset = 0;
                loop {
                    let len = match input.read(&mut buffer) {
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        result => result?,
                    };
                    if len == 0 {
                        return Ok(());
                    }
                    self.connection
                        .sftp
                        .write(&handle, offset, buffer[..len].to_vec())
                        .await?;
                    offset += len as u64;
                }
            }
            .await;
            if let Err(error) = result {
                // Closing an incomplete upload can commit it. End the session first.
                let _ = self.connection.socket.0.shutdown(Shutdown::Both);
                let _ = self.connection.sftp.close_session();
                return Err(error);
            }
            self.connection
                .sftp
                .close(handle)
                .await
                .context("push rejected")?;
            Ok(())
        })
    }

    pub fn meta(&self, bucket: &str, out: &mut dyn Write) -> Result<()> {
        self.pull(&remote_path(&[bucket, config::NAME_META]), out)
    }

    /// Run a downloaded script with inherited process state and the selected endpoint.
    /// Return 255 when the script terminates by signal.
    pub fn exec(&self, name: &str, args: &[OsString]) -> Result<i32> {
        let dir = tempfile::Builder::new().prefix("pds-exec-").tempdir()?;
        let base = name.trim_end_matches('/').rsplit('/').next().unwrap_or(".");
        let path = dir.path().join(base);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&path)?;
        self.pull(
            &remote_path(&[config::NAME_PDS, config::NAME_EXEC, name]),
            &mut file,
        )?;
        // Drop before exec so the kernel does not reject a writable executable.
        drop(file);
        let status = Command::new(path)
            .arg0(base)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .env("PDS_ENDPOINT", &self.endpoint)
            .status()?;
        Ok(status.code().unwrap_or(255))
    }

    pub fn close(self) -> Result<()> {
        let _ = self.connection.sftp.close_session();
        self.runtime.block_on(
            self.connection
                .ssh
                .disconnect(Disconnect::ByApplication, "", ""),
        )?;
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.connection.socket.0.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests;
