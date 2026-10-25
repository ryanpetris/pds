//! SSH/SFTP and optional anonymous HTTP access to the bucket store.
//!
//! `Server::new` accepts configuration and already-loaded private keys. The daemon
//! calls `listen_and_serve`; callers supplying a listener can use `serve` and cancel
//! its token to stop accepting connections and close existing sessions.
mod fs;
mod http;
mod iface;
mod mime;
mod sftp;

pub use http::HttpBody;

#[cfg(test)]
mod tests;

use anyhow::{Context, ensure};
use russh::{Channel, ChannelId, server as ssh};
use std::{
    collections::HashMap,
    net::{Shutdown, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{Result, config, keys, store};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CONNECTIONS: usize = 256;

#[derive(Clone)]
pub struct Server {
    config: Arc<config::Server>,
    ssh: Arc<ssh::Config>,
    hosts: Arc<keys::ClientHostMap>,
    committer: Arc<store::Committer>,
    connections: Arc<Semaphore>,
}

impl Server {
    pub fn new(config: config::Server, signers: Vec<keys::PrivateKey>) -> Result<Self> {
        ensure!(
            !signers.is_empty(),
            "no host keys: place at least one private key in ~/.ssh/id_*"
        );
        let mut host_key = None;
        for key in signers {
            if key.algorithm() == keys::Algorithm::Ed25519 {
                host_key = Some(key);
            } else {
                eprintln!("pdsd: ignoring non-ed25519 host key ({})", key.algorithm());
            }
        }
        let host_key = host_key
            .context("no ed25519 host keys: place an ed25519 private key in ~/.ssh/id_*")?;
        let (hosts, warnings) = keys::client_host_map(&config.authorized_keys)?;
        for warning in warnings {
            eprintln!("pdsd: {warning}");
        }
        ensure!(
            !hosts.is_empty() || config.allow_anonymous,
            "authorizedKeys has no usable ed25519 keys and allowAnonymous is false"
        );
        if !config.authorized_keys.is_empty() && hosts.is_empty() {
            eprintln!("pdsd: no usable ed25519 authorizedKeys; serving anonymous (read-only) only");
        }
        ensure!(
            config.http_listen.is_empty() || config.allow_anonymous,
            "httpListen requires allowAnonymous: true"
        );
        let mut methods = russh::MethodSet::empty();
        if !hosts.is_empty() {
            methods.push(russh::MethodKind::PublicKey);
        }
        if config.allow_anonymous {
            methods.push(russh::MethodKind::None);
        }
        let ssh = ssh::Config {
            keys: vec![host_key],
            methods,
            auth_rejection_time: Duration::ZERO,
            max_auth_attempts: 6,
            inactivity_timeout: None,
            ..Default::default()
        };
        Ok(Self {
            config: Arc::new(config),
            ssh: Arc::new(ssh),
            hosts: Arc::new(hosts),
            committer: Arc::new(store::Committer::new()),
            connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        })
    }

    pub async fn listen_and_serve(self) -> Result<()> {
        let ssh = self.config.ssh_endpoint()?;
        let http = self.config.http_endpoint()?;
        let stop = CancellationToken::new();
        let _guard = stop.clone().drop_guard();
        let tasks = TaskTracker::new();
        let result = iface::run(self, ssh, http, stop.clone(), tasks.clone()).await;
        stop.cancel();
        tasks.close();
        tasks.wait().await;
        result
    }

    /// Serve SSH on a supplied listener until cancellation or an accept error.
    pub async fn serve(self, listener: TcpListener, stop: CancellationToken) -> Result<()> {
        let _guard = stop.clone().drop_guard();
        let tasks = TaskTracker::new();
        let result = self
            .accept_ssh(listener, stop.clone(), stop.clone(), tasks.clone())
            .await;
        stop.cancel();
        tasks.close();
        tasks.wait().await;
        result
    }

    async fn accept_ssh(
        &self,
        listener: TcpListener,
        listener_stop: CancellationToken,
        stop: CancellationToken,
        tasks: TaskTracker,
    ) -> Result<()> {
        loop {
            let (socket, peer) = tokio::select! {
                _ = listener_stop.cancelled() => return Ok(()),
                accepted = listener.accept() => accepted?,
            };
            let Ok(permit) = self.connections.clone().try_acquire_owned() else {
                eprintln!("pdsd: at capacity ({MAX_CONNECTIONS} conns); rejecting {peer}");
                continue;
            };
            let server = self.clone();
            let stop = stop.clone();
            tasks.spawn(async move {
                let _permit = permit;
                if let Err(error) = server.connection(socket, peer, stop).await {
                    eprintln!("pdsd: SSH connection from {peer}: {error:#}");
                }
            });
        }
    }

    async fn connection(
        &self,
        socket: TcpStream,
        peer: SocketAddr,
        stop: CancellationToken,
    ) -> Result<()> {
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let socket = socket.into_std()?;
        let guard = SocketGuard(socket.try_clone()?);
        let socket = TcpStream::from_std(socket)?;
        let (authenticated, ready) = oneshot::channel();
        let sessions = Arc::new(Mutex::new(Vec::new()));
        let handler = Ssh {
            server: self.clone(),
            peer,
            host: None,
            channels: HashMap::new(),
            authenticated: Some(authenticated),
            sessions: sessions.clone(),
        };
        let running = tokio::select! {
            _ = stop.cancelled() => return Ok(()),
            result = tokio::time::timeout_at(deadline, ssh::run_stream(self.ssh.clone(), socket, handler)) => result.context("SSH handshake timed out")??,
        };
        tokio::pin!(running);
        let mut result = Ok(());
        let setup = tokio::select! {
            ended = &mut running => { result = ended; None },
            _ = stop.cancelled() => Some(false),
            result = tokio::time::timeout_at(deadline, ready) => Some(matches!(result, Ok(Ok(())))),
        };
        if let Some(setup) = setup {
            if setup {
                result = tokio::select! {
                    result = &mut running => result,
                    _ = stop.cancelled() => { guard.shutdown(); (&mut running).await },
                };
            } else {
                guard.shutdown();
                result = (&mut running).await;
            }
        }
        guard.shutdown();
        let sessions = std::mem::take(&mut *sessions.lock().unwrap());
        for done in sessions {
            let _ = done.await;
        }
        result.map_err(Into::into)
    }
}

struct SocketGuard(std::net::TcpStream);
impl SocketGuard {
    fn shutdown(&self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Ssh {
    server: Server,
    peer: SocketAddr,
    host: Option<String>,
    channels: HashMap<ChannelId, Channel<ssh::Msg>>,
    authenticated: Option<oneshot::Sender<()>>,
    sessions: Arc<Mutex<Vec<oneshot::Receiver<()>>>>,
}

impl ssh::Handler for Ssh {
    type Error = russh::Error;

    async fn auth_none(&mut self, user: &str) -> Result<ssh::Auth, Self::Error> {
        Ok(
            if self.server.config.allow_anonymous && user == config::ANONYMOUS_USER {
                self.host = None;
                ssh::Auth::Accept
            } else {
                ssh::Auth::reject()
            },
        )
    }

    async fn auth_publickey_offered(
        &mut self,
        _: &str,
        offer: ssh::PublicKeyOffer<'_>,
    ) -> Result<ssh::Auth, Self::Error> {
        Ok(
            if keys::host_for(&self.server.hosts, offer.public_key).is_some() {
                ssh::Auth::Accept
            } else {
                ssh::Auth::reject()
            },
        )
    }

    async fn auth_publickey(
        &mut self,
        _: &str,
        key: ssh::VerifiedPublicKey<'_>,
    ) -> Result<ssh::Auth, Self::Error> {
        Ok(
            if let Some(host) = keys::host_for(&self.server.hosts, key.public_key) {
                self.host = Some(host.to_owned());
                ssh::Auth::Accept
            } else {
                ssh::Auth::reject()
            },
        )
    }

    async fn auth_succeeded(&mut self, _: &mut ssh::Session) -> Result<(), Self::Error> {
        match &self.host {
            Some(host) => eprintln!("pdsd: connection from {} as host {host:?}", self.peer),
            None => eprintln!("pdsd: anonymous (read-only) connection from {}", self.peer),
        }
        if let Some(ready) = self.authenticated.take() {
            let _ = ready.send(());
        }
        Ok(())
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<ssh::Msg>,
        reply: ssh::ChannelOpenHandle,
        _: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(
        &mut self,
        id: ChannelId,
        _: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&id);
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        id: ChannelId,
        name: &str,
        session: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp"
            && let Some(channel) = self.channels.remove(&id)
        {
            session.channel_success(id)?;
            let (handler, done) = sftp::Sftp::new(
                fs::View {
                    config: self.server.config.clone(),
                    host: self.host.clone(),
                },
                self.server.committer.clone(),
            );
            self.sessions.lock().unwrap().push(done);
            russh_sftp::server::run(channel.into_stream(), handler).await;
        } else {
            session.channel_failure(id)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        id: ChannelId,
        session: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }
    async fn exec_request(
        &mut self,
        id: ChannelId,
        _: &[u8],
        session: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }
    async fn env_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: &str,
        session: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }
    async fn pty_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        session: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }
    async fn x11_request(
        &mut self,
        id: ChannelId,
        _: bool,
        _: &str,
        _: &str,
        _: u32,
        session: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }
    async fn window_change_request(
        &mut self,
        id: ChannelId,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        session: &mut ssh::Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(id)
    }
    async fn agent_request(
        &mut self,
        id: ChannelId,
        session: &mut ssh::Session,
    ) -> Result<bool, Self::Error> {
        session.channel_failure(id)?;
        Ok(false)
    }
}
