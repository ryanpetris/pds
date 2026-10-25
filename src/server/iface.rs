use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use nix::{
    ifaddrs::getifaddrs,
    net::if_::InterfaceFlags,
    sys::socket::{setsockopt, sockopt::Ipv6V6Only},
};
use tokio::{
    net::{TcpListener, TcpSocket},
    task::JoinSet,
    time::Instant,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use super::Server;
use crate::{Result, config::EndpointSpec};

type AddressSource = Arc<dyn Fn() -> Result<Vec<String>> + Send + Sync>;

const POLL: Duration = Duration::from_secs(2);
const GRACE: Duration = Duration::from_secs(60);

struct Listener {
    stop: CancellationToken,
    task: tokio::task::JoinHandle<Result<()>>,
}

struct Group {
    spec: EndpointSpec,
    http: bool,
    active: HashMap<String, Listener>,
    empty_since: Option<Instant>,
}

impl Group {
    fn new(spec: EndpointSpec, http: bool) -> Self {
        Self {
            spec,
            http,
            active: HashMap::new(),
            empty_since: None,
        }
    }

    fn grace(&mut self, serving: bool, now: Instant) -> Result<()> {
        if serving {
            self.empty_since = None;
            return Ok(());
        }
        let EndpointSpec::Interface { name, .. } = &self.spec else {
            bail!("no address to listen on");
        };
        let since = *self.empty_since.get_or_insert_with(|| {
            eprintln!("pdsd: interface {name:?} has no usable address; waiting up to 60s");
            now
        });
        if now.duration_since(since) >= GRACE {
            bail!("interface {name:?} had no usable address for 60s");
        }
        Ok(())
    }

    async fn reconcile(
        &mut self,
        addresses: Vec<String>,
        server: &Server,
        stop: &CancellationToken,
        tasks: &TaskTracker,
    ) -> Result<()> {
        let desired: HashSet<_> = addresses.into_iter().collect();
        let removed: Vec<_> = self
            .active
            .keys()
            .filter(|addr| !desired.contains(*addr))
            .cloned()
            .collect();
        for addr in removed {
            let listener = self.active.remove(&addr).unwrap();
            listener.stop.cancel();
            listener.task.await??;
            if let EndpointSpec::Interface { name, .. } = &self.spec {
                eprintln!("pdsd: interface {name:?} lost {addr}, stopped listening");
            }
        }
        for address in desired {
            if self.active.contains_key(&address) {
                continue;
            }
            let raw = address.clone();
            let bind = tokio::task::spawn_blocking(move || bind_address(&raw)).await??;
            let listener = listen_address(&bind)
                .await
                .with_context(|| format!("listen {address}"))?;
            let local = listener.local_addr()?;
            match &self.spec {
                EndpointSpec::Interface { name, .. } => {
                    eprintln!("pdsd: interface {name:?} listening on {local}")
                }
                EndpointSpec::Static { .. } => eprintln!("pdsd: listening on {local}"),
            }
            let listener_stop = stop.child_token();
            let child_stop = listener_stop.clone();
            let stop = stop.clone();
            let server = server.clone();
            let tasks = tasks.clone();
            let http = self.http;
            let task = tokio::spawn(async move {
                if http {
                    server.accept_http(listener, child_stop).await
                } else {
                    server.accept_ssh(listener, child_stop, stop, tasks).await
                }
            });
            self.active.insert(
                address,
                Listener {
                    stop: listener_stop,
                    task,
                },
            );
        }
        self.grace(!self.active.is_empty(), Instant::now())
    }

    async fn close(&mut self) {
        for listener in self.active.values() {
            listener.stop.cancel();
        }
        for (_, listener) in self.active.drain() {
            let _ = listener.task.await;
        }
    }

    async fn run(
        mut self,
        server: Server,
        stop: CancellationToken,
        tasks: TaskTracker,
    ) -> Result<()> {
        let spec = self.spec.clone();
        let source: AddressSource = Arc::new(move || addresses(&spec));
        let result = self.poll(&server, &stop, &tasks, source).await;
        self.close().await;
        result
    }

    async fn listener_ended(&mut self) -> Result<()> {
        if self.active.is_empty() {
            return std::future::pending().await;
        }
        let (address, result) =
            futures_util::future::select_all(self.active.iter_mut().map(|(address, listener)| {
                Box::pin(async move { (address.clone(), (&mut listener.task).await) })
            }))
            .await
            .0;
        self.active.remove(&address);
        result?.with_context(|| format!("serve {address}"))?;
        bail!("serve {address} stopped unexpectedly")
    }

    async fn poll(
        &mut self,
        server: &Server,
        stop: &CancellationToken,
        tasks: &TaskTracker,
        source: AddressSource,
    ) -> Result<()> {
        let mut tick = tokio::time::interval(POLL);
        loop {
            tokio::select! {
                _ = stop.cancelled() => return Ok(()),
                result = self.listener_ended() => return result,
                _ = tick.tick() => {
                    if self.spec.is_static() && !self.active.is_empty() { continue; }
                    let source = source.clone();
                    let addresses = tokio::task::spawn_blocking(move || source()).await??;
                    self.reconcile(addresses, server, stop, tasks).await?;
                }
            }
        }
    }
}

pub(super) async fn run(
    server: Server,
    ssh: EndpointSpec,
    http: Option<EndpointSpec>,
    stop: CancellationToken,
    tasks: TaskTracker,
) -> Result<()> {
    let mut groups = JoinSet::new();
    groups.spawn(Group::new(ssh, false).run(server.clone(), stop.clone(), tasks.clone()));
    if let Some(spec) = http {
        groups.spawn(Group::new(spec, true).run(server, stop.clone(), tasks));
    }
    let result = groups.join_next().await.unwrap()?;
    stop.cancel();
    while groups.join_next().await.is_some() {}
    result
}

fn usable(ip: IpAddr, up: bool) -> bool {
    up && !ip.is_unspecified()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
}

fn service_port(port: &str) -> Result<u16> {
    if matches!(port, "" | "+" | "-") {
        return Ok(0);
    }
    if let Ok(port) = port.parse::<u16>() {
        return Ok(port);
    }
    let port = port.to_ascii_lowercase();
    if let Ok(services) = std::fs::read_to_string("/etc/services") {
        for line in services.lines() {
            let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
            if let (Some(name), Some(value)) = (fields.next(), fields.next())
                && let Some(number) = value.strip_suffix("/tcp")
                && (name == port || fields.any(|alias| alias == port))
            {
                return Ok(number.parse()?);
            }
        }
    }
    Ok(match port.as_str() {
        "ftp" => 21,
        "ftps" => 990,
        "gopher" => 70,
        "http" => 80,
        "https" => 443,
        "imap2" => 143,
        "imap3" => 220,
        "imaps" => 993,
        "pop3" => 110,
        "pop3s" => 995,
        "smtp" => 25,
        "submissions" => 465,
        "ssh" => 22,
        "telnet" => 23,
        _ => bail!("unknown TCP service {port:?}"),
    })
}

fn bind_address(address: &str) -> Result<String> {
    let (host, port) = crate::config::split_host_port(address)?;
    let port = service_port(port)?;
    Ok(if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    })
}

fn listen_wildcard(port: u16, ipv6: io::Result<TcpSocket>) -> io::Result<TcpListener> {
    let listener = ipv6.and_then(|socket| {
        setsockopt(&socket, Ipv6V6Only, &false)?;
        socket.set_reuseaddr(true)?;
        socket.bind(SocketAddr::from(([0u16; 8], port)))?;
        socket.listen(1024)
    });
    match listener {
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(
                    libc::EAFNOSUPPORT
                        | libc::EPROTONOSUPPORT
                        | libc::ENOPROTOOPT
                        | libc::EOPNOTSUPP
                        | libc::EADDRNOTAVAIL
                )
            ) =>
        {
            let socket = TcpSocket::new_v4()?;
            socket.set_reuseaddr(true)?;
            socket.bind(SocketAddr::from(([0; 4], port)))?;
            socket.listen(1024)
        }
        result => result,
    }
}

async fn listen_address(address: &str) -> io::Result<TcpListener> {
    let wildcard_port = address
        .strip_prefix(':')
        .and_then(|port| port.parse().ok())
        .or_else(|| {
            address
                .parse::<SocketAddr>()
                .ok()
                .filter(|addr| addr.ip().to_canonical().is_unspecified())
                .map(|addr| addr.port())
        });
    if let Some(port) = wildcard_port {
        listen_wildcard(port, TcpSocket::new_v6())
    } else {
        TcpListener::bind(address).await
    }
}

fn addresses(spec: &EndpointSpec) -> Result<Vec<String>> {
    let EndpointSpec::Interface { name, port } = spec else {
        let EndpointSpec::Static { addr } = spec else {
            unreachable!()
        };
        return Ok(vec![addr.clone()]);
    };
    let interfaces = getifaddrs().with_context(|| format!("interface {name:?}: enumeration failed (is AF_NETLINK allowed? see RestrictAddressFamilies)"))?;
    let mut addresses = Vec::new();
    for interface in interfaces.filter(|i| i.interface_name == *name) {
        let Some(addr) = interface.address else {
            continue;
        };
        let ip = addr
            .as_sockaddr_in()
            .map(|a| IpAddr::V4(a.ip()))
            .or_else(|| addr.as_sockaddr_in6().map(|a| IpAddr::V6(a.ip())));
        if let Some(ip) = ip
            && usable(ip, interface.flags.contains(InterfaceFlags::IFF_UP))
        {
            addresses.push(SocketAddr::new(ip, service_port(port)?).to_string());
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect_listener(listener: &TcpListener, host: IpAddr) {
        tokio::time::timeout(Duration::from_secs(2), async {
            let _stream = tokio::net::TcpStream::connect(SocketAddr::new(
                host,
                listener.local_addr().unwrap().port(),
            ))
            .await
            .unwrap();
            listener.accept().await.unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn wildcard_accepts_both_families_even_with_v6only_socket_default() {
        let socket = TcpSocket::new_v6().unwrap();
        setsockopt(&socket, Ipv6V6Only, &true).unwrap();
        let listener = listen_wildcard(0, Ok(socket)).unwrap();
        assert!(!nix::sys::socket::getsockopt(&listener, Ipv6V6Only).unwrap());
        connect_listener(&listener, "127.0.0.1".parse().unwrap()).await;
        connect_listener(&listener, "::1".parse().unwrap()).await;

        for address in [":0", "0.0.0.0:0", "[::]:0", "[::ffff:0.0.0.0]:0"] {
            let listener = listen_address(&bind_address(address).unwrap())
                .await
                .unwrap();
            connect_listener(&listener, "127.0.0.1".parse().unwrap()).await;
            connect_listener(&listener, "::1".parse().unwrap()).await;
        }
    }

    #[tokio::test]
    async fn wildcard_uses_ipv4_when_ipv6_is_unavailable() {
        for code in [
            libc::EAFNOSUPPORT,
            libc::EPROTONOSUPPORT,
            libc::ENOPROTOOPT,
            libc::EOPNOTSUPP,
            libc::EADDRNOTAVAIL,
        ] {
            let listener = listen_wildcard(0, Err(io::Error::from_raw_os_error(code))).unwrap();
            assert!(listener.local_addr().unwrap().is_ipv4());
            connect_listener(&listener, "127.0.0.1".parse().unwrap()).await;
        }
    }

    #[tokio::test]
    async fn wildcard_bind_conflicts_and_permission_errors_remain_fatal() {
        let socket = TcpSocket::new_v6().unwrap();
        setsockopt(&socket, Ipv6V6Only, &true).unwrap();
        socket.bind("[::]:0".parse().unwrap()).unwrap();
        let occupied = socket.listen(1024).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let error = listen_address(&format!(":{port}")).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        let ipv4 = TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
            .await
            .unwrap();
        drop(ipv4);
        for code in [libc::EACCES, libc::EPERM, libc::EMFILE] {
            assert_eq!(
                listen_wildcard(0, Err(io::Error::from_raw_os_error(code)))
                    .unwrap_err()
                    .raw_os_error(),
                Some(code)
            );
        }
    }

    #[tokio::test]
    async fn explicit_bind_addresses_stay_on_the_requested_interface() {
        for host in ["127.0.0.1", "::1"] {
            let host: IpAddr = host.parse().unwrap();
            let listener = listen_address(&SocketAddr::new(host, 0).to_string())
                .await
                .unwrap();
            assert_eq!(listener.local_addr().unwrap().ip(), host);
            connect_listener(&listener, host).await;
        }
    }

    #[tokio::test(start_paused = true)]
    async fn grace_expires_and_recovery_resets_it() {
        let mut group = Group::new(
            EndpointSpec::Interface {
                name: "test".into(),
                port: "1".into(),
            },
            false,
        );
        group.grace(false, Instant::now()).unwrap();
        tokio::time::advance(Duration::from_secs(59)).await;
        group.grace(false, Instant::now()).unwrap();
        group.grace(true, Instant::now()).unwrap();
        tokio::time::advance(Duration::from_secs(10)).await;
        group.grace(false, Instant::now()).unwrap();
        tokio::time::advance(Duration::from_secs(59)).await;
        group.grace(false, Instant::now()).unwrap();
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(group.grace(false, Instant::now()).is_err());
    }

    #[test]
    fn addresses_skip_down_local_multicast_and_unspecified() {
        for (ip, want) in [
            ("192.0.2.10", true),
            ("2001:db8::1", true),
            ("fd00::1", true),
            ("127.0.0.1", true),
            ("169.254.1.1", false),
            ("fe80::1", false),
            ("224.0.0.1", false),
            ("0.0.0.0", false),
            ("::", false),
        ] {
            assert_eq!(usable(ip.parse().unwrap(), true), want);
            assert!(!usable(ip.parse().unwrap(), false));
        }
        assert!(
            addresses(&EndpointSpec::Interface {
                name: "pds-missing-interface".into(),
                port: "1".into()
            })
            .unwrap()
            .is_empty()
        );
        assert!(
            include_str!("../../packaging/systemd/pds@.service")
                .lines()
                .any(|line| line.starts_with("RestrictAddressFamilies=")
                    && line.contains("AF_NETLINK"))
        );
    }

    fn server() -> Server {
        Server::new(
            crate::config::Server {
                allow_anonymous: true,
                ..Default::default()
            },
            vec![
                crate::keys::PrivateKey::random(&mut rand::rng(), crate::keys::Algorithm::Ed25519)
                    .unwrap(),
            ],
        )
        .unwrap()
    }

    #[tokio::test]
    async fn reconcile_removes_addresses_closes_http_connections_and_fails_on_bind() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = first.local_addr().unwrap().to_string();
        let b = second.local_addr().unwrap().to_string();
        drop((first, second));
        let server = server();
        let stop = CancellationToken::new();
        let tasks = TaskTracker::new();
        let mut group = Group::new(
            EndpointSpec::Interface {
                name: "test".into(),
                port: "0".into(),
            },
            true,
        );
        group
            .reconcile(
                vec![a.clone(), b.clone(), a.clone()],
                &server,
                &stop,
                &tasks,
            )
            .await
            .unwrap();
        assert_eq!(group.active.len(), 2);
        let mut socket = tokio::net::TcpStream::connect(&a).await.unwrap();
        socket
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut buffer = [0; 1024];
        assert!(socket.read(&mut buffer).await.unwrap() > 0);
        group
            .reconcile(vec![b.clone()], &server, &stop, &tasks)
            .await
            .unwrap();
        assert!(tokio::net::TcpStream::connect(&a).await.is_err());
        assert_eq!(socket.read(&mut buffer).await.unwrap(), 0);
        assert!(tokio::net::TcpStream::connect(&b).await.is_ok());
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(
            group
                .reconcile(
                    vec![b.clone(), occupied.local_addr().unwrap().to_string()],
                    &server,
                    &stop,
                    &tasks
                )
                .await
                .is_err()
        );
        group.close().await;
        assert!(tokio::net::TcpStream::connect(&b).await.is_err());
    }

    #[tokio::test]
    async fn enumeration_failure_is_fatal_and_endpoint_failure_closes_sibling() {
        let mut group = Group::new(
            EndpointSpec::Interface {
                name: "test".into(),
                port: "0".into(),
            },
            false,
        );
        let stop = CancellationToken::new();
        let tasks = TaskTracker::new();
        let source: AddressSource = Arc::new(|| anyhow::bail!("enumeration failed"));
        let error = group
            .poll(&server(), &stop, &tasks, source)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("enumeration failed"));
        let available = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = available.local_addr().unwrap();
        drop(available);
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let error = run(
            server(),
            EndpointSpec::Static {
                addr: address.to_string(),
            },
            Some(EndpointSpec::Static {
                addr: occupied.local_addr().unwrap().to_string(),
            }),
            stop.clone(),
            tasks,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("listen"));
        assert!(stop.is_cancelled());
        assert!(TcpListener::bind(address).await.is_ok());
    }

    #[test]
    fn bind_service_names_and_wildcards() {
        assert_eq!(bind_address(":ssh").unwrap(), ":22");
        assert_eq!(bind_address("[::1]:http").unwrap(), "[::1]:80");
        assert_eq!(bind_address("localhost:+123").unwrap(), "localhost:123");
        assert_eq!(service_port("-").unwrap(), 0);
    }
}
