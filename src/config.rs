use std::collections::{BTreeMap, HashMap, HashSet};
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_yaml_ng::{Mapping, Value};

use crate::validate::Validator;

pub const NAME_SELF: &str = ".self";
pub const NAME_META: &str = ".meta";
pub const NAME_PUSH: &str = ".push";
pub const NAME_PDS: &str = ".pds";
pub const NAME_EXEC: &str = "exec";
pub const ANONYMOUS_USER: &str = "anonymous";
pub const DEFAULT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientEndpoint {
    #[serde(deserialize_with = "go_string")]
    pub host: String,
    #[serde(deserialize_with = "go_integer")]
    pub ssh_port: i64,
    #[serde(deserialize_with = "go_integer")]
    pub http_port: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoDuration(pub i64);

impl GoDuration {
    pub fn parse(input: &str) -> Result<Self> {
        let negative = input.starts_with('-');
        let mut rest = input.strip_prefix(['+', '-']).unwrap_or(input);
        if rest == "0" {
            return Ok(Self(0));
        }
        ensure!(!rest.is_empty(), "invalid duration {input:?}");
        let mut total = 0_u64;
        while !rest.is_empty() {
            let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
            let integer: u64 = if digits == 0 {
                0
            } else {
                rest[..digits].parse()?
            };
            rest = &rest[digits..];
            let mut fraction = 0_u64;
            let mut scale = 1_f64;
            let mut fractional_digits = 0;
            if let Some(tail) = rest.strip_prefix('.') {
                fractional_digits = tail.bytes().take_while(u8::is_ascii_digit).count();
                let mut overflow = false;
                for digit in tail[..fractional_digits].bytes() {
                    if !overflow {
                        if let Some(value) = fraction
                            .checked_mul(10)
                            .and_then(|v| v.checked_add(u64::from(digit - b'0')))
                            .filter(|v| *v <= (1_u64 << 63))
                        {
                            fraction = value;
                            scale *= 10.0;
                        } else {
                            overflow = true;
                        }
                    }
                }
                rest = &tail[fractional_digits..];
            }
            ensure!(
                digits > 0 || fractional_digits > 0,
                "invalid duration {input:?}"
            );
            let unit_end = rest
                .find(|c: char| c.is_ascii_digit() || c == '.')
                .unwrap_or(rest.len());
            let unit = match &rest[..unit_end] {
                "ns" => 1_u64,
                "us" | "\u{b5}s" | "\u{3bc}s" => 1_000,
                "ms" => 1_000_000,
                "s" => 1_000_000_000,
                "m" => 60_000_000_000,
                "h" => 3_600_000_000_000,
                _ => bail!("invalid duration {input:?}"),
            };
            rest = &rest[unit_end..];
            let value = integer
                .checked_mul(unit)
                .and_then(|v| v.checked_add((fraction as f64 * (unit as f64 / scale)) as u64))
                .context("duration overflow")?;
            total = total.checked_add(value).context("duration overflow")?;
            ensure!(total <= (1_u64 << 63), "duration overflow");
        }
        if negative {
            Ok(Self((total as i64).wrapping_neg()))
        } else {
            Ok(Self(i64::try_from(total).context("duration overflow")?))
        }
    }
}

impl Serialize for GoDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{}ns", self.0))
    }
}

impl<'de> Deserialize<'de> for GoDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(value, _) => Self::parse(&value).map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom(
                "duration must be a Go duration string",
            )),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Client {
    #[serde(deserialize_with = "go_structs")]
    pub endpoints: Vec<ClientEndpoint>,
    pub dial_timeout: Option<GoDuration>,
    #[serde(deserialize_with = "go_strings")]
    pub trusted_keys: Vec<String>,
    #[serde(deserialize_with = "go_strings")]
    pub identities: Vec<String>,
}

impl Client {
    pub fn effective_dial_timeout(&self) -> Duration {
        self.dial_timeout.map_or(DEFAULT_DIAL_TIMEOUT, |timeout| {
            Duration::from_nanos(timeout.0.max(0) as u64)
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.endpoints.is_empty(),
            "config: at least one endpoints entry is required"
        );
        let mut seen = HashMap::new();
        for (i, endpoint) in self.endpoints.iter().enumerate() {
            ensure!(
                !endpoint.host.trim().is_empty(),
                "config: endpoints[{i}] has no host"
            );
            ensure!(
                (1..=65535).contains(&endpoint.ssh_port),
                "config: endpoints[{i}] sshPort must be between 1 and 65535"
            );
            ensure!(
                (0..=65535).contains(&endpoint.http_port),
                "config: endpoints[{i}] httpPort must be 0 or between 1 and 65535"
            );
            let key = normalized_client_ssh_endpoint(endpoint);
            if let Some(previous) = seen.insert(key.clone(), i) {
                bail!(
                    "config: endpoints[{i}] duplicates endpoints[{previous}] SSH endpoint {key:?}"
                );
            }
        }
        ensure!(
            self.dial_timeout.is_none_or(|v| v.0 > 0),
            "config: dialTimeout must be positive"
        );
        ensure!(
            !self.trusted_keys.is_empty(),
            "config: at least one trustedKeys entry is required"
        );
        Ok(())
    }
}

pub fn normalized_client_ssh_endpoint(endpoint: &ClientEndpoint) -> String {
    let host = endpoint.host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host);
    let (address, zone) = host
        .split_once('%')
        .map_or((host, None), |(ip, zone)| (ip, Some(zone)));
    let host = match address.parse::<IpAddr>() {
        Ok(ip) if zone.is_none() || ip.is_ipv6() => {
            format!(
                "{ip}{}",
                zone.map_or(String::new(), |zone| format!("%{zone}"))
            )
        }
        _ => host.to_lowercase(),
    };
    if host.contains(':') {
        format!("[{host}]:{}", endpoint.ssh_port)
    } else {
        format!("{host}:{}", endpoint.ssh_port)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Server {
    #[serde(deserialize_with = "go_string")]
    pub ssh_listen: String,
    #[serde(deserialize_with = "go_string")]
    pub http_listen: String,
    #[serde(deserialize_with = "go_structs")]
    pub authorized_keys: Vec<ClientEntry>,
    #[serde(deserialize_with = "go_bool")]
    pub allow_anonymous: bool,
    #[serde(deserialize_with = "go_string")]
    pub exec_bucket: String,
    #[serde(deserialize_with = "go_buckets")]
    pub buckets: BTreeMap<String, Bucket>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientEntry {
    #[serde(deserialize_with = "go_string")]
    pub host: String,
    #[serde(deserialize_with = "go_strings")]
    pub keys: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Mode {
    #[default]
    ReadOnly,
    ReadWrite,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "ro",
            Self::ReadWrite => "rw",
        }
    }
}

impl Serialize for Mode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match go_string(deserializer)?.to_ascii_lowercase().as_str() {
            "" | "ro" => Ok(Self::ReadOnly),
            "rw" => Ok(Self::ReadWrite),
            _ => Err(serde::de::Error::custom("bucket mode must be ro or rw")),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields, rename_all = "camelCase")]
pub struct Bucket {
    #[serde(deserialize_with = "go_path")]
    pub path: PathBuf,
    #[serde(deserialize_with = "null_default")]
    pub mode: Mode,
    #[serde(deserialize_with = "go_bool")]
    pub versioned: bool,
    #[serde(deserialize_with = "go_bool")]
    pub by_host: bool,
    #[serde(deserialize_with = "go_string")]
    pub extension: String,
    #[serde(deserialize_with = "null_default")]
    pub validator: Validator,
}

impl Bucket {
    pub fn writable(&self) -> bool {
        self.mode == Mode::ReadWrite
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointSpec {
    Static { addr: String },
    Interface { name: String, port: String },
}

impl EndpointSpec {
    pub fn is_static(&self) -> bool {
        matches!(self, Self::Static { .. })
    }
}

pub fn split_host_port(value: &str) -> Result<(&str, &str)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').context("missing ']' in address")?;
        (
            host,
            rest.strip_prefix(':').context("missing port in address")?,
        )
    } else {
        let (host, port) = value.split_once(':').context("missing port in address")?;
        ensure!(!host.contains(['[', ']']), "unexpected bracket in address");
        (host, port)
    };
    ensure!(
        !host.contains(['[', ']']) && !port.contains([':', '[', ']']),
        "invalid host:port address"
    );
    Ok((host, port))
}

pub fn parse_endpoint(value: &str) -> Result<EndpointSpec> {
    if let Some(rest) = value.strip_prefix("iface:") {
        let (name, port) =
            split_host_port(rest).with_context(|| format!("interface listen {value:?}"))?;
        ensure!(
            !name.is_empty(),
            "interface listen {value:?}: missing interface name"
        );
        ensure!(
            !name.contains(['/', '%', '[', ']']),
            "interface listen {value:?}: invalid interface name {name:?}"
        );
        ensure!(
            valid_interface_port(port),
            "interface listen {value:?}: invalid port {port:?}"
        );
        Ok(EndpointSpec::Interface {
            name: name.into(),
            port: port.into(),
        })
    } else {
        let (_, port) = split_host_port(value).with_context(|| format!("listen {value:?}"))?;
        ensure!(!port.is_empty(), "listen {value:?}: missing port");
        Ok(EndpointSpec::Static { addr: value.into() })
    }
}

fn valid_interface_port(port: &str) -> bool {
    if matches!(port, "" | "+" | "-") {
        return true;
    }
    if let Ok(number) = port.parse::<i64>() {
        return (0..=65535).contains(&number);
    }
    let port = port.to_ascii_lowercase();
    if matches!(
        port.as_str(),
        "ftp"
            | "ftps"
            | "gopher"
            | "http"
            | "https"
            | "imap2"
            | "imap3"
            | "imaps"
            | "pop3"
            | "pop3s"
            | "smtp"
            | "submissions"
            | "ssh"
            | "telnet"
    ) {
        return true;
    }
    // Go's TCP service names come from the system services database.
    if let Ok(services) = fs::read_to_string("/etc/services") {
        for line in services.lines() {
            let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
            if let (Some(name), Some(service)) = (fields.next(), fields.next())
                && service.ends_with("/tcp")
                && (name.eq_ignore_ascii_case(&port)
                    || fields.any(|alias| alias.eq_ignore_ascii_case(&port)))
            {
                return true;
            }
        }
    }
    false
}

impl Server {
    pub fn ssh_endpoint(&self) -> Result<EndpointSpec> {
        parse_endpoint(&self.ssh_listen)
    }

    pub fn http_endpoint(&self) -> Result<Option<EndpointSpec>> {
        if self.http_listen.is_empty() {
            Ok(None)
        } else {
            parse_endpoint(&self.http_listen).map(Some)
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.ssh_listen.is_empty(), "config: sshListen is required");
        self.ssh_endpoint().context("config")?;
        if !self.http_listen.is_empty() {
            ensure!(
                self.allow_anonymous,
                "config: httpListen requires allowAnonymous: true (HTTP is unauthenticated read-only access)"
            );
            self.http_endpoint().context("config")?;
        }
        ensure!(
            !self.authorized_keys.is_empty() || self.allow_anonymous,
            "config: at least one authorizedKeys entry is required (or set allowAnonymous: true)"
        );
        for (i, entry) in self.authorized_keys.iter().enumerate() {
            ensure!(
                !entry.host.is_empty(),
                "config: authorizedKeys[{i}] has no host"
            );
            ensure!(
                !entry.keys.is_empty(),
                "config: authorizedKeys host {:?} has no keys",
                entry.host
            );
        }
        for (name, bucket) in &self.buckets {
            ensure!(
                !name.starts_with('.'),
                "config: bucket name {name:?} may not begin with '.'"
            );
            ensure!(
                !bucket.path.as_os_str().is_empty(),
                "config: bucket {name:?} has no path"
            );
            if bucket.writable() {
                ensure!(
                    !bucket.extension.is_empty(),
                    "config: rw bucket {name:?} requires extension"
                );
                ensure!(
                    valid_extension(&bucket.extension),
                    "config: rw bucket {name:?} extension {:?} must be a safe filename suffix",
                    bucket.extension
                );
                ensure!(
                    bucket.validator.known(),
                    "config: rw bucket {name:?} validator {:?} must be one of {:?}",
                    bucket.validator.as_str(),
                    Validator::NAMES
                );
            }
        }
        if !self.exec_bucket.is_empty() {
            let bucket = self.buckets.get(&self.exec_bucket).with_context(|| {
                format!(
                    "config: execBucket {:?} is not a defined bucket",
                    self.exec_bucket
                )
            })?;
            ensure!(
                !bucket.writable(),
                "config: execBucket {:?} must be mode ro (got rw)",
                self.exec_bucket
            );
        }
        Ok(())
    }
}

pub fn valid_extension(extension: &str) -> bool {
    let bytes = extension.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_alphanumeric()
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(b))
        && !extension.contains("..")
}

pub fn expand_user(path: impl AsRef<Path>) -> Result<PathBuf> {
    let path = path.as_ref();
    if path == Path::new("~") || path.starts_with("~/") {
        let home = env::var_os("HOME")
            .filter(|v| !v.is_empty())
            .context("HOME is not defined")?;
        let joined = PathBuf::from(home).join(path.strip_prefix("~")?);
        let mut clean = PathBuf::new();
        for component in joined.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    if clean.file_name().is_some_and(|name| name != "..") {
                        clean.pop();
                    } else if !clean.has_root() {
                        clean.push("..");
                    }
                }
                component => clean.push(component.as_os_str()),
            }
        }
        if clean.as_os_str().is_empty() {
            clean.push(".");
        }
        Ok(clean)
    } else {
        Ok(path.into())
    }
}

pub fn tier_roots(role: Role) -> Vec<PathBuf> {
    let xdg = env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map_or_else(
            || PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".config"),
            PathBuf::from,
        );
    [
        PathBuf::from("/usr/lib/pds"),
        PathBuf::from("/etc/pds"),
        xdg.join("pds"),
    ]
    .into_iter()
    .map(|root| root.join(role.as_str()))
    .collect()
}

pub fn layer_files(root: impl AsRef<Path>) -> Vec<PathBuf> {
    let root = root.as_ref();
    let mut files = Vec::new();
    let base = root.join("config.yaml");
    if base.is_file() {
        files.push(base);
    }
    if let Ok(entries) = fs::read_dir(root.join("config.d")) {
        let mut drops: Vec<_> = entries
            .filter_map(Result::ok)
            .filter(|entry| {
                !entry.file_type().is_ok_and(|kind| kind.is_dir())
                    && [b".yaml".as_slice(), b".yml".as_slice()]
                        .iter()
                        .any(|suffix| entry.file_name().as_encoded_bytes().ends_with(suffix))
            })
            .map(|entry| entry.path())
            .collect();
        drops.sort();
        files.extend(drops);
    }
    files
}

pub fn merge_map(dst: &mut Mapping, src: Mapping) {
    for (key, value) in src {
        match (dst.get_mut(&key), value) {
            (Some(Value::Mapping(dst)), Value::Mapping(src))
                if dst.keys().all(|key| matches!(key, Value::String(..)))
                    && src.keys().all(|key| matches!(key, Value::String(..))) =>
            {
                merge_map(dst, src);
            }
            (Some(Value::Sequence(dst)), Value::Sequence(src)) => {
                let mut seen: HashSet<String> = dst
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect();
                for value in src {
                    if let Value::String(ref s, _) = value
                        && !seen.insert(s.clone())
                    {
                        continue;
                    }
                    dst.push(value);
                }
            }
            (_, value) => {
                dst.insert(key, value);
            }
        }
    }
}

pub fn merge_config_map(dst: &mut Mapping, src: Mapping, role: Role) {
    let endpoints = (role == Role::Client)
        .then(|| src.get("endpoints").cloned())
        .flatten();
    merge_map(dst, src);
    if let Some(endpoints) = endpoints {
        dst.insert(Value::String("endpoints".into(), None), endpoints);
    }
}

pub fn merge_file(dst: &mut Mapping, path: impl AsRef<Path>, role: Role) -> Result<()> {
    let path = path.as_ref();
    let data = fs::read(path).with_context(|| format!("config: reading {}", path.display()))?;
    let value = crate::yaml::first_document(&data)
        .with_context(|| format!("config: parsing {}", path.display()))?;
    match value {
        Value::Null(_) => Ok(()),
        Value::Mapping(src) => {
            merge_config_map(dst, src, role);
            Ok(())
        }
        _ => bail!("config: {} must contain a mapping", path.display()),
    }
}

pub fn load_merged_from_roots(
    role: Role,
    roots: &[PathBuf],
    override_path: Option<&Path>,
) -> Result<Mapping> {
    let mut merged = Mapping::new();
    for root in roots {
        for path in layer_files(root) {
            merge_file(&mut merged, path, role)?;
        }
    }
    if let Some(path) = override_path {
        merge_file(&mut merged, path, role)?;
    }
    Ok(merged)
}

pub fn load_client_unvalidated(override_path: Option<&Path>) -> Result<Client> {
    decode(load_merged_from_roots(
        Role::Client,
        &tier_roots(Role::Client),
        override_path,
    )?)
}

pub fn load_client(override_path: Option<&Path>) -> Result<Client> {
    let client = load_client_unvalidated(override_path)?;
    client.validate()?;
    Ok(client)
}

pub fn load_server(override_path: Option<&Path>) -> Result<Server> {
    let mut server: Server = decode(load_merged_from_roots(
        Role::Server,
        &tier_roots(Role::Server),
        override_path,
    )?)?;
    for (name, bucket) in &mut server.buckets {
        bucket.path = expand_user(&bucket.path)
            .with_context(|| format!("config: bucket {name:?} path {:?}", bucket.path))?;
    }
    server.validate()?;
    Ok(server)
}

pub fn decode<T: serde::de::DeserializeOwned>(mapping: Mapping) -> Result<T> {
    let value = crate::yaml::config_merges(Value::Mapping(mapping))?;
    serde_yaml_ng::from_value(value).context("config")
}

fn null_default<'de, D: Deserializer<'de>, T: Deserialize<'de> + Default>(
    deserializer: D,
) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

fn scalar_string(value: Value) -> Result<String> {
    match value {
        Value::Null(_) => Ok(String::new()),
        Value::String(value, _) => Ok(value),
        Value::Bool(value, _) => Ok(value.to_string()),
        Value::Number(value, _) if value.is_f64() => {
            let value = value.as_f64().expect("floating point number");
            if value.is_nan() {
                return Ok(".nan".into());
            }
            if value.is_infinite() {
                return Ok(if value.is_sign_negative() {
                    "-.inf"
                } else {
                    ".inf"
                }
                .into());
            }
            if value != 0.0 && (value.abs() < 1e-4 || value.abs() >= 1e6) {
                let text = format!("{value:e}");
                let (mantissa, exponent) = text.split_once('e').expect("scientific notation");
                let exponent: i32 = exponent.parse().expect("decimal exponent");
                Ok(format!("{mantissa}e{exponent:+03}"))
            } else {
                Ok(value.to_string())
            }
        }
        Value::Number(value, _) => Ok(value.to_string()),
        _ => bail!("expected a scalar string"),
    }
}

fn go_structs<'de, D: Deserializer<'de>, T: serde::de::DeserializeOwned>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    let values: Vec<Value> = null_default(deserializer)?;
    values
        .into_iter()
        .filter(|value| !value.is_null())
        .map(|value| serde_yaml_ng::from_value(value).map_err(serde::de::Error::custom))
        .collect()
}

fn go_buckets<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Bucket>, D::Error> {
    let values: Mapping = null_default(deserializer)?;
    values
        .into_iter()
        .map(|(key, value)| {
            let name = scalar_string(key).map_err(serde::de::Error::custom)?;
            let bucket = if value.is_null() {
                Bucket::default()
            } else {
                serde_yaml_ng::from_value(value).map_err(serde::de::Error::custom)?
            };
            Ok((name, bucket))
        })
        .collect()
}

pub(crate) fn go_string<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    scalar_string(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
}

fn go_path<'de, D: Deserializer<'de>>(deserializer: D) -> Result<PathBuf, D::Error> {
    let value = Value::deserialize(deserializer)?;
    #[cfg(unix)]
    if let Value::Tagged(tagged) = &value
        && tagged.tag == "binary"
        && let Some(encoded) = tagged.value.as_str()
    {
        use base64::Engine;
        use std::os::unix::ffi::OsStringExt;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)?;
        return Ok(std::ffi::OsString::from_vec(bytes).into());
    }
    scalar_string(value)
        .map(PathBuf::from)
        .map_err(serde::de::Error::custom)
}

fn go_strings<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<String>, D::Error> {
    let values: Vec<Value> = null_default(deserializer)?;
    values
        .into_iter()
        .filter(|value| !value.is_null())
        .map(|value| scalar_string(value).map_err(serde::de::Error::custom))
        .collect()
}

fn go_integer<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Null(_) => Ok(0),
        Value::Number(number, _) => {
            if let Some(value) = number.as_i64() {
                return Ok(value);
            }
            if number.is_f64()
                && let Some(value) = number.as_f64()
                && value >= i64::MIN as f64
                && value < -(i64::MIN as f64)
            {
                return Ok(value as i64);
            }
            Err(serde::de::Error::custom("integer out of range"))
        }
        _ => Err(serde::de::Error::custom("expected an integer")),
    }
}

fn go_bool<'de, D: Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    match Value::deserialize(deserializer)? {
        Value::Null(_) => Ok(false),
        Value::Bool(value, _) => Ok(value),
        Value::String(value, _) => match value.as_str() {
            "y" | "Y" | "yes" | "Yes" | "YES" | "on" | "On" | "ON" => Ok(true),
            "n" | "N" | "no" | "No" | "NO" | "off" | "Off" | "OFF" => Ok(false),
            _ => Err(serde::de::Error::custom("expected a boolean")),
        },
        _ => Err(serde::de::Error::custom("expected a boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(yaml: &str) -> Mapping {
        let Value::Mapping(mapping) = crate::yaml::first_document(yaml.as_bytes()).unwrap() else {
            panic!("expected a mapping");
        };
        mapping
    }

    fn client() -> Client {
        Client {
            endpoints: vec![ClientEndpoint {
                host: "host.example".into(),
                ssh_port: 22,
                http_port: 0,
            }],
            trusted_keys: vec!["key".into()],
            ..Client::default()
        }
    }

    fn server() -> Server {
        Server {
            ssh_listen: ":2222".into(),
            allow_anonymous: true,
            ..Server::default()
        }
    }

    #[test]
    fn merge_rules_preserve_order_and_only_deduplicate_strings() {
        let mut dst = mapping("scalar: old\nlist: [a, a, b, {x: 1}]\nnested: {keep: 1, over: old}");
        merge_map(
            &mut dst,
            mapping("scalar: new\nlist: [b, c, c, {x: 1}]\nnested: {over: new, add: 2}"),
        );
        assert_eq!(
            dst,
            mapping(
                "scalar: new\nlist: [a, a, b, {x: 1}, c, {x: 1}]\nnested: {keep: 1, over: new, add: 2}"
            )
        );
        let base = mapping(
            "endpoints: [{host: old, sshPort: 22}]\ntrustedKeys: [old-key]\nidentities: [old-id]",
        );
        let next = mapping(
            "endpoints: [{host: new, sshPort: 2222}]\ntrustedKeys: [new-key]\nidentities: [new-id]",
        );
        let mut merged = base.clone();
        merge_config_map(&mut merged, next.clone(), Role::Client);
        let client: Client = decode(merged).unwrap();
        assert_eq!(client.endpoints.len(), 1);
        assert_eq!(client.endpoints[0].host, "new");
        assert_eq!(client.trusted_keys, ["old-key", "new-key"]);
        assert_eq!(client.identities, ["old-id", "new-id"]);
        let mut merged = base;
        merge_config_map(&mut merged, next, Role::Server);
        assert_eq!(merged["endpoints"].as_sequence().unwrap().len(), 2);
        merge_config_map(&mut merged, mapping("endpoints: []"), Role::Client);
        assert!(merged["endpoints"].as_sequence().unwrap().is_empty());
        merge_config_map(&mut merged, mapping("endpoints: null"), Role::Client);
        assert!(decode::<Client>(merged).unwrap().endpoints.is_empty());
    }

    #[test]
    fn files_and_tiers_apply_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let roots: Vec<_> = ["vendor", "system", "user"]
            .into_iter()
            .map(|name| dir.path().join(name))
            .collect();
        for root in &roots {
            fs::create_dir_all(root.join("config.d")).unwrap();
        }
        fs::write(
            roots[0].join("config.yaml"),
            "sshListen: ':1'\nallowAnonymous: true\nbuckets: {scripts: {path: /srv/scripts}}",
        )
        .unwrap();
        fs::write(roots[1].join("config.yaml"), "sshListen: ':2'\n").unwrap();
        fs::write(roots[2].join("config.yaml"), "sshListen: ':3'\n").unwrap();
        fs::write(roots[2].join("config.d/20-last.yml"), "sshListen: ':5'\n").unwrap();
        fs::write(roots[2].join("config.d/10-first.yaml"), "sshListen: ':4'\nbuckets: {metrics: {path: /data/metrics, mode: RW, extension: yaml, validator: yaml}}").unwrap();
        fs::write(roots[2].join("config.d/00-ignore.txt"), "unknown: ignored").unwrap();
        fs::create_dir(roots[2].join("config.d/99-ignore.yaml")).unwrap();
        let files = layer_files(&roots[2]);
        assert_eq!(files.len(), 3);
        assert!(files[1].ends_with("10-first.yaml"));
        let server: Server =
            decode(load_merged_from_roots(Role::Server, &roots, None).unwrap()).unwrap();
        server.validate().unwrap();
        assert_eq!(server.ssh_listen, ":5");
        assert_eq!(server.buckets.len(), 2);
        assert!(server.buckets["metrics"].writable());
        let override_path = dir.path().join("override");
        fs::write(&override_path, "sshListen: ':6'").unwrap();
        let server: Server =
            decode(load_merged_from_roots(Role::Server, &roots, Some(&override_path)).unwrap())
                .unwrap();
        assert_eq!(server.ssh_listen, ":6");
        assert!(
            load_merged_from_roots(Role::Server, &roots, Some(&dir.path().join("missing")))
                .is_err()
        );
    }

    #[test]
    fn unknown_fields_are_rejected_at_every_level() {
        for yaml in [
            "host: legacy.example\nsshPort: 22",
            "anonymous: true",
            "endpoints: [{host: h, sshPort: 22, unknown: x}]",
            "dialTimeout: soon",
            "dialTimeout: 1000",
        ] {
            assert!(decode::<Client>(mapping(yaml)).is_err(), "{yaml}");
        }
        for yaml in [
            "unknown: true",
            "authorizedKeys: [{host: h, keys: [k], unknown: x}]",
            "buckets: {b: {path: /b, unknown: true}}",
            "buckets: {b: {mode: bad}}",
        ] {
            assert!(decode::<Server>(mapping(yaml)).is_err(), "{yaml}");
        }
        let cfg: Client = decode(mapping(
            "endpoints: [{host: mirror.example, httpPort: 8080}]",
        ))
        .unwrap();
        assert!(cfg.validate().is_err());
        assert_eq!(cfg.endpoints[0].http_port, 8080);
        assert_eq!(cfg.effective_dial_timeout(), DEFAULT_DIAL_TIMEOUT);
    }

    #[test]
    fn client_validation_and_normalized_duplicates() {
        client().validate().unwrap();
        assert!(Client::default().validate().is_err());
        for endpoint in [
            ClientEndpoint {
                host: " \t".into(),
                ssh_port: 22,
                http_port: 0,
            },
            ClientEndpoint {
                host: "h".into(),
                ssh_port: 0,
                http_port: 0,
            },
            ClientEndpoint {
                host: "h".into(),
                ssh_port: -1,
                http_port: 0,
            },
            ClientEndpoint {
                host: "h".into(),
                ssh_port: 65536,
                http_port: 0,
            },
            ClientEndpoint {
                host: "h".into(),
                ssh_port: 22,
                http_port: -1,
            },
            ClientEndpoint {
                host: "h".into(),
                ssh_port: 22,
                http_port: 65536,
            },
        ] {
            let cfg = Client {
                endpoints: vec![endpoint],
                ..client()
            };
            assert!(cfg.validate().is_err());
        }
        let mut cfg = client();
        cfg.trusted_keys.clear();
        assert!(cfg.validate().is_err());
        for (a, b) in [
            ("host.example", "host.example"),
            ("HOST.Example", " host.example "),
            ("[0:0:0:0:0:0:0:1]", "::1"),
            ("[fe80:0:0:0:0:0:0:1%eth0]", "fe80::1%eth0"),
        ] {
            let cfg = Client {
                endpoints: vec![
                    ClientEndpoint {
                        host: a.into(),
                        ssh_port: 22,
                        http_port: 0,
                    },
                    ClientEndpoint {
                        host: b.into(),
                        ssh_port: 22,
                        http_port: 8080,
                    },
                ],
                ..client()
            };
            assert!(cfg.validate().is_err(), "{a} {b}");
        }
        let mut cfg = client();
        cfg.endpoints.push(ClientEndpoint {
            host: "host.example".into(),
            ssh_port: 2222,
            http_port: 8080,
        });
        cfg.validate().unwrap();
    }

    #[test]
    fn go_duration_syntax_and_bounds() {
        for (text, nanos) in [
            ("0", 0),
            ("+0", 0),
            ("-0", 0),
            ("10s", 10_000_000_000),
            ("1h2m3.5s", 3_723_500_000_000),
            (".5s", 500_000_000),
            ("1.s", 1_000_000_000),
            ("-1ms", -1_000_000),
            ("2\u{b5}s", 2000),
            ("2\u{3bc}s", 2000),
            ("9223372036854775807ns", i64::MAX),
            ("-9223372036854775808ns", i64::MIN),
            (
                "0.33333333333333333333333333333333333333h",
                1_200_000_000_000,
            ),
        ] {
            assert_eq!(
                GoDuration::parse(text).unwrap(),
                GoDuration(nanos),
                "{text}"
            );
        }
        for text in [
            "",
            "+",
            ".s",
            "1",
            "soon",
            "1d",
            "1 s",
            "1e3s",
            "9223372036854775808ns",
            "-9223372036854775809ns",
            "999999999999999999999999999999h",
            "1\u{2603}",
        ] {
            assert!(GoDuration::parse(text).is_err(), "{text}");
        }
        let cfg: Client = decode(mapping("dialTimeout: 1.5s")).unwrap();
        assert_eq!(cfg.effective_dial_timeout(), Duration::from_millis(1500));
        for nanos in [0, -1] {
            let cfg = Client {
                dial_timeout: Some(GoDuration(nanos)),
                ..client()
            };
            assert!(cfg.validate().is_err());
        }
    }

    #[test]
    fn server_validation() {
        assert!(Server::default().validate().is_err());
        server().validate().unwrap();
        let mut cfg = server();
        cfg.allow_anonymous = false;
        assert!(cfg.validate().is_err());
        cfg.authorized_keys.push(ClientEntry {
            host: "h".into(),
            keys: vec!["k".into()],
        });
        cfg.validate().unwrap();
        cfg.http_listen = ":8080".into();
        assert!(cfg.validate().is_err());
        cfg.allow_anonymous = true;
        cfg.validate().unwrap();
        cfg.authorized_keys[0].host.clear();
        assert!(cfg.validate().is_err());
        cfg.authorized_keys[0].host = "h".into();
        cfg.authorized_keys[0].keys.clear();
        assert!(cfg.validate().is_err());
        let mut cfg = server();
        let mut bucket = Bucket {
            path: "/data".into(),
            mode: Mode::ReadWrite,
            extension: "yaml".into(),
            ..Bucket::default()
        };
        cfg.buckets.insert("data".into(), bucket.clone());
        assert!(cfg.validate().is_err());
        bucket.validator = Validator::Yaml;
        for extension in [
            "../x", "/x", ".", "..", "a/b", "x..", "a\\b", "a.", "_a", "a-", "a..b", "",
        ] {
            bucket.extension = extension.into();
            cfg.buckets.insert("data".into(), bucket.clone());
            assert!(cfg.validate().is_err(), "{extension}");
        }
        for extension in ["yaml", "json", "tar.gz", "txt", "a_b-c.d", "1"] {
            bucket.extension = extension.into();
            cfg.buckets.insert("data".into(), bucket.clone());
            cfg.validate().unwrap();
        }
        cfg.exec_bucket = "missing".into();
        assert!(cfg.validate().is_err());
        cfg.exec_bucket = "data".into();
        assert!(cfg.validate().is_err());
        cfg.buckets.get_mut("data").unwrap().mode = Mode::ReadOnly;
        cfg.validate().unwrap();
        cfg.buckets.insert(".reserved".into(), bucket);
        assert!(cfg.validate().is_err());
        cfg.buckets.remove(".reserved");
        cfg.buckets.get_mut("data").unwrap().path.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn listen_endpoints_and_accessors() {
        for value in [
            ":2222",
            "127.0.0.1:2222",
            "[::1]:2222",
            "myhost.example:2222",
            ":unresolved",
            ":70000",
        ] {
            assert_eq!(
                parse_endpoint(value).unwrap(),
                EndpointSpec::Static { addr: value.into() }
            );
        }
        for (value, name, port) in [
            ("iface:eth0:2222", "eth0", "2222"),
            ("iface:tailscale0:443", "tailscale0", "443"),
            ("iface:eth0:0", "eth0", "0"),
            ("iface:eth0:http", "eth0", "http"),
        ] {
            let spec = parse_endpoint(value).unwrap();
            assert!(!spec.is_static());
            assert_eq!(
                spec,
                EndpointSpec::Interface {
                    name: name.into(),
                    port: port.into()
                }
            );
        }
        for value in [
            "2222",
            ":",
            "iface:eth0",
            "iface::2222",
            "iface:",
            "iface:e:t:h0:22",
            "iface:a/b:22",
            "iface:eth0:65536",
            "iface:eth0:-1",
            "iface:eth0:unknown-service",
            "[::1:22",
            "::1:22",
            "host:[22]",
        ] {
            assert!(parse_endpoint(value).is_err(), "{value}");
        }
        let mut cfg = server();
        assert!(cfg.ssh_endpoint().unwrap().is_static());
        assert!(cfg.http_endpoint().unwrap().is_none());
        cfg.http_listen = "iface:eth0:8080".into();
        assert!(matches!(
            cfg.http_endpoint().unwrap(),
            Some(EndpointSpec::Interface { .. })
        ));
    }

    #[test]
    fn yaml_scalar_and_null_rules() {
        let cfg: Server = decode(mapping("sshListen: null\nhttpListen: 123\nallowAnonymous: YES\nbuckets: {b: {path: 42, mode: null, versioned: ON, byHost: off, extension: null, validator: null}}\nauthorizedKeys: null")).unwrap();
        assert_eq!(cfg.ssh_listen, "");
        assert_eq!(cfg.http_listen, "123");
        assert!(cfg.allow_anonymous);
        assert!(cfg.buckets["b"].versioned);
        assert!(!cfg.buckets["b"].by_host);
        assert_eq!(cfg.buckets["b"].path, Path::new("42"));
        let cfg: Client = decode(mapping("endpoints: [{host: true, sshPort: 22.9, httpPort: null}]\ntrustedKeys: [123, null]\nidentities: null")).unwrap();
        assert_eq!(cfg.endpoints[0].host, "true");
        assert_eq!(cfg.endpoints[0].ssh_port, 22);
        assert_eq!(cfg.trusted_keys, ["123"]);
        assert!(decode::<Server>(mapping("allowAnonymous: 'true'")).is_err());
        let cfg: Client = decode(mapping(
            "endpoints: [null]\ntrustedKeys: [1.0, 1000000.0, 0.00001]\n",
        ))
        .unwrap();
        assert!(cfg.endpoints.is_empty());
        assert_eq!(cfg.trusted_keys, ["1", "1e+06", "1e-05"]);
        let cfg: Server = decode(mapping("buckets: {1: null}\nauthorizedKeys: [null]\n")).unwrap();
        assert!(cfg.buckets["1"].path.as_os_str().is_empty());
        assert!(cfg.authorized_keys.is_empty());
    }

    #[test]
    fn home_expansion_leaves_other_paths_alone() {
        assert_eq!(expand_user("/").unwrap(), Path::new("/"));
        assert_eq!(
            expand_user("~other/data").unwrap(),
            Path::new("~other/data")
        );
        let home = PathBuf::from(env::var_os("HOME").unwrap());
        assert_eq!(expand_user("~").unwrap(), home);
        assert_eq!(
            expand_user("~/buckets/data").unwrap(),
            home.join("buckets/data")
        );
    }

    #[test]
    fn yaml_file_errors_and_merge_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        for yaml in [
            "[not-a-map]",
            "sshListen: [",
            "sshListen: one\nsshListen: two",
        ] {
            fs::write(&path, yaml).unwrap();
            assert!(merge_file(&mut Mapping::new(), &path, Role::Server).is_err());
        }
        fs::write(
            &path,
            "buckets:\n  a: &base {path: /a, mode: ro}\n  b: {<<: *base, path: /b}\n",
        )
        .unwrap();
        let mut merged = Mapping::new();
        merge_file(&mut merged, &path, Role::Server).unwrap();
        let cfg: Server = decode(merged).unwrap();
        assert_eq!(cfg.buckets["b"].path, Path::new("/b"));
        assert_eq!(cfg.buckets["b"].mode, Mode::ReadOnly);
        fs::write(&path, "buckets:\n  a: &first {path: /first, mode: ro}\n  b: &second {path: /second, extension: yaml}\n  c: {<<: [*first, *second]}\n").unwrap();
        let mut merged = Mapping::new();
        merge_file(&mut merged, &path, Role::Server).unwrap();
        let cfg: Server = decode(merged).unwrap();
        assert_eq!(cfg.buckets["c"].path, Path::new("/first"));
        assert_eq!(cfg.buckets["c"].extension, "yaml");
        fs::write(&path, "sshListen: ':22'\n---\nignored: [invalid").unwrap();
        let mut merged = Mapping::new();
        merge_file(&mut merged, &path, Role::Server).unwrap();
        assert_eq!(decode::<Server>(merged).unwrap().ssh_listen, ":22");
    }
    #[test]
    fn yaml_files_preserve_go_scalar_resolution_and_null_slices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        for (port, expected) in [("026", 22), ("022", 18), ("08", 8), ("2_222", 2222)] {
            fs::write(&path, format!("endpoints: [null, {{host: !!binary ZXhhbXBsZQ==, sshPort: {port}}}]\ntrustedKeys: [null, key]\nidentities: [null, id]")).unwrap();
            let cfg: Client =
                decode(load_merged_from_roots(Role::Client, &[], Some(&path)).unwrap()).unwrap();
            cfg.validate().unwrap();
            assert_eq!(cfg.endpoints.len(), 1);
            assert_eq!(cfg.endpoints[0].host, "example");
            assert_eq!(cfg.endpoints[0].ssh_port, expected);
            assert_eq!(cfg.trusted_keys, ["key"]);
            assert_eq!(cfg.identities, ["id"]);
        }
        for port in ["++22", "+-22", "-+22", "--22"] {
            fs::write(
                &path,
                format!("endpoints: [{{host: example, sshPort: {port}}}]"),
            )
            .unwrap();
            let merged = load_merged_from_roots(Role::Client, &[], Some(&path)).unwrap();
            assert!(decode::<Client>(merged).is_err(), "{port}");
        }
        for (scalar, expected) in [
            ("010", "8"),
            ("'010'", "010"),
            ("! '010'", "010"),
            ("!!str 010", "010"),
            ("2001-12-14", "2001-12-14T00:00:00Z"),
            ("'2001-12-14'", "2001-12-14"),
            ("2001-1-2t3:4:5.120+01:30", "2001-01-02T03:04:05.12+01:30"),
            ("2001-1-2 3:4:5.123456789", "2001-01-02T03:04:05.123456789Z"),
            ("2001-01-01T01:02:03+01:60", "2001-01-01T01:02:03+02:00"),
            ("2001-01-01T01:02:03+0100", "2001-01-01T01:02:03+0100"),
            ("2001- 1-2", "2001- 1-2"),
            (".1__2", ".1__2"),
            ("+0x8000000000000000", "+0x8000000000000000"),
            ("!!binary L2RhdGE=", "/data"),
        ] {
            let cfg: Server =
                decode(mapping(&format!("buckets: {{b: {{path: {scalar}}}}}"))).unwrap();
            assert_eq!(cfg.buckets["b"].path, Path::new(expected), "{scalar}");
        }
        assert!(decode::<Client>(mapping("endpoints: [{sshPort: '026'}]")).is_err());
        assert!(decode::<Server>(mapping("allowAnonymous: tRuE")).is_err());
        assert!(decode::<Server>(mapping("buckets: {'<<': {path: /data}}")).is_err());
        let cfg: Client =
            decode(mapping("endpoints: [{'<<': {host: example, sshPort: 22}}]")).unwrap();
        assert_eq!(cfg.endpoints[0].host, "example");
        assert_eq!(cfg.endpoints[0].ssh_port, 22);
        assert!(decode::<Client>(mapping("endpoints: [{'<<': 1}]")).is_err());
        let cfg: Client = decode(mapping(
            "endpoints: [{host: good, '<<': {host: {'<<': 1}}}]",
        ))
        .unwrap();
        assert_eq!(cfg.endpoints[0].host, "good");
        let cfg: Client = decode(mapping(
            "endpoints: [{<<: {<<: {host: example}, sshPort: 22}}]",
        ))
        .unwrap();
        assert_eq!(cfg.endpoints[0].host, "example");
        assert_eq!(cfg.endpoints[0].ssh_port, 22);
        let cfg: Server = decode(mapping(
            "authorizedKeys: [null, {host: example, keys: [null, key]}]",
        ))
        .unwrap();
        assert_eq!(cfg.authorized_keys.len(), 1);
        assert_eq!(cfg.authorized_keys[0].keys, ["key"]);
    }

    #[test]
    fn key_tags_determine_whether_configuration_maps_recurse() {
        for (key, name) in [
            ("2024-01-01", "2024-01-01T00:00:00Z"),
            ("!!timestamp 2024-01-01", "2024-01-01T00:00:00Z"),
            ("!!binary YQ==", "a"),
            ("!custom a", "a"),
            ("02", "2"),
        ] {
            let tagged = format!("buckets: {{{key}: {{path: /a}}}}");
            let strings = "buckets: {other: {path: /b}}";
            for (first, second, expected) in [
                (tagged.as_str(), strings, "other"),
                (strings, tagged.as_str(), name),
            ] {
                let mut merged = mapping(first);
                merge_map(&mut merged, mapping(second));
                let cfg: Server = decode(merged).unwrap();
                assert_eq!(cfg.buckets.len(), 1, "{first} then {second}");
                assert!(cfg.buckets.contains_key(expected), "{expected}");
            }
        }
        for key in ["'2024-01-01'", "!!str 2024-01-01"] {
            let mut merged = mapping(&format!("buckets: {{{key}: {{path: /a}}}}"));
            merge_map(&mut merged, mapping("buckets: {other: {path: /b}}"));
            let cfg: Server = decode(merged).unwrap();
            assert_eq!(cfg.buckets.len(), 2);
            assert_eq!(cfg.buckets["2024-01-01"].path, Path::new("/a"));
        }
    }

    #[test]
    fn merged_keys_use_the_receiving_maps_key_type() {
        for (key, name) in [
            ("02", "02"),
            ("TRUE", "TRUE"),
            ("2024-01-01", "2024-01-01"),
            ("!!binary YQ==", "a"),
            ("!custom a", "a"),
        ] {
            for source in [
                format!("{{{key}: {{path: /a}}}}"),
                format!("{{<<: {{{key}: {{path: /a}}}}}}"),
                format!("[{{{key}: {{path: /a}}}}, {{{key}: {{path: /ignored}}}}]"),
            ] {
                let mut merged =
                    mapping(&format!("buckets: {{base: {{path: /base}}, <<: {source}}}"));
                merge_map(
                    &mut merged,
                    mapping(&format!(
                        "buckets: {{'{name}': {{mode: rw}}, other: {{path: /b}}}}"
                    )),
                );
                let cfg: Server = decode(merged).unwrap();
                assert_eq!(cfg.buckets.len(), 3, "{source}");
                assert_eq!(cfg.buckets[name].path, Path::new("/a"), "{source}");
                assert!(cfg.buckets[name].writable());
            }
        }
        let cfg: Server = decode(mapping(
            "buckets: {base: {path: /base}, <<: {null: {path: /ignored}}}",
        ))
        .unwrap();
        assert_eq!(cfg.buckets.len(), 1);
        let cfg: Server =
            decode(mapping("buckets: {02: {path: /a}, <<: {TRUE: {path: /b}}}")).unwrap();
        assert_eq!(cfg.buckets["2"].path, Path::new("/a"));
        assert_eq!(cfg.buckets["true"].path, Path::new("/b"));
        for source in ["{02: {path: /a}}", "[{02: {path: /a}}]"] {
            let cfg: Server = decode(mapping(&format!("buckets: {{'<<': {source}}}"))).unwrap();
            assert_eq!(cfg.buckets["2"].path, Path::new("/a"));
        }
        let cfg: Server = decode(mapping(
            "buckets: {'02': {path: /a}, <<: {02: !!int invalid}}",
        ))
        .unwrap();
        assert_eq!(cfg.buckets["02"].path, Path::new("/a"));
    }

    #[test]
    fn key_aliases_preserve_map_types_and_merge_destinations() {
        for (tag, count) in [("!!str", 2), ("!!timestamp", 1)] {
            let mut merged = mapping(&format!(
                "key: &key {tag} 2024-01-01\nsource: &source {{*key : value}}\ntarget: {{<<: *source}}"
            ));
            merge_map(
                &mut merged,
                mapping("source: {other: value}\ntarget: {other: value}"),
            );
            assert_eq!(merged["source"].as_mapping().unwrap().len(), count);
            assert_eq!(merged["target"].as_mapping().unwrap().len(), 2);
            assert_eq!(merged["target"]["2024-01-01"].as_str(), Some("value"));
        }
    }

    #[test]
    fn numeric_bucket_keys_replace_layers_and_dotfiles_are_loaded() {
        for (first, second, expected) in [
            (
                "buckets: {first: {path: /first}}",
                "buckets: {2024: {path: /next}}",
                "2024",
            ),
            (
                "buckets: {2024: {path: /first}}",
                "buckets: {next: {path: /next}}",
                "next",
            ),
        ] {
            let mut merged = mapping(first);
            merge_map(&mut merged, mapping(second));
            let cfg: Server = decode(merged).unwrap();
            assert_eq!(cfg.buckets.len(), 1);
            assert_eq!(cfg.buckets[expected].path, Path::new("/next"));
        }
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("config.d")).unwrap();
        for (name, port) in [(".yaml", 22), (".yml", 23)] {
            fs::write(
                dir.path().join("config.d").join(name),
                format!("sshListen: ':{port}'"),
            )
            .unwrap();
        }
        assert_eq!(layer_files(dir.path()).len(), 2);
        let cfg: Server =
            decode(load_merged_from_roots(Role::Server, &[dir.path().into()], None).unwrap())
                .unwrap();
        assert_eq!(cfg.ssh_listen, ":23");
    }
    #[test]
    #[cfg(unix)]
    fn binary_yaml_paths_preserve_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;
        let cfg: Server = decode(mapping("buckets: {b: {path: !!binary /w==}}")).unwrap();
        assert_eq!(cfg.buckets["b"].path.as_os_str().as_bytes(), &[0xff]);
    }
}
