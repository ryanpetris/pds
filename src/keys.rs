use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
pub use russh::keys::{Algorithm, Certificate, PrivateKey, PublicKey};
use russh::keys::{PublicKeyBase64, decode_secret_key};

use crate::config::ClientEntry;

pub type TrustedSet = HashSet<Vec<u8>>;
pub type ClientHostMap = HashMap<Vec<u8>, String>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthIdentity {
    Anonymous,
    Host(String),
}

#[derive(Clone, Debug)]
pub enum AuthorizedKey {
    Public(PublicKey),
    Certificate(Box<Certificate>),
}

impl AuthorizedKey {
    fn ed25519(&self) -> Option<&PublicKey> {
        match self {
            Self::Public(key) if key.algorithm() == Algorithm::Ed25519 => Some(key),
            _ => None,
        }
    }

    fn algorithm(&self) -> String {
        match self {
            Self::Public(key) => key.algorithm().to_string(),
            Self::Certificate(key) => key.algorithm().to_certificate_type(),
        }
    }
}

pub fn parse_authorized_key(input: &str) -> Result<AuthorizedKey> {
    for line in input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let Some((first, rest)) = take_field(line) else {
            continue;
        };
        let mut candidates = vec![(first, rest)];
        if let Some((kind, rest)) = take_field(rest) {
            candidates.push((kind, rest));
        }
        for (kind, rest) in candidates {
            let Some((encoded, _)) = take_field(rest) else {
                continue;
            };
            if let Ok(cert) = Certificate::from_openssh(&format!("{kind} {encoded}")) {
                return Ok(AuthorizedKey::Certificate(Box::new(cert)));
            }
            if let Ok(key) = russh::keys::parse_public_key_base64(encoded)
                && !matches!(key.algorithm(), Algorithm::Other(_))
            {
                return Ok(AuthorizedKey::Public(key));
            }
        }
    }
    bail!("no key found")
}

fn take_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start_matches([' ', '\t']);
    if input.is_empty() {
        return None;
    }
    let mut quoted = false;
    let mut escaped = false;
    for (i, ch) in input.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => return Some((&input[..i], &input[i..])),
            _ => {}
        }
    }
    (!quoted).then_some((input, ""))
}

pub fn parse_public_key(line: &str) -> Result<PublicKey> {
    match parse_authorized_key(line)? {
        AuthorizedKey::Public(key) => Ok(key),
        AuthorizedKey::Certificate(_) => bail!("expected a public key, got a certificate"),
    }
}

pub fn trusted_set(lines: &[String]) -> Result<TrustedSet> {
    let mut set = TrustedSet::new();
    for line in lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
    {
        let parsed = parse_authorized_key(line).with_context(|| format!("trusted key {line:?}"))?;
        let key = parsed.ed25519().with_context(|| {
            format!(
                "trusted key {line:?}: only ed25519 host keys are supported, got {}",
                parsed.algorithm()
            )
        })?;
        set.insert(key.public_key_bytes());
    }
    if set.is_empty() {
        bail!("no usable trusted keys");
    }
    Ok(set)
}

pub fn trusted(set: &TrustedSet, key: &PublicKey) -> bool {
    set.contains(&key.public_key_bytes())
}

pub fn client_host_map(entries: &[ClientEntry]) -> Result<(ClientHostMap, Vec<String>)> {
    let mut map = ClientHostMap::new();
    let mut warnings = Vec::new();
    for entry in entries {
        for line in entry
            .keys
            .iter()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
        {
            let parsed = parse_authorized_key(line)
                .with_context(|| format!("authorizedKeys host {:?} key {line:?}", entry.host))?;
            if let Some(key) = parsed.ed25519() {
                map.insert(key.public_key_bytes(), entry.host.clone());
            } else {
                warnings.push(format!(
                    "authorizedKeys host {:?}: ignoring non-ed25519 key ({})",
                    entry.host,
                    parsed.algorithm()
                ));
            }
        }
    }
    Ok((map, warnings))
}

pub fn host_for<'a>(map: &'a ClientHostMap, key: &PublicKey) -> Option<&'a str> {
    map.get(&key.public_key_bytes()).map(String::as_str)
}

pub fn load_signers(dir: impl AsRef<Path>) -> Result<(Vec<PrivateKey>, Vec<String>)> {
    let mut matches: Vec<_> = match fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with("id_") && !name.ends_with(".pub")
            })
            .map(|entry| entry.path())
            .collect(),
        Err(_) => return Ok((Vec::new(), Vec::new())),
    };
    matches.sort();
    let mut signers = Vec::new();
    let mut skipped = Vec::new();
    for path in matches {
        let result = fs::read_to_string(&path)
            .context("reading private key")
            .and_then(|data| {
                if !data.contains("-----BEGIN ") {
                    bail!("unsupported private key format");
                }
                let key = decode_secret_key(&data, None)?;
                if key.is_encrypted() {
                    bail!("private key is passphrase protected");
                }
                Ok(key)
            });
        match result {
            Ok(key) => signers.push(key),
            Err(error) => skipped.push(format!("{}: {error:#}", path.display())),
        }
    }
    Ok((signers, skipped))
}

pub fn default_ssh_dir() -> PathBuf {
    PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".ssh")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(algorithm: Algorithm) -> PrivateKey {
        PrivateKey::random(&mut rand::rng(), algorithm).unwrap()
    }

    #[test]
    fn trusted_keys_only_accept_ed25519() {
        let ed = key(Algorithm::Ed25519).public_key().to_openssh().unwrap();
        let ec = key(Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        })
        .public_key()
        .to_openssh()
        .unwrap();
        let set = trusted_set(&[ed.clone(), "".into(), "  ".into()]).unwrap();
        assert!(trusted(&set, &parse_public_key(&ed).unwrap()));
        for lines in [
            vec![],
            vec!["  ".into()],
            vec!["not-a-key".into()],
            vec![ec.clone()],
            vec![ed, ec],
        ] {
            assert!(trusted_set(&lines).is_err());
        }
    }

    #[test]
    fn authorized_keys_warn_and_last_host_wins() {
        let ed = key(Algorithm::Ed25519).public_key().to_openssh().unwrap();
        let ec = key(Algorithm::Ecdsa {
            curve: russh::keys::EcdsaCurve::NistP256,
        })
        .public_key()
        .to_openssh()
        .unwrap();
        let (map, warnings) = client_host_map(&[
            ClientEntry {
                host: "first".into(),
                keys: vec![ed.clone(), ec.clone(), " ".into()],
            },
            ClientEntry {
                host: "second".into(),
                keys: vec![ed.clone()],
            },
        ])
        .unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(
            host_for(&map, &parse_public_key(&ed).unwrap()),
            Some("second")
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("first"));
        let (map, warnings) = client_host_map(&[ClientEntry {
            host: "host".into(),
            keys: vec![ec],
        }])
        .unwrap();
        assert!(map.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(
            client_host_map(&[ClientEntry {
                host: "host".into(),
                keys: vec!["garbage".into()]
            }])
            .is_err()
        );
    }

    #[test]
    fn authorized_key_options_comments_and_whitespace() {
        let ed = key(Algorithm::Ed25519).public_key().to_openssh().unwrap();
        let expected = parse_public_key(&ed).unwrap().public_key_bytes();
        for line in [
            format!("# comment\n{ed} comment words"),
            format!("command=\"echo hello\",no-pty\t{ed}"),
            format!("\t{ed}\tcomment"),
        ] {
            assert_eq!(
                parse_public_key(&line).unwrap().public_key_bytes(),
                expected
            );
        }
    }

    #[test]
    fn signer_discovery_is_sorted_and_skips_bad_keys() {
        let dir = tempfile::tempdir().unwrap();
        let ed = key(Algorithm::Ed25519);
        fs::write(
            dir.path().join("id_b"),
            ed.to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        fs::write(dir.path().join("id_a"), b"broken").unwrap();
        fs::write(dir.path().join("id_b.pub"), b"ignored").unwrap();
        fs::create_dir(dir.path().join("id_directory")).unwrap();
        fs::write(dir.path().join("other"), b"ignored").unwrap();
        let (signers, skipped) = load_signers(dir.path()).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].public_key(), ed.public_key());
        assert_eq!(skipped.len(), 2);
        assert!(skipped[0].contains("id_a"));
        assert!(
            load_signers(dir.path().join("missing"))
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn certificates_are_rejected_for_pinning_and_warned_for_authentication() {
        use russh::keys::ssh_key::certificate::Builder;
        let ca = key(Algorithm::Ed25519);
        let host = key(Algorithm::Ed25519);
        let mut builder = Builder::new(
            vec![1; 32],
            host.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .unwrap();
        builder.all_principals_valid().unwrap();
        let cert = builder.sign(&ca).unwrap().to_openssh().unwrap();
        assert!(matches!(
            parse_authorized_key(&cert).unwrap(),
            AuthorizedKey::Certificate(_)
        ));
        assert!(trusted_set(std::slice::from_ref(&cert)).is_err());
        let (map, warnings) = client_host_map(&[ClientEntry {
            host: "host".into(),
            keys: vec![cert],
        }])
        .unwrap();
        assert!(map.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("-cert-v01@openssh.com"));
    }

    #[test]
    fn encrypted_keys_are_skipped_and_pkcs8_keys_load() {
        let dir = tempfile::tempdir().unwrap();
        let private = key(Algorithm::Ed25519);
        let encrypted = private.encrypt(&mut rand::rng(), "secret").unwrap();
        fs::write(
            dir.path().join("id_encrypted"),
            encrypted
                .to_openssh(russh::keys::ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        let mut pkcs8 = Vec::new();
        russh::keys::encode_pkcs8_pem(&private, &mut pkcs8).unwrap();
        fs::write(dir.path().join("id_pkcs8"), pkcs8).unwrap();
        let (signers, skipped) = load_signers(dir.path()).unwrap();
        assert_eq!(signers.len(), 1);
        assert_eq!(signers[0].public_key(), private.public_key());
        assert_eq!(skipped.len(), 1);
        assert!(skipped[0].contains("id_encrypted"));
    }

    #[test]
    fn rsa_keys_are_rejected_for_pinning_and_ignored_for_authentication() {
        let rsa =
            russh::keys::ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048).unwrap();
        let private = PrivateKey::new(rsa.into(), "").unwrap();
        let line = private.public_key().to_openssh().unwrap();
        assert!(trusted_set(std::slice::from_ref(&line)).is_err());
        let (map, warnings) = client_host_map(&[ClientEntry {
            host: "host".into(),
            keys: vec![line],
        }])
        .unwrap();
        assert!(map.is_empty());
        assert_eq!(warnings.len(), 1);
    }
}
