use std::{io, sync::Arc};

use crate::{Result, config, store};
use russh_sftp::protocol::{File, FileAttributes};

#[derive(Clone)]
pub(super) struct View {
    pub config: Arc<config::Server>,
    pub host: Option<String>,
}

pub(super) enum Resolved<'a> {
    Root,
    Internal,
    Bucket {
        name: &'a str,
        bucket: &'a config::Bucket,
        sub: String,
        meta: bool,
        push: bool,
    },
}

pub(super) fn clean(path: &str) -> String {
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => (),
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    format!("/{}", parts.join("/"))
}

pub(super) fn denied() -> anyhow::Error {
    io::Error::from(io::ErrorKind::PermissionDenied).into()
}

pub(super) fn missing() -> anyhow::Error {
    io::Error::from(io::ErrorKind::NotFound).into()
}

pub(super) fn invalid() -> anyhow::Error {
    io::Error::from(io::ErrorKind::InvalidInput).into()
}

pub(super) fn virtual_file(name: &str, size: u64, mode: u32) -> File {
    File::new(
        name,
        FileAttributes {
            size: Some(size),
            uid: Some(0),
            gid: Some(0),
            permissions: Some(mode),
            atime: Some(0),
            mtime: Some(0),
            ..Default::default()
        },
    )
}

pub(super) fn attributes(metadata: &std::fs::Metadata) -> FileAttributes {
    use std::os::unix::fs::MetadataExt;
    FileAttributes {
        size: Some(metadata.len()),
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        permissions: Some(metadata.mode()),
        atime: Some(metadata.atime() as u32),
        mtime: Some(metadata.mtime() as u32),
        ..Default::default()
    }
}

impl View {
    pub fn resolve(&self, path: &str) -> Result<Resolved<'_>> {
        let path = clean(path);
        let mut parts: Vec<_> = path.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Ok(Resolved::Root);
        }
        if parts[0] == config::NAME_PDS {
            if parts.len() == 1 {
                return Ok(Resolved::Internal);
            }
            if parts[1] != config::NAME_EXEC || self.config.exec_bucket.is_empty() {
                return Err(missing());
            }
            parts.remove(0);
            parts[0] = &self.config.exec_bucket;
        }
        let (name, bucket) = self
            .config
            .buckets
            .get_key_value(parts[0])
            .ok_or_else(missing)?;
        let rest = &mut parts[1..];
        let meta = rest == [config::NAME_META];
        let push = rest == [config::NAME_PUSH];
        if rest.first() == Some(&config::NAME_SELF) {
            let host = self.host.as_deref().filter(|h| !h.is_empty());
            if !bucket.by_host || host.is_none() {
                return Err(missing());
            }
            rest[0] = host.unwrap();
        }
        Ok(Resolved::Bucket {
            name,
            bucket,
            sub: rest.join("/"),
            meta,
            push,
        })
    }

    pub fn list(&self, path: &str) -> Result<Vec<File>> {
        match self.resolve(path)? {
            Resolved::Root => {
                let mut files: Vec<_> = self
                    .config
                    .buckets
                    .keys()
                    .map(|name| virtual_file(name, 0, 0o40555))
                    .collect();
                files.push(virtual_file(config::NAME_PDS, 0, 0o40555));
                Ok(files)
            }
            Resolved::Internal => Ok(if self.config.exec_bucket.is_empty() {
                vec![]
            } else {
                vec![virtual_file(config::NAME_EXEC, 0, 0o40555)]
            }),
            Resolved::Bucket {
                bucket,
                sub,
                meta,
                push,
                ..
            } => {
                if meta || push {
                    return Err(invalid());
                }
                let mut files: Vec<_> = store::list(bucket, &sub)?
                    .into_iter()
                    .map(|entry| {
                        File::new(entry.name.to_string_lossy(), attributes(&entry.metadata))
                    })
                    .collect();
                if sub.is_empty() {
                    files.push(virtual_file(
                        config::NAME_META,
                        store::meta(bucket)?.len() as u64,
                        0o100444,
                    ));
                    if bucket.by_host && self.host.as_deref().is_some_and(|h| !h.is_empty()) {
                        files.push(virtual_file(config::NAME_SELF, 0, 0o40555));
                    }
                }
                Ok(files)
            }
        }
    }

    pub fn stat(&self, path: &str) -> Result<FileAttributes> {
        match self.resolve(path)? {
            Resolved::Root | Resolved::Internal => Ok(virtual_file("", 0, 0o40555).attrs),
            Resolved::Bucket {
                name,
                bucket,
                sub,
                meta,
                push,
            } => {
                if meta {
                    return Ok(virtual_file(
                        config::NAME_META,
                        store::meta(bucket)?.len() as u64,
                        0o100444,
                    )
                    .attrs);
                }
                if push {
                    return Ok(virtual_file(config::NAME_PUSH, 0, 0o100200).attrs);
                }
                match store::stat(bucket, &sub) {
                    Ok(metadata) => Ok(attributes(&metadata)),
                    Err(_) if sub.is_empty() => Ok(virtual_file(name, 0, 0o40555).attrs),
                    Err(error) => Err(error),
                }
            }
        }
    }
}
