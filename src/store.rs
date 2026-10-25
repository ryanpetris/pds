use std::ffi::OsString;
use std::fs::{self, File, Metadata};
use std::io::{self, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use tempfile::NamedTempFile;

use crate::config::{Bucket, Mode};

pub const MAX_PUSH: u64 = 5 << 20;

pub fn safe_segment(segment: &str) -> Result<&str> {
    ensure!(
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && !segment.contains(['/', '\\', '\0']),
        "not a valid path segment"
    );
    Ok(segment)
}

pub fn safe_resolve(base: impl AsRef<Path>, sub: &str) -> Result<PathBuf> {
    let mut clean = PathBuf::new();
    for component in Path::new(sub).components() {
        match component {
            Component::Normal(name) => clean.push(name),
            Component::ParentDir => {
                clean.pop();
            }
            _ => {}
        }
    }
    Ok(if clean.as_os_str().is_empty() {
        base.as_ref().to_path_buf()
    } else {
        base.as_ref().join(clean)
    })
}

pub fn open(bucket: &Bucket, sub: &str) -> Result<File> {
    Ok(File::open(safe_resolve(&bucket.path, sub)?)?)
}

pub fn stat(bucket: &Bucket, sub: &str) -> Result<Metadata> {
    Ok(fs::metadata(safe_resolve(&bucket.path, sub)?)?)
}

#[derive(Debug)]
pub struct FileInfo {
    pub name: OsString,
    pub metadata: Metadata,
}

pub fn list(bucket: &Bucket, sub: &str) -> Result<Vec<FileInfo>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(safe_resolve(&bucket.path, sub)?)? {
        let entry = entry?;
        if let Ok(metadata) = fs::symlink_metadata(entry.path()) {
            entries.push(FileInfo {
                name: entry.file_name(),
                metadata,
            });
        }
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

pub fn meta(bucket: &Bucket) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Meta<'a> {
        mode: Mode,
        versioned: bool,
        by_host: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        extension: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        validator: Option<&'a str>,
    }
    Ok(serde_yaml_ng::to_string(&Meta {
        mode: bucket.mode,
        versioned: bucket.versioned,
        by_host: bucket.by_host,
        extension: bucket.writable().then_some(bucket.extension.as_str()),
        validator: bucket.writable().then_some(bucket.validator.as_str()),
    })?
    .into_bytes())
}

#[derive(Debug, Default)]
pub struct Committer {
    // Validation and placement share a lock to bound validation memory and avoid
    // timestamp collisions. Upload streaming does not hold this lock.
    lock: Mutex<()>,
}

impl Committer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn commit(&self, mut pusher: Pusher) -> Result<String> {
        if let Some(error) = pusher.error.take() {
            bail!(error);
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| anyhow::anyhow!("commit lock poisoned"))?;
        pusher.temp.as_file().sync_all()?;
        pusher.temp.as_file_mut().seek(SeekFrom::Start(0))?;
        pusher
            .bucket
            .validator
            .validate(pusher.temp.as_file_mut())?;
        let dir = pusher
            .temp
            .path()
            .parent()
            .context("upload has no parent directory")?
            .to_owned();
        let latest = format!("latest.{}", pusher.bucket.extension);
        let name = if pusher.bucket.versioned {
            unique_name(
                &dir,
                &pusher.bucket.extension,
                &chrono::Utc::now().format("%Y%m%d%H%M%S").to_string(),
            )?
        } else {
            latest.clone()
        };
        pusher
            .temp
            .persist(dir.join(&name))
            .map_err(|error| error.error)?;
        if pusher.bucket.versioned {
            atomic_symlink(&dir, &name, &latest)?;
        }
        Ok(name)
    }
}

#[derive(Debug)]
pub struct Pusher {
    bucket: Bucket,
    temp: NamedTempFile,
    size: u64,
    error: Option<String>,
}

impl Pusher {
    pub fn new(bucket: &Bucket, host: &str) -> Result<Self> {
        ensure!(bucket.writable(), "bucket is read-only");
        let dir = if bucket.by_host {
            bucket
                .path
                .join(safe_segment(host).with_context(|| format!("invalid host {host:?}"))?)
        } else {
            bucket.path.clone()
        };
        fs::create_dir_all(&dir)?;
        let mut builder = tempfile::Builder::new();
        builder.prefix(".tmp-");
        #[cfg(unix)]
        builder.permissions(fs::Permissions::from_mode(0o666));
        Ok(Self {
            bucket: bucket.clone(),
            temp: builder.tempfile_in(dir)?,
            size: 0,
            error: None,
        })
    }

    pub fn write_at(&mut self, data: &[u8], offset: i64) -> Result<usize> {
        let result = (|| {
            let offset = u64::try_from(offset).context("negative write offset")?;
            let end = offset
                .checked_add(data.len() as u64)
                .context("write offset overflow")?;
            ensure!(end <= MAX_PUSH, "upload exceeds {MAX_PUSH} bytes");
            self.temp.as_file_mut().seek(SeekFrom::Start(offset))?;
            self.temp.as_file_mut().write_all(data)?;
            self.size = self.size.max(end);
            Ok(data.len())
        })();
        if let Err(ref error) = result {
            self.error = Some(format!("{error:#}"));
        }
        result
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn finish(self, committer: &Committer) -> Result<String> {
        committer.commit(self)
    }

    pub fn abort(self) {}
}

fn unique_name(dir: &Path, extension: &str, stamp: &str) -> Result<String> {
    for i in 0..1000 {
        let name = if i == 0 {
            format!("{stamp}.{extension}")
        } else {
            format!("{stamp}-{i}.{extension}")
        };
        match fs::symlink_metadata(dir.join(&name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(name),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
    }
    bail!("could not allocate a unique name")
}

fn atomic_symlink(dir: &Path, target: &str, dest: &str) -> Result<()> {
    let temp = tempfile::Builder::new()
        .prefix(".latest-tmp-")
        .tempfile_in(dir)?
        .into_temp_path();
    fs::remove_file(&temp)?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, &temp)?;
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(target, &temp)?;
    fs::rename(&temp, dir.join(dest))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::Validator;
    use std::io::Read;
    use std::sync::Arc;

    fn bucket(path: &Path) -> Bucket {
        Bucket {
            path: path.into(),
            mode: Mode::ReadWrite,
            extension: "yaml".into(),
            validator: Validator::Yaml,
            ..Bucket::default()
        }
    }

    fn commit(committer: &Committer, bucket: &Bucket, host: &str, data: &[u8]) -> Result<String> {
        let mut pusher = Pusher::new(bucket, host)?;
        pusher.write_at(data, 0)?;
        pusher.finish(committer)
    }

    fn contents(bucket: &Bucket, path: &str) -> Vec<u8> {
        let mut data = Vec::new();
        open(bucket, path).unwrap().read_to_end(&mut data).unwrap();
        data
    }

    #[test]
    fn versioned_by_host_preserves_bytes_and_latest_link() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = Bucket {
            versioned: true,
            by_host: true,
            ..bucket(dir.path())
        };
        let committer = Committer::new();
        let data = b"a: 1\r\n# untouched formatting\r\n";
        let name = commit(&committer, &bucket, "web01", data).unwrap();
        assert!(name.ends_with(".yaml"));
        assert!(name[..14].bytes().all(|byte| byte.is_ascii_digit()));
        assert_eq!(
            fs::read_link(dir.path().join("web01/latest.yaml")).unwrap(),
            Path::new(&name)
        );
        assert_eq!(contents(&bucket, "web01/latest.yaml"), data);
        assert_eq!(
            stat(&bucket, "web01/latest.yaml").unwrap().len(),
            data.len() as u64
        );
        assert!(commit(&committer, &bucket, "web01", b"foo: [bar").is_err());
        assert_eq!(contents(&bucket, "web01/latest.yaml"), data);
        assert_eq!(fs::read_dir(dir.path().join("web01")).unwrap().count(), 2);
    }

    #[test]
    fn latest_only_overwrites_and_validates_before_placement() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = Bucket {
            extension: "json".into(),
            validator: Validator::Json,
            ..bucket(dir.path())
        };
        let committer = Committer::new();
        assert_eq!(
            commit(&committer, &bucket, "ignored", b"{\"v\":1}").unwrap(),
            "latest.json"
        );
        commit(&committer, &bucket, "ignored", b"{\"v\":2}").unwrap();
        assert_eq!(contents(&bucket, "latest.json"), b"{\"v\":2}");
        assert!(commit(&committer, &bucket, "ignored", b"invalid").is_err());
        assert_eq!(contents(&bucket, "latest.json"), b"{\"v\":2}");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(
            !fs::symlink_metadata(dir.path().join("latest.json"))
                .unwrap()
                .is_symlink()
        );
    }

    #[test]
    fn out_of_order_chunks_and_sparse_uploads() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = Bucket {
            extension: "bin".into(),
            validator: Validator::None,
            ..bucket(dir.path())
        };
        let committer = Committer::new();
        let mut pusher = Pusher::new(&bucket, "").unwrap();
        pusher.write_at(b"world", 6).unwrap();
        pusher.write_at(b"hello ", 0).unwrap();
        assert_eq!(pusher.size(), 11);
        pusher.finish(&committer).unwrap();
        assert_eq!(contents(&bucket, "latest.bin"), b"hello world");
        let mut pusher = Pusher::new(&bucket, "").unwrap();
        pusher.write_at(b"\xff", 2).unwrap();
        pusher.finish(&committer).unwrap();
        assert_eq!(contents(&bucket, "latest.bin"), b"\0\0\xff");
    }

    #[test]
    fn bad_offsets_are_sticky_and_temporary_files_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = Bucket {
            extension: "bin".into(),
            validator: Validator::None,
            ..bucket(dir.path())
        };
        for offset in [-1, MAX_PUSH as i64, i64::MAX] {
            let mut pusher = Pusher::new(&bucket, "").unwrap();
            assert!(pusher.write_at(b"x", offset).is_err());
            pusher.write_at(b"okay", 0).unwrap();
            assert!(pusher.finish(&Committer::new()).is_err());
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        }
        let mut pusher = Pusher::new(&bucket, "").unwrap();
        pusher.write_at(b"x", MAX_PUSH as i64 - 1).unwrap();
        pusher.finish(&Committer::new()).unwrap();
        assert_eq!(stat(&bucket, "latest.bin").unwrap().len(), MAX_PUSH);
        fs::remove_file(dir.path().join("latest.bin")).unwrap();
        drop(Pusher::new(&bucket, "").unwrap());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        Pusher::new(&bucket, "").unwrap().abort();
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn shared_committer_serializes_concurrent_versions() {
        let dir = tempfile::tempdir().unwrap();
        let bucket = Arc::new(Bucket {
            versioned: true,
            by_host: true,
            ..bucket(dir.path())
        });
        let committer = Arc::new(Committer::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let bucket = Arc::clone(&bucket);
                let committer = Arc::clone(&committer);
                std::thread::spawn(move || commit(&committer, &bucket, "web01", b"a: 1\n").unwrap())
            })
            .collect();
        let names: std::collections::HashSet<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(names.len(), 8);
        assert_eq!(fs::read_dir(dir.path().join("web01")).unwrap().count(), 9);
    }

    #[test]
    fn read_only_and_unsafe_host_names_fail() {
        let dir = tempfile::tempdir().unwrap();
        let read_only = Bucket {
            path: dir.path().into(),
            ..Bucket::default()
        };
        assert!(Pusher::new(&read_only, "host").is_err());
        let bucket = Bucket {
            by_host: true,
            ..bucket(dir.path())
        };
        for host in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(Pusher::new(&bucket, host).is_err(), "{host:?}");
        }
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn operator_symlinks_work_for_reads_and_by_host_writes() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let bucket = Bucket {
            by_host: true,
            ..bucket(dir.path())
        };
        fs::write(outside.path().join("secret"), b"secret").unwrap();
        symlink(outside.path(), dir.path().join("evil")).unwrap();
        assert_eq!(contents(&bucket, "evil/secret"), b"secret");
        assert_eq!(stat(&bucket, "evil/secret").unwrap().len(), 6);
        assert_eq!(list(&bucket, "evil").unwrap().len(), 1);
        commit(&Committer::new(), &bucket, "evil", b"a: 1\n").unwrap();
        assert_eq!(
            fs::read(outside.path().join("latest.yaml")).unwrap(),
            b"a: 1\n"
        );
        let full = safe_resolve(dir.path(), "../etc/passwd").unwrap();
        assert_eq!(full, dir.path().join("etc/passwd"));
        fs::create_dir(dir.path().join("real")).unwrap();
        fs::write(dir.path().join("real/file"), b"inside").unwrap();
        symlink(dir.path().join("real"), dir.path().join("absolute")).unwrap();
        assert_eq!(contents(&bucket, "absolute/file"), b"inside");
        commit(&Committer::new(), &bucket, "absolute", b"a: 1\n").unwrap();
        assert_eq!(contents(&bucket, "real/latest.yaml"), b"a: 1\n");
        symlink(
            outside.path().join("secret"),
            dir.path().join("real/latest.yaml.link"),
        )
        .unwrap();
        let entries = list(&bucket, "real").unwrap();
        assert!(
            entries
                .iter()
                .find(|entry| entry.name == "latest.yaml.link")
                .unwrap()
                .metadata
                .is_symlink()
        );
    }

    #[test]
    fn metadata_has_the_same_fields() {
        let bucket = Bucket {
            path: "/data".into(),
            mode: Mode::ReadWrite,
            versioned: true,
            by_host: true,
            extension: "yaml".into(),
            validator: Validator::Yaml,
        };
        let document: serde_yaml_ng::Value =
            serde_yaml_ng::from_slice(&meta(&bucket).unwrap()).unwrap();
        assert_eq!(document["mode"], "rw");
        assert_eq!(document["versioned"], true);
        assert_eq!(document["byHost"], true);
        assert_eq!(document["extension"], "yaml");
        assert_eq!(document["validator"], "yaml");
        assert_eq!(document.as_mapping().unwrap().len(), 5);
        let document: serde_yaml_ng::Value =
            serde_yaml_ng::from_slice(&meta(&Bucket::default()).unwrap()).unwrap();
        assert_eq!(document["mode"], "ro");
        assert!(document.get("extension").is_none());
        assert!(document.get("validator").is_none());
        assert_eq!(document.as_mapping().unwrap().len(), 3);
    }

    #[test]
    fn names_use_collision_suffixes_and_count_dangling_links() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("20060102150405.yaml"), b"existing").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("missing", dir.path().join("20060102150405-1.yaml")).unwrap();
        #[cfg(not(unix))]
        fs::write(dir.path().join("20060102150405-1.yaml"), b"existing").unwrap();
        assert_eq!(
            unique_name(dir.path(), "yaml", "20060102150405").unwrap(),
            "20060102150405-2.yaml"
        );
    }
}
