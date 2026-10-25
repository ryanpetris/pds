use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};

use russh_sftp::{
    protocol::*,
    server::{Handler, StatusReply},
};
use tokio::sync::oneshot;

use super::fs::{self, Resolved, View};
use crate::{Result, store};

enum Opened {
    File(File),
    Meta(Vec<u8>),
    Directory(std::vec::IntoIter<russh_sftp::protocol::File>),
    Upload(store::Pusher),
}

struct Entry {
    path: String,
    opened: Opened,
}

struct State {
    view: View,
    committer: Arc<store::Committer>,
    handles: HashMap<String, Entry>,
    next: u64,
    _done: oneshot::Sender<()>,
}

impl State {
    fn insert(&mut self, id: u32, path: String, opened: Opened) -> Handle {
        self.next += 1;
        let handle = self.next.to_string();
        self.handles.insert(handle.clone(), Entry { path, opened });
        Handle { id, handle }
    }
}

pub(super) struct Sftp {
    state: Option<State>,
}

impl Sftp {
    pub fn new(view: View, committer: Arc<store::Committer>) -> (Self, oneshot::Receiver<()>) {
        let (done, finished) = oneshot::channel();
        (
            Self {
                state: Some(State {
                    view,
                    committer,
                    handles: HashMap::new(),
                    next: 0,
                    _done: done,
                }),
            },
            finished,
        )
    }

    async fn blocking<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut State) -> Result<T> + Send + 'static,
    ) -> Result<T, StatusReply> {
        let mut state = self.state.take().expect("SFTP requests are serialized");
        let (state, result) = tokio::task::spawn_blocking(move || {
            let result = f(&mut state);
            (state, result)
        })
        .await
        .map_err(|e| StatusCode::Failure.with_message(e.to_string()))?;
        self.state = Some(state);
        result.map_err(status_error)
    }
}

impl Drop for Sftp {
    fn drop(&mut self) {
        // Pending uploads are discarded; only CLOSE publishes a validated file.
        let state = self.state.take();
        tokio::task::spawn_blocking(move || drop(state));
    }
}

fn status_error(error: anyhow::Error) -> StatusReply {
    let code = match error
        .downcast_ref::<std::io::Error>()
        .map(std::io::Error::kind)
    {
        Some(std::io::ErrorKind::NotFound) => StatusCode::NoSuchFile,
        Some(std::io::ErrorKind::PermissionDenied) => StatusCode::PermissionDenied,
        Some(std::io::ErrorKind::UnexpectedEof) => StatusCode::Eof,
        _ => StatusCode::Failure,
    };
    code.with_message(format!("{error:#}"))
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: String::new(),
        language_tag: String::new(),
    }
}

fn eof() -> anyhow::Error {
    std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into()
}

impl Handler for Sftp {
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::PermissionDenied.into()
    }

    async fn open(
        &mut self,
        id: u32,
        path: String,
        flags: OpenFlags,
        _: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        self.blocking(move |s| {
            let write = flags.intersects(
                OpenFlags::WRITE | OpenFlags::APPEND | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            );
            if write && s.view.host.is_none() {
                return Err(fs::denied());
            }
            let Resolved::Bucket {
                bucket,
                sub,
                meta,
                push,
                ..
            } = s.view.resolve(&path)?
            else {
                return Err(fs::invalid());
            };
            let opened = if write {
                if !push || !bucket.writable() {
                    return Err(fs::denied());
                }
                Opened::Upload(store::Pusher::new(bucket, s.view.host.as_deref().unwrap())?)
            } else if flags.contains(OpenFlags::READ) {
                if push {
                    return Err(fs::denied());
                }
                if meta {
                    Opened::Meta(store::meta(bucket)?)
                } else {
                    Opened::File(store::open(bucket, &sub)?)
                }
            } else {
                return Err(fs::invalid());
            };
            Ok(s.insert(id, path, opened))
        })
        .await
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.blocking(move |s| {
            let entry = s.handles.remove(&handle).ok_or_else(fs::invalid)?;
            if let Opened::Upload(pusher) = entry.opened {
                pusher.finish(&s.committer)?;
            }
            Ok(ok(id))
        })
        .await
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        self.blocking(move |s| {
            let entry = s.handles.get_mut(&handle).ok_or_else(fs::invalid)?;
            let mut data = vec![0; len.min(32768) as usize];
            let n = match &mut entry.opened {
                Opened::File(file) => {
                    file.seek(SeekFrom::Start(offset))?;
                    file.read(&mut data)?
                }
                Opened::Meta(bytes) => {
                    let offset = usize::try_from(offset).map_err(|_| eof())?;
                    let bytes = bytes.get(offset..).ok_or_else(eof)?;
                    let n = bytes.len().min(data.len());
                    data[..n].copy_from_slice(&bytes[..n]);
                    n
                }
                _ => return Err(fs::invalid()),
            };
            if n == 0 {
                return Err(eof());
            }
            data.truncate(n);
            Ok(Data { id, data })
        })
        .await
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        self.blocking(move |s| {
            let entry = s.handles.get_mut(&handle).ok_or_else(fs::invalid)?;
            let Opened::Upload(pusher) = &mut entry.opened else {
                return Err(fs::invalid());
            };
            // Passing an invalid signed offset records a sticky error in the pusher.
            pusher.write_at(&data, i64::try_from(offset).unwrap_or(-1))?;
            Ok(ok(id))
        })
        .await
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.blocking(move |s| {
            Ok(Attrs {
                id,
                attrs: s.view.stat(&path)?,
            })
        })
        .await
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        self.blocking(move |s| {
            let entry = s.handles.get(&handle).ok_or_else(fs::invalid)?;
            Ok(Attrs {
                id,
                attrs: s.view.stat(&entry.path)?,
            })
        })
        .await
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        self.blocking(move |s| {
            let entries = s.view.list(&path)?;
            Ok(s.insert(id, path, Opened::Directory(entries.into_iter())))
        })
        .await
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        self.blocking(move |s| {
            let entry = s.handles.get_mut(&handle).ok_or_else(fs::invalid)?;
            let Opened::Directory(entries) = &mut entry.opened else {
                return Err(fs::invalid());
            };
            let files: Vec<_> = entries.take(100).collect();
            if files.is_empty() {
                return Err(eof());
            }
            Ok(Name { id, files })
        })
        .await
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Ok(Name {
            id,
            files: vec![russh_sftp::protocol::File::dummy(fs::clean(&path))],
        })
    }

    async fn readlink(&mut self, _: u32, _: String) -> Result<Name, Self::Error> {
        Err(status_error(fs::invalid()))
    }

    async fn extended(
        &mut self,
        _: u32,
        request: String,
        _: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        Err(
            if request == "posix-rename@openssh.com" || request == "hardlink@openssh.com" {
                StatusCode::PermissionDenied.into()
            } else {
                StatusCode::OpUnsupported.into()
            },
        )
    }
}
