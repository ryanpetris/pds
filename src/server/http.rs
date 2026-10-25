use std::{
    collections::VecDeque,
    convert::Infallible,
    io::{self, Read},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{BodyExt, Full, StreamBody, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode,
    body::Frame,
    header::{self, HeaderMap},
};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    net::TcpListener,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use super::{
    Server,
    fs::{Resolved, View},
};
use crate::{Result, store};

/// Streaming HTTP body returned by `Server::http_response`.
pub type HttpBody = UnsyncBoxBody<Bytes, io::Error>;

fn full(bytes: impl Into<Bytes>) -> HttpBody {
    Full::new(bytes.into())
        .map_err(|never: Infallible| match never {})
        .boxed_unsync()
}

fn response(
    status: StatusCode,
    content_type: &str,
    bytes: Vec<u8>,
    head: bool,
) -> Response<HttpBody> {
    let len = bytes.len();
    let mut response = Response::new(if head {
        full(Bytes::new())
    } else {
        full(bytes)
    });
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, len.into());
    response
}

fn error(status: StatusCode, text: &str, head: bool) -> Response<HttpBody> {
    let mut response = response(
        status,
        "text/plain; charset=utf-8",
        format!("{text}\n").into_bytes(),
        head,
    );
    response
        .headers_mut()
        .insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    response
}

fn store_error(err: anyhow::Error, head: bool) -> Response<HttpBody> {
    match err.downcast_ref::<io::Error>().map(io::Error::kind) {
        Some(io::ErrorKind::NotFound) => error(StatusCode::NOT_FOUND, "not found", head),
        Some(io::ErrorKind::PermissionDenied) => error(StatusCode::FORBIDDEN, "forbidden", head),
        _ => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error", head),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    name: String,
    size: u64,
    is_dir: bool,
    mod_time: String,
}

struct Content {
    file: std::fs::File,
    size: u64,
    modified: SystemTime,
    mime: String,
}

enum Prepared {
    Bytes(&'static str, Vec<u8>),
    File(Content),
    MissingPush,
}

fn prepare(config: Arc<crate::config::Server>, path: &str) -> Result<Prepared> {
    let view = View { config, host: None };
    match view.resolve(path)? {
        Resolved::Bucket { push: true, .. } => return Ok(Prepared::MissingPush),
        Resolved::Bucket {
            bucket, meta: true, ..
        } => return Ok(Prepared::Bytes("application/yaml", store::meta(bucket)?)),
        Resolved::Bucket { bucket, sub, .. } => {
            let metadata = store::stat(bucket, &sub)?;
            if !metadata.is_dir() {
                let mut file = store::open(bucket, &sub)?;
                let path = store::safe_resolve(&bucket.path, &sub)?;
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                let mime = match super::mime::by_extension(&name) {
                    Some(mime) => mime,
                    None => {
                        let mut prefix = Vec::new();
                        Read::by_ref(&mut file).take(512).read_to_end(&mut prefix)?;
                        super::mime::sniff(&prefix).to_owned()
                    }
                };
                return Ok(Prepared::File(Content {
                    file,
                    size: metadata.len(),
                    modified: metadata.modified().unwrap_or(UNIX_EPOCH),
                    mime,
                }));
            }
            let mut entries: Vec<_> = store::list(bucket, &sub)?
                .into_iter()
                .map(|entry| Entry {
                    name: entry.name.to_string_lossy().into_owned(),
                    size: entry.metadata.len(),
                    is_dir: entry.metadata.is_dir(),
                    mod_time: chrono::DateTime::<chrono::Utc>::from(
                        entry.metadata.modified().unwrap_or(UNIX_EPOCH),
                    )
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                })
                .collect();
            if sub.is_empty() {
                entries.push(Entry {
                    name: crate::config::NAME_META.into(),
                    size: store::meta(bucket)?.len() as u64,
                    is_dir: false,
                    mod_time: "1970-01-01T00:00:00Z".into(),
                });
            }
            return json(entries);
        }
        _ => (),
    }
    let entries: Vec<_> = view
        .list(path)?
        .into_iter()
        .map(|file| Entry {
            name: file.filename,
            size: file.attrs.size.unwrap_or(0),
            is_dir: file.attrs.permissions.unwrap_or(0) & 0o170000 == 0o40000,
            mod_time: chrono::DateTime::from_timestamp(file.attrs.mtime.unwrap_or(0) as i64, 0)
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
        .collect();
    json(entries)
}

fn json(entries: Vec<Entry>) -> Result<Prepared> {
    let mut bytes = serde_json::to_vec(&entries)?;
    bytes.push(b'\n');
    Ok(Prepared::Bytes("application/json", bytes))
}

impl Server {
    /// Handle one read-only HTTP request. The HTTP listener uses this same handler.
    pub async fn http_response<B>(&self, request: Request<B>) -> Response<HttpBody> {
        let (parts, _) = request.into_parts();
        let head = parts.method == Method::HEAD;
        if !head && parts.method != Method::GET {
            return error(StatusCode::METHOD_NOT_ALLOWED, "read-only", false);
        }
        if !self.config.allow_anonymous {
            return error(StatusCode::FORBIDDEN, "forbidden", head);
        }
        let path = percent_encoding::percent_decode_str(parts.uri.path())
            .decode_utf8_lossy()
            .into_owned();
        let config = self.config.clone();
        let result = tokio::task::spawn_blocking(move || prepare(config, &path)).await;
        match result {
            Ok(Ok(Prepared::Bytes(mime, bytes))) => response(StatusCode::OK, mime, bytes, head),
            Ok(Ok(Prepared::File(content))) => serve_content(content, &parts.headers, head),
            Ok(Ok(Prepared::MissingPush)) => {
                error(StatusCode::NOT_FOUND, "404 page not found", head)
            }
            Ok(Err(err)) => store_error(err, head),
            Err(_) => error(StatusCode::INTERNAL_SERVER_ERROR, "internal error", head),
        }
    }

    pub(super) async fn accept_http(
        &self,
        listener: TcpListener,
        stop: CancellationToken,
    ) -> Result<()> {
        let mut connections = JoinSet::new();
        let result = loop {
            tokio::select! {
                _ = stop.cancelled() => break Ok(()),
                _ = connections.join_next(), if !connections.is_empty() => (),
                accepted = listener.accept() => {
                    let socket = match accepted { Ok((socket, _)) => socket, Err(error) => break Err(error.into()) };
                    let server = self.clone();
                    connections.spawn(async move {
                        let service = hyper::service::service_fn(move |request| {
                            let server = server.clone();
                            async move { Ok::<_, Infallible>(server.http_response(request).await) }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .timer(TokioTimer::new()).header_read_timeout(super::HANDSHAKE_TIMEOUT)
                            .serve_connection(TokioIo::new(socket), service).await;
                    });
                }
            }
        };
        connections.shutdown().await;
        result
    }
}

fn get<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

fn date(headers: &HeaderMap, name: &str) -> Option<SystemTime> {
    httpdate::parse_http_date(get(headers, name)).ok()
}

fn seconds(time: SystemTime) -> i64 {
    chrono::DateTime::<chrono::Utc>::from(time).timestamp()
}

// There is no response ETag; only a wildcard in a valid ETag list can match.
fn wildcard(mut value: &str) -> bool {
    loop {
        value = value.trim_start_matches([' ', '\t', '\r', '\n', ',']);
        if value.starts_with('*') {
            return true;
        }
        value = value.strip_prefix("W/").unwrap_or(value);
        let Some(rest) = value.strip_prefix('"') else {
            return false;
        };
        let Some(end) = rest.find('"') else {
            return false;
        };
        if rest.as_bytes()[..end]
            .iter()
            .any(|b| *b < 0x21 || *b == 0x7f)
        {
            return false;
        }
        value = &rest[end + 1..];
    }
}

fn precondition(headers: &HeaderMap, modified: SystemTime) -> Option<StatusCode> {
    let valid_time = modified != UNIX_EPOCH;
    let matched = get(headers, "if-match");
    if !matched.is_empty() {
        if !wildcard(matched) {
            return Some(StatusCode::PRECONDITION_FAILED);
        }
    } else if valid_time
        && date(headers, "if-unmodified-since")
            .is_some_and(|date| seconds(modified) > seconds(date))
    {
        return Some(StatusCode::PRECONDITION_FAILED);
    }
    let unmatched = get(headers, "if-none-match");
    if !unmatched.is_empty() {
        if wildcard(unmatched) {
            return Some(StatusCode::NOT_MODIFIED);
        }
    } else if valid_time
        && date(headers, "if-modified-since").is_some_and(|date| seconds(modified) <= seconds(date))
    {
        return Some(StatusCode::NOT_MODIFIED);
    }
    None
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Range {
    start: u64,
    len: u64,
}
impl Range {
    fn header(self, size: u64) -> String {
        format!(
            "bytes {}-{}/{size}",
            self.start,
            self.start as i128 + self.len as i128 - 1
        )
    }
}

#[derive(Debug, PartialEq)]
enum RangeError {
    Invalid,
    NoOverlap,
}

fn ranges(header: &str, size: u64) -> Result<Vec<Range>, RangeError> {
    if header.is_empty() {
        return Ok(vec![]);
    }
    let input = header.strip_prefix("bytes=").ok_or(RangeError::Invalid)?;
    if input.bytes().filter(|b| *b == b',').count() >= 200 {
        return Ok(vec![]);
    }
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    let number = |s: &str| -> Result<u64, RangeError> {
        s.parse::<i64>()
            .ok()
            .and_then(|n| u64::try_from(n).ok())
            .ok_or(RangeError::Invalid)
    };
    for part in input.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (start, end) = part.split_once('-').ok_or(RangeError::Invalid)?;
        let (start, end) = (start.trim(), end.trim());
        if start.is_empty() {
            if end.starts_with('-') {
                return Err(RangeError::Invalid);
            }
            let len = number(end)?.min(size);
            ranges.push(Range {
                start: size - len,
                len,
            });
        } else {
            let start = number(start)?;
            if start >= size {
                no_overlap = true;
                continue;
            }
            let end = if end.is_empty() {
                size - 1
            } else {
                number(end)?
            };
            if end < start {
                return Err(RangeError::Invalid);
            }
            ranges.push(Range {
                start,
                len: end.min(size - 1) - start + 1,
            });
        }
    }
    if no_overlap && ranges.is_empty() {
        Err(RangeError::NoOverlap)
    } else {
        Ok(ranges)
    }
}

enum Piece {
    Bytes(Bytes),
    File { offset: Option<u64>, len: u64 },
}

fn file_body(file: std::fs::File, pieces: VecDeque<Piece>) -> HttpBody {
    let stream = stream::try_unfold(
        (tokio::fs::File::from_std(file), pieces),
        |(mut file, mut pieces)| async move {
            while let Some(piece) = pieces.pop_front() {
                match piece {
                    Piece::Bytes(bytes) => return Ok(Some((Frame::data(bytes), (file, pieces)))),
                    Piece::File { offset, len } => {
                        if let Some(offset) = offset {
                            file.seek(io::SeekFrom::Start(offset)).await?;
                        }
                        if len == 0 {
                            continue;
                        }
                        let mut bytes = vec![0; len.min(65536) as usize];
                        let read = file.read(&mut bytes).await?;
                        if read == 0 {
                            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                        }
                        bytes.truncate(read);
                        pieces.push_front(Piece::File {
                            offset: None,
                            len: len - read as u64,
                        });
                        return Ok(Some((Frame::data(Bytes::from(bytes)), (file, pieces))));
                    }
                }
            }
            Ok(None)
        },
    );
    StreamBody::new(stream).boxed_unsync()
}

fn serve_content(content: Content, headers: &HeaderMap, head: bool) -> Response<HttpBody> {
    let mut response = Response::new(full(Bytes::new()));
    if content.modified != UNIX_EPOCH {
        let formatted = chrono::DateTime::<chrono::Utc>::from(content.modified)
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        response
            .headers_mut()
            .insert(header::LAST_MODIFIED, formatted.parse().unwrap());
    }
    if let Some(status) = precondition(headers, content.modified) {
        *response.status_mut() = status;
        return response;
    }
    let mut range = get(headers, "range");
    if !get(headers, "if-range").is_empty()
        && !date(headers, "if-range").is_some_and(|time| seconds(time) == seconds(content.modified))
    {
        range = "";
    }
    let mut ranges = match ranges(range, content.size) {
        Ok(ranges) => ranges,
        Err(RangeError::NoOverlap) if content.size == 0 => vec![],
        Err(err) => {
            let text = if err == RangeError::NoOverlap {
                "invalid range: failed to overlap"
            } else {
                "invalid range"
            };
            let mut response = error(StatusCode::RANGE_NOT_SATISFIABLE, text, head);
            if err == RangeError::NoOverlap {
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    format!("bytes */{}", content.size).parse().unwrap(),
                );
            }
            return response;
        }
    };
    if ranges.iter().map(|range| range.len as u128).sum::<u128>() > content.size as u128 {
        ranges.clear();
    }
    let mut pieces = VecDeque::new();
    let mut mime = content.mime;
    let mut size = content.size;
    match ranges.as_slice() {
        [] => pieces.push_back(Piece::File {
            offset: Some(0),
            len: size,
        }),
        [range] => {
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            response
                .headers_mut()
                .insert(header::CONTENT_RANGE, range.header(size).parse().unwrap());
            size = range.len;
            pieces.push_back(Piece::File {
                offset: Some(range.start),
                len: range.len,
            });
        }
        ranges => {
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            // A per-response boundary keeps unrelated responses independent.
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let boundary = format!(
                "pds-{:x}-{:x}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            );
            size = 0;
            for (i, range) in ranges.iter().enumerate() {
                let prefix = if i == 0 { "" } else { "\r\n" };
                let header = format!(
                    "{prefix}--{boundary}\r\nContent-Range: {}\r\nContent-Type: {mime}\r\n\r\n",
                    range.header(content.size)
                );
                size += header.len() as u64 + range.len;
                pieces.push_back(Piece::Bytes(header.into()));
                pieces.push_back(Piece::File {
                    offset: Some(range.start),
                    len: range.len,
                });
            }
            let end = format!("\r\n--{boundary}--\r\n");
            size += end.len() as u64;
            pieces.push_back(Piece::Bytes(end.into()));
            mime = format!("multipart/byteranges; boundary={boundary}");
        }
    }
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, mime.parse().unwrap());
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    response
        .headers_mut()
        .insert(header::CONTENT_LENGTH, size.into());
    if !head {
        *response.body_mut() = file_body(content.file, pieces);
    }
    response
}
