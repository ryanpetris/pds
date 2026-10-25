use std::{collections::HashMap, fs, sync::OnceLock};

fn with_charset(value: &str) -> String {
    if value.starts_with("text/") && !value.contains("charset=") {
        format!("{value}; charset=utf-8")
    } else {
        value.to_owned()
    }
}

pub(super) fn by_extension(name: &str) -> Option<String> {
    static TYPES: OnceLock<HashMap<String, String>> = OnceLock::new();
    let types = TYPES.get_or_init(load);
    let dot = name.rfind('.')?;
    let extension = &name[dot..];
    types
        .get(extension)
        .or_else(|| types.get(&extension.to_ascii_lowercase()))
        .cloned()
}

fn load() -> HashMap<String, String> {
    let mut types: HashMap<String, String> = BUILTINS
        .iter()
        .map(|(ext, mime)| (ext.to_string(), with_charset(mime)))
        .collect();
    for path in ["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let fields: Vec<_> = line.split(':').collect();
            if fields.len() < 3 || fields[0].is_empty() || fields[0].starts_with('#') {
                continue;
            }
            let Some(extension) = fields[2].strip_prefix('*') else {
                continue;
            };
            if !extension.starts_with('.')
                || extension.len() < 2
                || extension.contains(['?', '*', '['])
            {
                continue;
            }
            if !types.contains_key(extension) {
                let mime = with_charset(fields[1]);
                types.insert(extension.to_ascii_lowercase(), mime.clone());
                types.insert(extension.to_owned(), mime);
            }
        }
        return types;
    }
    for path in [
        "/etc/mime.types",
        "/etc/apache2/mime.types",
        "/etc/apache/mime.types",
        "/etc/httpd/conf/mime.types",
    ] {
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        for line in text.lines() {
            let mut fields = line.split('#').next().unwrap_or("").split_whitespace();
            let Some(mime) = fields.next() else {
                continue;
            };
            for extension in fields {
                types.insert(
                    format!(".{}", extension.to_ascii_lowercase()),
                    with_charset(mime),
                );
                types.insert(format!(".{extension}"), with_charset(mime));
            }
        }
    }
    types
}

pub(super) fn sniff(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(512)];
    let first = data
        .iter()
        .position(|b| !matches!(b, b'\t' | b'\n' | 12 | b'\r' | b' '))
        .unwrap_or(data.len());
    let trimmed = &data[first..];
    for tag in [
        "<!DOCTYPE HTML",
        "<HTML",
        "<HEAD",
        "<SCRIPT",
        "<IFRAME",
        "<H1",
        "<DIV",
        "<FONT",
        "<TABLE",
        "<A",
        "<STYLE",
        "<TITLE",
        "<B",
        "<BODY",
        "<BR",
        "<P",
        "<!--",
    ] {
        if trimmed.len() > tag.len()
            && trimmed[..tag.len()].eq_ignore_ascii_case(tag.as_bytes())
            && matches!(trimmed[tag.len()], b' ' | b'>')
        {
            return "text/html; charset=utf-8";
        }
    }
    if trimmed.starts_with(b"<?xml") {
        return "text/xml; charset=utf-8";
    }
    if data.starts_with(b"%PDF-") {
        return "application/pdf";
    }
    if data.starts_with(b"%!PS-Adobe-") {
        return "application/postscript";
    }
    if data.len() >= 4 {
        if data.starts_with(b"\xfe\xff") {
            return "text/plain; charset=utf-16be";
        }
        if data.starts_with(b"\xff\xfe") {
            return "text/plain; charset=utf-16le";
        }
        if data.starts_with(b"\xef\xbb\xbf") {
            return "text/plain; charset=utf-8";
        }
    }
    for (prefix, mime) in IMAGE_PREFIXES {
        if data.starts_with(prefix) {
            return mime;
        }
    }
    if data.len() >= 14 && &data[..4] == b"RIFF" && &data[8..14] == b"WEBPVP" {
        return "image/webp";
    }
    if data.len() >= 12 && &data[..4] == b"FORM" && &data[8..12] == b"AIFF" {
        return "audio/aiff";
    }
    for (prefix, mime) in AUDIO_PREFIXES {
        if data.starts_with(prefix) {
            return mime;
        }
    }
    if data.len() >= 12 && &data[..4] == b"RIFF" {
        match &data[8..12] {
            b"AVI " => return "video/avi",
            b"WAVE" => return "audio/wave",
            _ => (),
        }
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        let len = u32::from_be_bytes(data[..4].try_into().unwrap()) as usize;
        if len <= data.len()
            && len.is_multiple_of(4)
            && (8..len)
                .step_by(4)
                .any(|i| i != 12 && &data[i..i + 3] == b"mp4")
        {
            return "video/mp4";
        }
    }
    if data.starts_with(b"\x1a\x45\xdf\xa3") {
        return "video/webm";
    }
    if data.len() >= 36 && &data[34..36] == b"LP" {
        return "application/vnd.ms-fontobject";
    }
    for (prefix, mime) in OTHER_PREFIXES {
        if data.starts_with(prefix) {
            return mime;
        }
    }
    if data
        .iter()
        .any(|b| matches!(b, 0..=8 | 11 | 14..=26 | 28..=31))
    {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    }
}

const IMAGE_PREFIXES: &[(&[u8], &str)] = &[
    (b"\0\0\x01\0", "image/x-icon"),
    (b"\0\0\x02\0", "image/x-icon"),
    (b"BM", "image/bmp"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
];
const AUDIO_PREFIXES: &[(&[u8], &str)] = &[
    (b"ID3", "audio/mpeg"),
    (b"OggS\0", "application/ogg"),
    (b"MThd\0\0\0\x06", "audio/midi"),
];
const OTHER_PREFIXES: &[(&[u8], &str)] = &[
    (b"\0\x01\0\0", "font/ttf"),
    (b"OTTO", "font/otf"),
    (b"ttcf", "font/collection"),
    (b"wOFF", "font/woff"),
    (b"wOF2", "font/woff2"),
    (b"\x1f\x8b\x08", "application/x-gzip"),
    (b"PK\x03\x04", "application/zip"),
    (b"Rar!\x1a\x07\0", "application/x-rar-compressed"),
    (b"Rar!\x1a\x07\x01\0", "application/x-rar-compressed"),
    (b"\0asm", "application/wasm"),
];

const BUILTINS: &[(&str, &str)] = &[
    (".ai", "application/postscript"),
    (".apk", "application/vnd.android.package-archive"),
    (".apng", "image/apng"),
    (".avif", "image/avif"),
    (".bin", "application/octet-stream"),
    (".bmp", "image/bmp"),
    (".com", "application/octet-stream"),
    (".css", "text/css; charset=utf-8"),
    (".csv", "text/csv; charset=utf-8"),
    (".doc", "application/msword"),
    (
        ".docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (".ehtml", "text/html; charset=utf-8"),
    (".eml", "message/rfc822"),
    (".eps", "application/postscript"),
    (".exe", "application/octet-stream"),
    (".flac", "audio/flac"),
    (".gif", "image/gif"),
    (".gz", "application/gzip"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".ico", "image/vnd.microsoft.icon"),
    (".ics", "text/calendar; charset=utf-8"),
    (".jfif", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".m4a", "audio/mp4"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".mp3", "audio/mpeg"),
    (".mp4", "video/mp4"),
    (".oga", "audio/ogg"),
    (".ogg", "audio/ogg"),
    (".ogv", "video/ogg"),
    (".opus", "audio/ogg"),
    (".pdf", "application/pdf"),
    (".pjp", "image/jpeg"),
    (".pjpeg", "image/jpeg"),
    (".png", "image/png"),
    (".ppt", "application/vnd.ms-powerpoint"),
    (
        ".pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    (".ps", "application/postscript"),
    (".rdf", "application/rdf+xml"),
    (".rtf", "application/rtf"),
    (".shtml", "text/html; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".text", "text/plain; charset=utf-8"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".txt", "text/plain; charset=utf-8"),
    (".vtt", "text/vtt; charset=utf-8"),
    (".wasm", "application/wasm"),
    (".wav", "audio/wav"),
    (".weba", "audio/webm"),
    (".webm", "video/webm"),
    (".webp", "image/webp"),
    (".xbl", "text/xml; charset=utf-8"),
    (".xbm", "image/x-xbitmap"),
    (".xht", "application/xhtml+xml"),
    (".xhtml", "application/xhtml+xml"),
    (".xls", "application/vnd.ms-excel"),
    (
        ".xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    (".xml", "text/xml; charset=utf-8"),
    (".xsl", "text/xml; charset=utf-8"),
    (".zip", "application/zip"),
];
