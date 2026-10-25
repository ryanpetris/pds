use std::fmt;
use std::io::{self, BufRead, BufReader, Read};
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Validator {
    None,
    Json,
    Jsonl,
    Yaml,
    Unknown(String),
}

impl Default for Validator {
    fn default() -> Self {
        Self::Unknown(String::new())
    }
}

impl Validator {
    pub const NAMES: [&'static str; 4] = ["none", "json", "jsonl", "yaml"];

    pub fn as_str(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Yaml => "yaml",
            Self::Unknown(name) => name,
        }
    }

    pub fn known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    pub fn validate(&self, reader: impl Read) -> Result<()> {
        match self {
            Self::None => Ok(()),
            Self::Json => validate_json(reader, true).context("invalid json"),
            Self::Jsonl => {
                let mut records = 0;
                for (i, line) in BufReader::new(reader).split(b'\n').enumerate() {
                    let line = line.context("invalid jsonl")?;
                    let line = String::from_utf8_lossy(&line);
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    validate_json(line.as_bytes(), false).with_context(|| {
                        format!(
                            "invalid jsonl: line {} is not a single valid json value",
                            i + 1
                        )
                    })?;
                    records += 1;
                }
                if records == 0 {
                    bail!("invalid jsonl: no json records");
                }
                Ok(())
            }
            Self::Yaml => crate::yaml::validate(reader).context("invalid yaml"),
            Self::Unknown(name) => bail!("unknown validator {name:?}"),
        }
    }
}

fn validate_json(reader: impl Read, check_numbers: bool) -> Result<()> {
    let reader = JsonReader {
        reader,
        check_numbers,
        number: Vec::new(),
        depth: 0,
        quoted: false,
        escaped: false,
    };
    let mut decoder = serde_json::Deserializer::from_reader(BufReader::new(reader));
    decoder.disable_recursion_limit();
    serde::de::IgnoredAny::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(())
}

struct JsonReader<R> {
    reader: R,
    check_numbers: bool,
    number: Vec<u8>,
    depth: u32,
    quoted: bool,
    escaped: bool,
}

impl<R> JsonReader<R> {
    fn end_number(&mut self) -> io::Result<()> {
        if !self.number.is_empty() {
            let text = std::str::from_utf8(&self.number).expect("JSON number is ASCII");
            if text.parse::<f64>().is_ok_and(|number| !number.is_finite()) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "JSON number out of float64 range",
                ));
            }
            self.number.clear();
        }
        Ok(())
    }
}

impl<R: Read> Read for JsonReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(buffer)?;
        for &byte in &buffer[..count] {
            if self.quoted {
                if self.escaped {
                    self.escaped = false;
                } else if byte == b'\\' {
                    self.escaped = true;
                } else if byte == b'"' {
                    self.quoted = false;
                }
                continue;
            }
            if self.check_numbers {
                if byte.is_ascii_digit()
                    || byte == b'-'
                    || (!self.number.is_empty() && b".+eE".contains(&byte))
                {
                    self.number.push(byte);
                } else {
                    self.end_number()?;
                }
            }
            match byte {
                b'"' => self.quoted = true,
                b'[' | b'{' => {
                    self.depth += 1;
                    if self.depth > 10000 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "JSON exceeds maximum depth",
                        ));
                    }
                }
                b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                _ => {}
            }
        }
        if count == 0 {
            self.end_number()?;
        }
        Ok(count)
    }
}

impl From<&str> for Validator {
    fn from(name: &str) -> Self {
        match name {
            "none" => Self::None,
            "json" => Self::Json,
            "jsonl" => Self::Jsonl,
            "yaml" => Self::Yaml,
            name => Self::Unknown(name.to_owned()),
        }
    }
}

impl FromStr for Validator {
    type Err = anyhow::Error;

    fn from_str(name: &str) -> Result<Self> {
        let validator = Self::from(name);
        if !validator.known() {
            bail!("unknown validator {name:?}");
        }
        Ok(validator)
    }
}

impl fmt::Display for Validator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Validator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Validator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from(crate::config::go_string(deserializer)?.as_str()))
    }
}

pub fn known(name: &str) -> bool {
    Validator::from(name).known()
}

pub fn validate(name: &str, reader: impl Read) -> Result<()> {
    Validator::from(name).validate(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_match_document_contracts() {
        for (name, data, valid) in [
            ("none", "anything at all", true),
            ("none", "", true),
            ("yaml", "a: 1\nb: [1,2,3]\n", true),
            ("yaml", "---\na: 1\n---\nb: 2\n", true),
            ("yaml", "", true),
            ("yaml", "foo: [bar", false),
            ("yaml", "a: 1\na: 2", false),
            ("json", "{\"a\":[1,2,3]}", true),
            ("json", "{}\n", true),
            ("json", "{\"a\":}", false),
            ("json", "", false),
            ("json", "{} {}", false),
            ("json", "1 2", false),
            ("json", "{}garbage", false),
            ("jsonl", "{\"a\":1}\n{\"b\":2}\n", true),
            ("jsonl", "{\"a\":1}", true),
            ("jsonl", "{\"a\":1}\n\n{\"b\":2}", true),
            ("jsonl", "", false),
            ("jsonl", "   \n", false),
            ("jsonl", "{} {}\n", false),
            ("jsonl", "{\n\"a\":1\n}\n", false),
            ("jsonl", "{\n", false),
            ("nope", "x", false),
        ] {
            assert_eq!(
                validate(name, data.as_bytes()).is_ok(),
                valid,
                "{name} {data:?}"
            );
        }
        assert!(known("yaml") && known("jsonl") && !known("nope"));
    }

    #[test]
    fn jsonl_accepts_large_records() {
        let record = format!("\"{}\"\n", "x".repeat(128 * 1024));
        validate("jsonl", record.as_bytes()).unwrap();
    }

    #[test]
    fn json_matches_go_numeric_unicode_and_depth_rules() {
        assert!(validate("json", b"1e1000".as_slice()).is_err());
        validate("jsonl", b"1e1000\n".as_slice()).unwrap();
        for data in [b"\"\\ud800\"".as_slice(), b"\"\xff\"", b"{\"\xff\":0}"] {
            validate("json", data).unwrap();
            validate("jsonl", data).unwrap();
        }
        validate("jsonl", "\u{a0}{}\u{a0}\n\u{2003}\n".as_bytes()).unwrap();
        let nested = format!("{}0{}", "[".repeat(10000), "]".repeat(10000));
        validate("json", nested.as_bytes()).unwrap();
        validate("jsonl", nested.as_bytes()).unwrap();
        let too_deep = format!("[{nested}]");
        assert!(validate("json", too_deep.as_bytes()).is_err());
        assert!(validate("jsonl", too_deep.as_bytes()).is_err());
    }

    #[test]
    fn yaml_handles_deep_documents_and_rejects_collection_keys() {
        for depth in [256, 10000] {
            let document = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
            validate("yaml", document.as_bytes()).unwrap();
        }
        assert!(validate("yaml", b"? [a, b]\n: value\n".as_slice()).is_err());
        assert!(validate("yaml", b"? {a: b}\n: value\n".as_slice()).is_err());
        assert!(validate("yaml", b"value: !!binary invalid!\n".as_slice()).is_err());
        assert!(validate("yaml", b"&a [*a]\n".as_slice()).is_err());
        assert!(validate("yaml", b"a: {<<: 1}\n".as_slice()).is_err());
        validate("yaml", b"value: !custom text\n".as_slice()).unwrap();
    }
}
