//! YAML node decoding with the scalar and alias rules used by yaml.v3.

use std::collections::{HashMap, HashSet};
use std::io::Read;

use anyhow::{Result, bail, ensure};
use base64::Engine;
use chrono::NaiveDate;
use granit_parser::{Parser, ScalarStyle};
use serde_yaml_ng::{Mapping, Value};

// Configuration layers recurse only into Go's map[string]any values.
const GENERAL_MAP: &str = "pds-general-map";

struct Node {
    event: Event,
    children: Vec<usize>,
}

enum Event {
    Scalar(String, bool, String),
    Alias(usize),
    SequenceStart,
    MappingStart,
}

#[derive(Default)]
struct Document {
    nodes: Vec<Node>,
}

pub(crate) fn first_document(data: &[u8]) -> Result<Value> {
    let mut result = Value::Null(None);
    documents(data, |document| {
        result = document.decode(true)?;
        Ok(false)
    })?;
    Ok(result)
}

pub(crate) fn validate(mut reader: impl Read) -> Result<()> {
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    documents(&data, |document| {
        let mut pending = vec![document.decode(false)?];
        while let Some(value) = pending.pop() {
            match value {
                Value::Sequence(values) => pending.extend(values),
                Value::Mapping(values) => {
                    for (key, value) in values {
                        pending.push(key);
                        pending.push(value);
                    }
                }
                Value::Tagged(tagged) => pending.push(tagged.value),
                _ => {}
            }
        }
        Ok(true)
    })
}

fn documents(data: &[u8], mut visit: impl FnMut(Document) -> Result<bool>) -> Result<()> {
    use granit_parser::Event as Parsed;
    let text = if data.starts_with(&[0xff, 0xfe]) || data.starts_with(&[0xfe, 0xff]) {
        ensure!(data.len().is_multiple_of(2), "incomplete UTF-16 YAML input");
        let little_endian = data[0] == 0xff;
        let units = data[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                if little_endian {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            })
            .collect::<Vec<_>>();
        std::borrow::Cow::Owned(String::from_utf16(&units)?)
    } else {
        std::borrow::Cow::Borrowed(std::str::from_utf8(data)?)
    };
    let options = granit_parser::options! {
        flow_nesting_limit: 10000,
        block_nesting_limit: 10000,
        max_directive_bytes: usize::MAX,
        max_reserved_directive_params: usize::MAX,
    };
    let mut document = Document::default();
    let mut anchors = HashMap::new();
    let mut parents: Vec<usize> = Vec::new();
    for event in Parser::new_from_str_with_options(&text, options) {
        let (event, span) = event?;
        let (kind, anchor) = match event {
            Parsed::DocumentStart(_, Some(version)) => {
                ensure!(
                    version.major == 1 && version.minor == 1,
                    "incompatible YAML version"
                );
                continue;
            }
            Parsed::DocumentEnd => {
                if !visit(std::mem::take(&mut document))? {
                    return Ok(());
                }
                anchors.clear();
                continue;
            }
            Parsed::Scalar(value, style, anchor, tag) => {
                if style == ScalarStyle::DoubleQuoted {
                    let mut chars = span.slice(&text).unwrap_or_default().chars();
                    while let Some(character) = chars.next() {
                        if character == '\\' && chars.next() == Some('u') {
                            let digits: String = chars.by_ref().take(4).collect();
                            let code = u16::from_str_radix(&digits, 16)?;
                            ensure!(
                                !(0xd800..=0xdfff).contains(&code),
                                "invalid Unicode character escape"
                            );
                        }
                    }
                }
                let tag = tag
                    .as_deref()
                    .map(|tag| {
                        let (handle, suffix) = tag.parts();
                        format!("{handle}{suffix}")
                    })
                    .unwrap_or_default();
                (
                    Event::Scalar(value.into_owned(), style == ScalarStyle::Plain, tag),
                    anchor,
                )
            }
            Parsed::Alias(anchor) => (Event::Alias(anchors[&anchor]), 0),
            Parsed::SequenceStart(_, anchor, _) => (Event::SequenceStart, anchor),
            Parsed::MappingStart(_, anchor, _) => (Event::MappingStart, anchor),
            Parsed::SequenceEnd | Parsed::MappingEnd => {
                parents.pop();
                continue;
            }
            _ => continue,
        };
        let index = document.nodes.len();
        if let Some(&parent) = parents.last() {
            document.nodes[parent].children.push(index);
        }
        if anchor != 0 {
            anchors.insert(anchor, index);
        }
        if matches!(kind, Event::SequenceStart | Event::MappingStart) {
            parents.push(index);
        }
        document.nodes.push(Node {
            event: kind,
            children: Vec::new(),
        });
    }
    Ok(())
}

#[derive(Default)]
struct Decoder {
    config: bool,
    decoded: usize,
    aliases: usize,
    active_aliases: HashSet<usize>,
}

impl Document {
    fn decode(&self, config: bool) -> Result<Value> {
        // yaml.v3 counts the document node as well as its contents.
        self.value(
            0,
            &mut Decoder {
                config,
                decoded: 1,
                ..Decoder::default()
            },
            0,
            None,
            config.then_some(true),
        )
    }

    fn value(
        &self,
        index: usize,
        decoder: &mut Decoder,
        alias_depth: usize,
        merged: Option<&mut HashSet<Value>>,
        string_keys: Option<bool>,
    ) -> Result<Value> {
        stacker::maybe_grow(64 * 1024, 1024 * 1024, || {
            decoder.decoded += 1;
            if alias_depth != 0 {
                decoder.aliases += 1;
            }
            let ratio = if decoder.decoded <= 400_000 {
                0.99
            } else if decoder.decoded >= 4_000_000 {
                0.10
            } else {
                0.99 - 0.89 * (decoder.decoded - 400_000) as f64 / 3_600_000.0
            };
            ensure!(
                decoder.aliases <= 100
                    || decoder.decoded <= 1000
                    || decoder.aliases as f64 / decoder.decoded as f64 <= ratio,
                "document contains excessive aliasing"
            );
            let node = &self.nodes[index];
            match &node.event {
                Event::Scalar(text, plain, tag) => scalar(text, *plain, tag),
                Event::Alias(anchor) => {
                    ensure!(
                        decoder.active_aliases.insert(index),
                        "anchor contains itself"
                    );
                    let result = self.value(*anchor, decoder, alias_depth + 1, merged, string_keys);
                    decoder.active_aliases.remove(&index);
                    result
                }
                Event::SequenceStart => node
                    .children
                    .iter()
                    .map(|&child| self.value(child, decoder, alias_depth, None, None))
                    .collect::<Result<Vec<_>>>()
                    .map(|values| {
                        Value::Sequence(serde_yaml_ng::Sequence {
                            elements: values,
                            anchor: None,
                        })
                    }),
                Event::MappingStart => {
                    self.mapping(index, decoder, alias_depth, merged, string_keys)
                }
            }
        })
    }

    fn mapping(
        &self,
        index: usize,
        decoder: &mut Decoder,
        alias_depth: usize,
        mut merged: Option<&mut HashSet<Value>>,
        string_keys: Option<bool>,
    ) -> Result<Value> {
        // Merge sources inherit the receiving map's key type.
        let string_keys = decoder.config
            && string_keys.unwrap_or_else(|| {
                self.nodes[index]
                    .children
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .all(|pair| match self.key_event(pair[0]) {
                        Event::Scalar(text, plain, tag) if tag.is_empty() || tag == "!" => {
                            !plain || text == "<<" || resolve(text, "").0 == "str"
                        }
                        Event::Scalar(_, _, tag) => matches!(
                            tag.as_str(),
                            "tag:yaml.org,2002:str" | "tag:yaml.org,2002:merge"
                        ),
                        _ => false,
                    })
            });
        let mut result = Mapping::new();
        let mut raw_keys = HashSet::new();
        let mut merge = None;
        for pair in self.nodes[index].children.as_chunks::<2>().0 {
            let key = &self.nodes[pair[0]];
            let identity = match &key.event {
                Event::Scalar(text, ..) => (0, text.to_string()),
                Event::Alias(anchor) => (1, anchor.to_string()),
                _ => bail!("invalid map key"),
            };
            ensure!(raw_keys.insert(identity), "duplicate YAML mapping key");
        }
        for pair in self.nodes[index].children.as_chunks::<2>().0 {
            if is_merge(&self.nodes[pair[0]].event) {
                merge = Some(pair[1]);
                continue;
            }
            let mut key = self.value(pair[0], decoder, alias_depth, None, None)?;
            ensure!(!key.is_mapping() && !key.is_sequence(), "invalid map key");
            if string_keys {
                if key.is_null() {
                    continue;
                }
                // yaml.v3 decodes string keys from node text, except binary data.
                if let Event::Scalar(text, _, tag) = self.key_event(pair[0])
                    && tag != "tag:yaml.org,2002:binary"
                {
                    key = Value::String(text.clone(), None);
                }
            }
            if let Some(fields) = merged.as_deref_mut()
                && !fields.insert(key.clone())
            {
                continue;
            }
            result.insert(key, self.value(pair[1], decoder, alias_depth, None, None)?);
        }
        if let Some(source) = merge {
            let mut fields = HashSet::new();
            let fields = match merged {
                Some(fields) => fields,
                None => {
                    for pair in self.nodes[index].children.as_chunks::<2>().0 {
                        fields.insert(self.value(pair[0], decoder, alias_depth, None, None)?);
                    }
                    &mut fields
                }
            };
            let sources = if matches!(self.nodes[source].event, Event::SequenceStart) {
                self.nodes[source].children.as_slice()
            } else {
                std::slice::from_ref(&source)
            };
            for &source in sources {
                let target = if let Event::Alias(anchor) = self.nodes[source].event {
                    anchor
                } else {
                    source
                };
                ensure!(
                    matches!(self.nodes[target].event, Event::MappingStart),
                    "YAML merge requires a map or sequence of maps"
                );
                if let Value::Mapping(values) = unmark_config_map(self.value(
                    source,
                    decoder,
                    alias_depth,
                    Some(fields),
                    Some(string_keys),
                )?) {
                    result.extend(values);
                }
            }
        }
        let value = Value::Mapping(result);
        if decoder.config && !string_keys {
            Ok(Value::Tagged(Box::new(serde_yaml_ng::value::TaggedValue {
                tag: serde_yaml_ng::value::Tag::new(GENERAL_MAP)?,
                value,
            })))
        } else {
            Ok(value)
        }
    }

    fn key_event(&self, mut index: usize) -> &Event {
        while let Event::Alias(anchor) = self.nodes[index].event {
            index = anchor;
        }
        &self.nodes[index].event
    }
}

fn unmark_config_map(value: Value) -> Value {
    match value {
        Value::Tagged(tagged) if tagged.tag == GENERAL_MAP => tagged.value,
        value => value,
    }
}

// yaml.v3 emits string keys named << as merge keys during the config round trip.
pub(crate) fn config_merges(value: Value) -> Result<Value> {
    stacker::maybe_grow(64 * 1024, 1024 * 1024, || {
        Ok(match unmark_config_map(value) {
            Value::Mapping(mut mapping) => {
                let mut pending: Vec<_> = mapping.remove("<<").into_iter().collect();
                while let Some(source) = pending.pop() {
                    match unmark_config_map(source) {
                        Value::Mapping(mut source) => {
                            pending.extend(source.remove("<<"));
                            for (key, value) in source {
                                mapping.entry(key).or_insert(value);
                            }
                        }
                        Value::Sequence(sources) if sources.iter().all(Value::is_mapping) => {
                            pending.extend(sources.into_iter().rev());
                        }
                        _ => bail!("YAML merge requires a map or sequence of maps"),
                    }
                }
                Value::Mapping(
                    mapping
                        .into_iter()
                        .map(|(key, value)| Ok((key, config_merges(value)?)))
                        .collect::<Result<Mapping>>()?,
                )
            }
            Value::Sequence(mut values) => {
                values.elements = values
                    .elements
                    .into_iter()
                    .map(config_merges)
                    .collect::<Result<_>>()?;
                Value::Sequence(values)
            }
            value => value,
        })
    })
}

fn is_merge(event: &Event) -> bool {
    matches!(event, Event::Scalar(text, plain, tag) if text == "<<" &&
        (tag == "tag:yaml.org,2002:merge" || ((tag.is_empty() || tag == "!") && *plain)))
}

fn scalar(text: &str, plain: bool, tag: &str) -> Result<Value> {
    let tag = if let Some(tag) = tag.strip_prefix("tag:yaml.org,2002:") {
        tag
    } else if (tag == "!" || tag.is_empty()) && plain {
        ""
    } else {
        "str"
    };
    if tag == "binary" {
        let encoded = text.replace(['\r', '\n'], "");
        let engine = base64::engine::general_purpose::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::general_purpose::GeneralPurposeConfig::new()
                .with_decode_allow_trailing_bits(true),
        );
        let bytes = engine.decode(encoded)?;
        let text = match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(error) => {
                return Ok(Value::Tagged(Box::new(serde_yaml_ng::value::TaggedValue {
                    tag: serde_yaml_ng::value::Tag::new("binary")?,
                    value: Value::String(engine.encode(error.as_bytes()), None),
                })));
            }
        };
        return Ok(Value::String(text, None));
    }
    if !matches!(tag, "" | "bool" | "int" | "float" | "null" | "timestamp") {
        return Ok(Value::String(text.into(), None));
    }
    let (resolved, value) = resolve(text, tag);
    ensure!(
        tag.is_empty() || tag == resolved,
        "cannot decode {text:?} as YAML {tag}"
    );
    Ok(value)
}

fn resolve(text: &str, tag: &str) -> (&'static str, Value) {
    let number = |n: f64| ("float", Value::Number(n.into(), None));
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return ("null", Value::Null(None)),
        "true" | "True" | "TRUE" => return ("bool", Value::Bool(true, None)),
        "false" | "False" | "FALSE" => return ("bool", Value::Bool(false, None)),
        ".nan" | ".NaN" | ".NAN" => return number(f64::NAN),
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" => return number(f64::INFINITY),
        "-.inf" | "-.Inf" | "-.INF" => return number(f64::NEG_INFINITY),
        _ => {}
    }
    if (tag.is_empty() || tag == "timestamp")
        && let Some(value) = timestamp(text)
    {
        return ("timestamp", Value::String(value, None));
    }
    if text.starts_with(|c: char| c.is_ascii_digit() || matches!(c, '+' | '-' | '.')) {
        if text.starts_with('.')
            && text.as_bytes().iter().enumerate().any(|(i, &byte)| {
                byte == b'_'
                    && (i == 0
                        || i + 1 == text.len()
                        || !text.as_bytes()[i - 1].is_ascii_digit()
                        || !text.as_bytes()[i + 1].is_ascii_digit())
            })
        {
            return ("str", Value::String(text.into(), None));
        }
        let plain = text.replace('_', "");
        let digits = plain.strip_prefix(['-', '+']).unwrap_or(&plain);
        if digits.starts_with(['-', '+']) {
            return ("str", Value::String(text.into(), None));
        }
        let (radix, digits) = if let Some(digits) = digits
            .strip_prefix("0x")
            .or_else(|| digits.strip_prefix("0X"))
        {
            (16, digits)
        } else if let Some(digits) = digits
            .strip_prefix("0b")
            .or_else(|| digits.strip_prefix("0B"))
        {
            (2, digits)
        } else if let Some(digits) = digits
            .strip_prefix("0o")
            .or_else(|| digits.strip_prefix("0O"))
        {
            (8, digits)
        } else if digits.starts_with('0') && digits.len() > 1 {
            (8, &digits[1..])
        } else {
            (10, digits)
        };
        if let Ok(unsigned) = u64::from_str_radix(digits, radix) {
            let signed = if plain.starts_with('-') {
                i64::try_from(-(unsigned as i128)).ok()
            } else {
                i64::try_from(unsigned).ok()
            };
            if let Some(signed) = signed {
                return if tag == "float" {
                    number(signed as f64)
                } else {
                    ("int", Value::Number(signed.into(), None))
                };
            }
            if !plain.starts_with(['-', '+']) {
                return ("int", Value::Number(unsigned.into(), None));
            }
        }
        if plain
            .bytes()
            .all(|b| b.is_ascii_digit() || b"+-.eE".contains(&b))
            && let Ok(value) = plain.parse::<f64>()
            && value.is_finite()
        {
            return number(value);
        }
    }
    ("str", Value::String(text.into(), None))
}

fn timestamp(text: &str) -> Option<String> {
    let decimal = |text: &str, width: usize| -> Option<u32> {
        if text.is_empty() || text.len() > width || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let (date, time) = text
        .find(['T', 't', ' '])
        .map_or((text, None), |i| (&text[..i], Some(&text[i..])));
    let mut parts = date.split('-');
    let year = parts.next()?;
    if year.len() != 4 {
        return None;
    }
    let year = decimal(year, 4)? as i32;
    let month = decimal(parts.next()?, 2)?;
    let day = decimal(parts.next()?, 2)?;
    if parts.next().is_some() {
        return None;
    }
    let date = NaiveDate::from_ymd_opt(year, month, day)?;
    let Some(time) = time else {
        return Some(format!("{date}T00:00:00Z"));
    };
    let (clock, offset) = if time.starts_with(' ') {
        (time.trim_start_matches(' '), 0)
    } else if let Some(clock) = time[1..].strip_suffix('Z') {
        (clock, 0)
    } else {
        let (clock, zone) = time[1..].split_at_checked(time.len().checked_sub(7)?)?;
        if zone.len() != 6 || !zone.starts_with(['+', '-']) || zone.as_bytes()[3] != b':' {
            return None;
        }
        let hours = decimal(&zone[1..3], 2)?;
        let minutes = decimal(&zone[4..], 2)?;
        if hours > 24 || minutes > 60 {
            return None;
        }
        let offset = (hours * 60 + minutes) as i32;
        (
            clock,
            if zone.starts_with('-') {
                -offset
            } else {
                offset
            },
        )
    };
    let (clock, fraction) = match clock.split_once(['.', ',']) {
        Some((clock, fraction)) => {
            if fraction.is_empty() || !fraction.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (
                clock,
                fraction[..fraction.len().min(9)].trim_end_matches('0'),
            )
        }
        None => (clock, ""),
    };
    let mut parts = clock.split(':');
    let hour = decimal(parts.next()?, 2)?;
    let minute = decimal(parts.next()?, 2)?;
    let second = decimal(parts.next()?, 2)?;
    if parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let mut result = format!("{date}T{hour:02}:{minute:02}:{second:02}");
    if !fraction.is_empty() {
        result.push('.');
        result.push_str(fraction);
    }
    if offset == 0 {
        result.push('Z');
    } else {
        result.push_str(&format!(
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            offset.abs() / 60,
            offset.abs() % 60
        ));
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validator_matches_go_scalar_keys_tags_and_merges() {
        for (text, accepted) in [
            ("{'<<': 1}", true),
            ("{!!str <<: 1}", true),
            ("{! '<<': 1}", true),
            ("{<<: 1}", false),
            ("1: a\n'1': b", false),
            ("null: a\n~: b", true),
            ("true: a\nTrue: b", true),
            ("0x1: a\n1: b", true),
            ("!!timestamp bogus", false),
            ("!!timestamp 2001-01-01T23:59:60Z", false),
            ("!!timestamp 2001-01-01T01:02:03+24:00", true),
            ("!!bool yes", false),
            ("!!bool tRuE", false),
            ("? !t [a]\n: 1", false),
            ("pic: !!binary |\n  aGVs\n  bG8=\n", true),
            ("? !!binary aGk=\n: v", true),
            ("? !!binary /w==\n: v", true),
            ("value: !!binary Zh==", true),
            ("value: !!binary 'a Gk='", false),
            ("x: {<<: {<<: {host: example}, port: 22}}", true),
            ("x: {<<: {host: !!int invalid}, host: good}", true),
            ("x: !custom true", true),
            ("%YAML 1.1\n---\nx: 1", true),
            ("%YAML 1.2\n---\nx: 1", false),
            (r#""\uD834\uDD1E""#, false),
            (r#""\\uD834\\uDD1E""#, true),
        ] {
            assert_eq!(validate(text.as_bytes()).is_ok(), accepted, "{text}");
        }
        for bytes in [
            vec![0xff, 0xfe, b'x', 0, b':', 0, b' ', 0, b'1', 0],
            vec![0xfe, 0xff, 0, b'x', 0, b':', 0, b' ', 0, b'1'],
        ] {
            validate(bytes.as_slice()).unwrap();
        }
    }

    #[test]
    fn alias_budget_counts_expanded_nodes_and_resets_per_document() {
        let document = |references| {
            format!(
                "a: &a [{}]\nb: [{}]\n",
                vec!["0"; 1000].join(","),
                vec!["*a"; references].join(","),
            )
        };
        let accepted = document(110);
        validate(accepted.as_bytes()).unwrap();
        validate(format!("{accepted}---\n{accepted}").as_bytes()).unwrap();
        for references in [111, 200] {
            assert!(validate(document(references).as_bytes()).is_err());
        }
        assert!(validate("[".repeat(10001).as_bytes()).is_err());
    }

    #[test]
    fn aliases_can_expand_beyond_the_parser_nesting_limit() {
        let document = format!(
            "a: &a {}0{}\nb: {}*a{}",
            "[".repeat(6000),
            "]".repeat(6000),
            "[".repeat(6000),
            "]".repeat(6000),
        );
        validate(document.as_bytes()).unwrap();
    }
}
