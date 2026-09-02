use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::confusable::{ConfusableDirection, compare, skeleton};
use crate::index::{assign_graphemes, assign_lines, boundaries, line_endings, raw_code_points};
use crate::index_types::{CodePointEntry, Coordinate, LineEndingCounts, LineEndingItem};
use crate::model::{MAX_TEXT_BYTES, TaggedTextValue, enforce_result_budget, error, invalid_input};
use crate::security_data::{
    BIDI_CONTROL_RANGES, DEFAULT_IGNORABLE_RANGES, FORMAT_CHARACTER_RANGES, SOURCE_MANIFEST_SHA256,
    SOURCE_ROOT, UNICODE_VERSION, UTS39_REVISION,
};

pub(crate) const MAX_DETAIL_ITEMS: usize = 128;
const DEFAULT_DETAIL_ITEMS: usize = 64;
pub(crate) const MAX_SOURCE_SPANS: usize = 128;
const MAX_SCOPE_CHARS: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SpanKind {
    Identifier,
    Token,
}

impl SpanKind {
    fn label(self) -> &'static str {
        match self {
            Self::Identifier => "identifier",
            Self::Token => "token",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SpanInput {
    kind: SpanKind,
    start_utf16: Value,
    end_utf16: Value,
    scope: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Arguments {
    source: TaggedTextValue,
    mode: String,
    spans: Vec<SpanInput>,
    confusable_direction: ConfusableDirection,
    detail_limit: Option<usize>,
}

#[derive(Clone)]
struct SourceSpan {
    index: usize,
    kind: SpanKind,
    scope: Option<String>,
    text: String,
    start: Coordinate,
    end: Coordinate,
}

impl SourceSpan {
    fn json(&self) -> Value {
        let mut value = json!({
            "index": self.index,
            "kind": self.kind.label(),
            "text": self.text,
            "start": self.start,
            "end": self.end
        });
        if let Some(scope) = &self.scope {
            value
                .as_object_mut()
                .expect("source span is an object")
                .insert("scope".into(), json!(scope));
        }
        value
    }
}

fn range_contains(table: &[(u32, u32)], code_point: u32) -> bool {
    table
        .binary_search_by(|(start, end)| {
            if code_point < *start {
                std::cmp::Ordering::Greater
            } else if code_point > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

fn code_point_label(code_point: u32) -> String {
    format!("U+{code_point:04X}")
}

fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_source(value: &TaggedTextValue) -> Result<String, Value> {
    String::from_utf16(&value.tagged.units()).map_err(|_| {
        error(
            "INVALID_UNICODE",
            "source contains an unpaired UTF-16 surrogate.",
            json!({ "field": "source" }),
        )
    })
}

fn validate_span_shape(value: &Value, index: usize) -> Option<Value> {
    let field = format!("spans[{index}]");
    let Some(object) = value.as_object() else {
        return Some(invalid_input(format!("{field} must be an object."), &field));
    };
    let kind = object.get("kind").and_then(Value::as_str);
    if !matches!(kind, Some("identifier" | "token")) {
        return Some(error(
            "INVALID_INPUT",
            format!("{field}.kind must be one of: identifier, token."),
            json!({ "field": format!("{field}.kind"), "allowed": ["identifier", "token"] }),
        ));
    }
    let identifier = kind == Some("identifier");
    let allowed = if identifier {
        ["kind", "startUtf16", "endUtf16", "scope"].as_slice()
    } else {
        ["kind", "startUtf16", "endUtf16"].as_slice()
    };
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return Some(error(
            "INVALID_INPUT",
            "Unknown fields are not allowed.",
            json!({ "unknownFields": unknown }),
        ));
    }
    let required = if identifier {
        ["kind", "startUtf16", "endUtf16", "scope"].as_slice()
    } else {
        ["kind", "startUtf16", "endUtf16"].as_slice()
    };
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|key| !object.contains_key(*key))
        .collect();
    if !missing.is_empty() {
        return Some(error(
            "INVALID_INPUT",
            "Required fields are missing.",
            json!({ "missingFields": missing }),
        ));
    }
    None
}

fn validate_arguments(value: &Value) -> Option<Value> {
    let Some(object) = value.as_object() else {
        return Some(invalid_input("arguments must be an object.", "arguments"));
    };
    let allowed = [
        "source",
        "mode",
        "spans",
        "confusableDirection",
        "detailLimit",
    ];
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return Some(error(
            "INVALID_INPUT",
            "Unknown fields are not allowed.",
            json!({ "unknownFields": unknown }),
        ));
    }
    let required = ["source", "mode", "spans", "confusableDirection"];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|key| !object.contains_key(*key))
        .collect();
    if !missing.is_empty() {
        return Some(error(
            "INVALID_INPUT",
            "Required fields are missing.",
            json!({ "missingFields": missing }),
        ));
    }
    if object.get("mode").and_then(Value::as_str) != Some("source") {
        return Some(invalid_input(
            "mode must be source for source diagnostics.",
            "mode",
        ));
    }
    if !matches!(
        object.get("confusableDirection").and_then(Value::as_str),
        Some("LTR" | "RTL" | "FS")
    ) {
        return Some(error(
            "INVALID_INPUT",
            "confusableDirection must be one of: LTR, RTL, FS.",
            json!({ "field": "confusableDirection", "allowed": ["LTR", "RTL", "FS"] }),
        ));
    }
    if let Some(detail_limit) = object.get("detailLimit") {
        let valid = detail_limit
            .as_u64()
            .is_some_and(|value| value <= MAX_DETAIL_ITEMS as u64);
        if !valid {
            return Some(error(
                "INVALID_INPUT",
                "detailLimit must be an integer from 0 to 128.",
                json!({ "field": "detailLimit", "minimum": 0, "maximum": 128 }),
            ));
        }
    }
    let Some(spans) = object.get("spans").and_then(Value::as_array) else {
        return Some(invalid_input("spans must be an array.", "spans"));
    };
    if spans.len() > MAX_SOURCE_SPANS {
        return Some(error(
            "REQUEST_TOO_LARGE",
            format!("spans exceeds the {MAX_SOURCE_SPANS}-item limit."),
            json!({ "field": "spans", "actualItems": spans.len(), "limitItems": MAX_SOURCE_SPANS }),
        ));
    }
    for (index, span) in spans.iter().enumerate() {
        if let Some(value) = validate_span_shape(span, index) {
            return Some(value);
        }
    }
    None
}

fn validate_spans(
    source: &str,
    boundaries: &BTreeMap<usize, Coordinate>,
    inputs: Vec<SpanInput>,
) -> Result<Vec<SourceSpan>, Value> {
    let max_utf16 = source.encode_utf16().count();
    let mut spans = Vec::with_capacity(inputs.len());
    for (index, input) in inputs.into_iter().enumerate() {
        let field = format!("spans[{index}]");
        let parse_index = |value: &Value, name: &str| -> Result<usize, Value> {
            let Some(index) = value.as_u64().and_then(|value| usize::try_from(value).ok()) else {
                return Err(error(
                    "INVALID_INPUT",
                    format!("{field}.{name} must be an integer from 0 to {max_utf16}."),
                    json!({
                        "field": format!("{field}.{name}"),
                        "minimum": 0,
                        "maximum": max_utf16
                    }),
                ));
            };
            if index > max_utf16 {
                return Err(error(
                    "INVALID_INPUT",
                    format!("{field}.{name} must be an integer from 0 to {max_utf16}."),
                    json!({
                        "field": format!("{field}.{name}"),
                        "minimum": 0,
                        "maximum": max_utf16
                    }),
                ));
            }
            Ok(index)
        };
        let start_utf16 = parse_index(&input.start_utf16, "startUtf16")?;
        let end_utf16 = parse_index(&input.end_utf16, "endUtf16")?;
        if end_utf16 <= start_utf16 {
            return Err(error(
                "INVALID_SPAN",
                format!("{field} must have endUtf16 greater than startUtf16."),
                json!({ "field": field, "startUtf16": start_utf16, "endUtf16": end_utf16 }),
            ));
        }
        let Some(start) = boundaries.get(&start_utf16).cloned() else {
            return Err(error(
                "INVALID_SPAN",
                format!("{field}.startUtf16 must be a Unicode code-point boundary."),
                json!({ "field": format!("{field}.startUtf16"), "indexUtf16": start_utf16 }),
            ));
        };
        let Some(end) = boundaries.get(&end_utf16).cloned() else {
            return Err(error(
                "INVALID_SPAN",
                format!("{field}.endUtf16 must be a Unicode code-point boundary."),
                json!({ "field": format!("{field}.endUtf16"), "indexUtf16": end_utf16 }),
            ));
        };
        let scope = if input.kind == SpanKind::Identifier {
            let scope_value = input.scope.expect("identifier scope shape was validated");
            let Some(scope) = scope_value.as_str() else {
                return Err(error(
                    "INVALID_INPUT",
                    format!("{field}.scope must be a string."),
                    json!({ "field": format!("{field}.scope") }),
                ));
            };
            let scope_utf16 = scope.encode_utf16().count();
            if scope.is_empty() || scope_utf16 > MAX_SCOPE_CHARS {
                return Err(error(
                    "INVALID_INPUT",
                    format!("{field}.scope must contain 1 to {MAX_SCOPE_CHARS} characters."),
                    json!({ "field": format!("{field}.scope") }),
                ));
            }
            Some(scope.to_owned())
        } else {
            None
        };
        spans.push(SourceSpan {
            index,
            kind: input.kind,
            scope,
            text: source[start.utf8_byte..end.utf8_byte].to_owned(),
            start,
            end,
        });
    }
    Ok(spans)
}

pub(crate) fn raw_source_diagnostic_units(arguments: &Value) -> u64 {
    if validate_arguments(arguments).is_some() {
        return 0;
    }
    let args: Arguments = match serde_json::from_value(arguments.clone()) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let source = match decode_source(&args.source) {
        Ok(value) if value.len() <= MAX_TEXT_BYTES => value,
        _ => return 0,
    };
    let detail_limit = args.detail_limit.unwrap_or(DEFAULT_DETAIL_ITEMS);
    let mut code_points = raw_code_points(&source);
    let graphemes = assign_graphemes(&source, &mut code_points);
    let final_line = assign_lines(&mut code_points);
    let boundary_map = boundaries(&source, &code_points, graphemes.len(), final_line);
    let spans = match validate_spans(&source, &boundary_map, args.spans) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let identifiers: Vec<&SourceSpan> = spans
        .iter()
        .filter(|span| span.kind == SpanKind::Identifier)
        .collect();
    let mut units = source.encode_utf16().count() as u64;
    units += identifiers
        .iter()
        .map(|span| span.text.encode_utf16().count() as u64)
        .sum::<u64>();

    let mut possible_pair_units = Vec::new();
    for left_index in 0..identifiers.len() {
        for right_index in left_index + 1..identifiers.len() {
            let left = identifiers[left_index];
            let right = identifiers[right_index];
            if left.scope == right.scope {
                possible_pair_units.push(
                    (left.text.encode_utf16().count() + right.text.encode_utf16().count()) as u64,
                );
            }
        }
    }
    possible_pair_units.sort_unstable_by(|left, right| right.cmp(left));
    units
        + possible_pair_units
            .into_iter()
            .take(detail_limit)
            .sum::<u64>()
}

fn covering_spans(spans: &[SourceSpan], index_utf16: usize) -> Vec<usize> {
    spans
        .iter()
        .filter(|span| {
            span.start.utf16_code_unit <= index_utf16 && span.end.utf16_code_unit > index_utf16
        })
        .map(|span| span.index)
        .collect()
}

fn hidden_character_diagnostics(
    entries: &[CodePointEntry],
    spans: &[SourceSpan],
    detail_limit: usize,
) -> Value {
    let mut count = 0usize;
    let mut items = Vec::new();
    for entry in entries {
        let code_point = entry.character.chars().next().expect("code point entry") as u32;
        let mut signal_kinds = Vec::new();
        if range_contains(BIDI_CONTROL_RANGES, code_point) {
            signal_kinds.push("bidi_control");
        }
        if range_contains(DEFAULT_IGNORABLE_RANGES, code_point) {
            signal_kinds.push("default_ignorable");
        }
        if range_contains(FORMAT_CHARACTER_RANGES, code_point) {
            signal_kinds.push("format_character");
        }
        if signal_kinds.is_empty() {
            continue;
        }
        count += 1;
        if items.len() < detail_limit {
            items.push(json!({
                "codePoint": code_point_label(code_point),
                "character": entry.character,
                "signalKinds": signal_kinds,
                "position": entry.start,
                "coveringSpanIndexes": covering_spans(spans, entry.start.utf16_code_unit)
            }));
        }
    }
    json!({ "count": count, "items": items, "truncated": count > items.len() })
}

fn abnormal_line_endings(entries: &[CodePointEntry], detail_limit: usize) -> Value {
    let observations = line_endings(entries, detail_limit);
    let LineEndingCounts {
        crlf,
        lf,
        cr,
        nel,
        line_separator,
        paragraph_separator,
    } = observations.counts.clone();
    let count = cr + nel + line_separator + paragraph_separator;
    let items: Vec<LineEndingItem> = observations
        .items
        .into_iter()
        .filter(|item| {
            matches!(
                item.kind,
                "cr" | "nel" | "lineSeparator" | "paragraphSeparator"
            )
        })
        .collect();
    json!({
        "count": count,
        "items": items,
        "truncated": count > items.len(),
        "allCounts": {
            "crlf": crlf,
            "lf": lf,
            "cr": cr,
            "nel": nel,
            "lineSeparator": line_separator,
            "paragraphSeparator": paragraph_separator
        }
    })
}

struct EnrichedIdentifier<'a> {
    span: &'a SourceSpan,
    skeleton: String,
    skeleton_sha256: String,
}

fn confusable_identifier_diagnostics(
    identifiers: &[&SourceSpan],
    direction: ConfusableDirection,
    detail_limit: usize,
) -> Value {
    let enriched: Vec<EnrichedIdentifier<'_>> = identifiers
        .iter()
        .map(|span| {
            let value = skeleton(&span.text, direction.bidi()).0;
            EnrichedIdentifier {
                span,
                skeleton_sha256: sha256(&value),
                skeleton: value,
            }
        })
        .collect();
    let mut buckets: Vec<(String, Vec<&EnrichedIdentifier<'_>>)> = Vec::new();
    for identifier in &enriched {
        let key = format!(
            "{}\0{}",
            identifier.span.scope.as_deref().expect("identifier scope"),
            identifier.skeleton_sha256
        );
        if let Some((_, bucket)) = buckets
            .iter_mut()
            .find(|(bucket_key, _)| *bucket_key == key)
        {
            bucket.push(identifier);
        } else {
            buckets.push((key, vec![identifier]));
        }
    }

    let mut count = 0usize;
    let mut pairs = Vec::new();
    for (_, bucket) in buckets {
        for left_index in 0..bucket.len() {
            for right_index in left_index + 1..bucket.len() {
                let left = bucket[left_index];
                let right = bucket[right_index];
                if left.skeleton != right.skeleton || left.span.text == right.span.text {
                    continue;
                }
                count += 1;
                if pairs.len() < detail_limit {
                    let relation = compare(&left.span.text, &right.span.text, direction);
                    pairs.push(json!({
                        "scope": left.span.scope,
                        "leftSpanIndex": left.span.index,
                        "rightSpanIndex": right.span.index,
                        "leftText": left.span.text,
                        "rightText": right.span.text,
                        "relation": relation["relation"],
                        "confusableClass": relation["confusableClass"],
                        "skeletonSha256": left.skeleton_sha256
                    }));
                }
            }
        }
    }
    json!({ "count": count, "pairs": pairs, "truncated": count > pairs.len() })
}

pub fn run(arguments: Value) -> Value {
    if let Some(value) = validate_arguments(&arguments) {
        return value;
    }
    let args: Arguments = match serde_json::from_value(arguments) {
        Ok(value) => value,
        Err(_) => {
            return invalid_input(
                "arguments do not match the closed source-diagnostics request.",
                "arguments",
            );
        }
    };
    if args.mode != "source" {
        return invalid_input("mode must be source for source diagnostics.", "mode");
    }
    let source = match decode_source(&args.source) {
        Ok(value) => value,
        Err(value) => return value,
    };
    if source.len() > MAX_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!("source exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({ "field": "source", "actualBytes": source.len(), "limitBytes": MAX_TEXT_BYTES }),
        );
    }
    let detail_limit = args.detail_limit.unwrap_or(DEFAULT_DETAIL_ITEMS);
    let mut code_points = raw_code_points(&source);
    let graphemes = assign_graphemes(&source, &mut code_points);
    let final_line = assign_lines(&mut code_points);
    let boundary_map = boundaries(&source, &code_points, graphemes.len(), final_line);
    let spans = match validate_spans(&source, &boundary_map, args.spans) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let identifiers: Vec<&SourceSpan> = spans
        .iter()
        .filter(|span| span.kind == SpanKind::Identifier)
        .collect();

    let mut data = Map::new();
    data.insert("unicodeVersion".into(), json!(UNICODE_VERSION));
    data.insert("uts39Revision".into(), json!(UTS39_REVISION));
    data.insert("sourceRoot".into(), json!(SOURCE_ROOT));
    data.insert("license".into(), json!("Unicode License V3"));
    data.insert("manifestSha256".into(), json!(SOURCE_MANIFEST_SHA256));
    data.insert("offline".into(), json!(true));
    data.insert("uts55Revision".into(), json!(5));

    let result = json!({
        "status": "ok",
        "operation": "source_diagnose",
        "mode": "source",
        "claimScope": "uts55_diagnostics_over_explicit_source_and_host_spans",
        "data": data,
        "spans": {
            "count": spans.len(),
            "identifiers": identifiers.len(),
            "items": spans.iter().map(SourceSpan::json).collect::<Vec<_>>()
        },
        "diagnostics": {
            "hiddenCharacters": hidden_character_diagnostics(&code_points, &spans, detail_limit),
            "abnormalLineEndings": abnormal_line_endings(&code_points, detail_limit),
            "confusableIdentifiers": confusable_identifier_diagnostics(
                &identifiers,
                args.confusable_direction,
                detail_limit
            )
        },
        "limitations": [
            "The caller, not this operation, supplies token, identifier, and scope boundaries.",
            "Diagnostics are representation facts and UTS #55 relations; they are not a maliciousness or code-correctness verdict.",
            "No file, workspace, parser, compiler, or rendering context is accessed."
        ]
    });
    enforce_result_budget(result)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::run;

    fn tagged(value: &str) -> Value {
        json!({ "$text": { "kind": "unicode_scalar_string", "value": value } })
    }

    #[test]
    fn reports_only_explicit_host_span_relations() {
        let result = run(json!({
            "source": tagged("let pаypal = paypal;\r\u{202e}"),
            "mode": "source",
            "spans": [
                { "kind": "identifier", "startUtf16": 4, "endUtf16": 10, "scope": "file" },
                { "kind": "identifier", "startUtf16": 13, "endUtf16": 19, "scope": "file" }
            ],
            "confusableDirection": "LTR",
            "detailLimit": 8
        }));
        assert_eq!(result["operation"], "source_diagnose");
        assert_eq!(result["diagnostics"]["confusableIdentifiers"]["count"], 1);
        assert_eq!(result["diagnostics"]["abnormalLineEndings"]["count"], 1);
        assert_eq!(result["diagnostics"]["hiddenCharacters"]["count"], 1);
    }

    #[test]
    fn rejects_a_surrogate_interior_coordinate() {
        let result = run(json!({
            "source": tagged("😀"),
            "mode": "source",
            "spans": [{ "kind": "token", "startUtf16": 1, "endUtf16": 2 }],
            "confusableDirection": "LTR"
        }));
        assert_eq!(result["error"]["code"], "INVALID_SPAN");
    }
}
