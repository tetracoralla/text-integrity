use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};
use unicode_segmentation::{UNICODE_VERSION, UnicodeSegmentation};

use crate::model::{MAX_TEXT_BYTES, error, result_budget_error};
use crate::validation::{
    assert_keys, require_integer, require_object, require_tagged_units, utf8_length_from_units,
};

const DEFAULT_DETAIL_ITEMS: usize = 64;
const MAX_DETAIL_ITEMS: usize = 128;

#[derive(Clone, Debug)]
struct CodePointSegment {
    code_point: u32,
    source_start: usize,
    source_end: usize,
    unpaired: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Counts {
    utf16_code_units: usize,
    code_points: usize,
    graphemes: usize,
    utf8_bytes: Option<usize>,
    utf16le_bytes: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EncodingObservation {
    well_formed: bool,
    byte_length: Option<usize>,
    hex: Option<String>,
}

#[derive(Serialize)]
struct Encodings {
    utf8: EncodingObservation,
    utf16le: EncodingObservation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CodePointDetail {
    index_code_unit: usize,
    value: String,
    character: Box<RawValue>,
    kind: &'static str,
    utf8_hex: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GraphemeDetail {
    index_code_unit: usize,
    text: Box<RawValue>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Detail {
    limit: usize,
    code_points: Vec<CodePointDetail>,
    code_points_truncated: bool,
    graphemes: Vec<GraphemeDetail>,
    graphemes_truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InspectResult {
    status: &'static str,
    operation: &'static str,
    input_well_formed: bool,
    counts: Counts,
    encodings: Encodings,
    detail: Detail,
}

fn code_point_segments(units: &[u16]) -> Vec<CodePointSegment> {
    let mut segments = Vec::new();
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xd800..=0xdbff).contains(&unit) {
            if let Some(&next) = units.get(index + 1) {
                if (0xdc00..=0xdfff).contains(&next) {
                    segments.push(CodePointSegment {
                        code_point: 0x10000
                            + (((unit as u32) - 0xd800) << 10)
                            + ((next as u32) - 0xdc00),
                        source_start: index,
                        source_end: index + 2,
                        unpaired: false,
                    });
                    index += 2;
                    continue;
                }
            }
            segments.push(CodePointSegment {
                code_point: unit.into(),
                source_start: index,
                source_end: index + 1,
                unpaired: true,
            });
            index += 1;
            continue;
        }
        segments.push(CodePointSegment {
            code_point: unit.into(),
            source_start: index,
            source_end: index + 1,
            unpaired: (0xdc00..=0xdfff).contains(&unit),
        });
        index += 1;
    }
    segments
}

fn raw_json_string(units: &[u16]) -> Box<RawValue> {
    let mut value = String::from("\"");
    for unit in units {
        match unit {
            0x08 => value.push_str("\\b"),
            0x09 => value.push_str("\\t"),
            0x0a => value.push_str("\\n"),
            0x0c => value.push_str("\\f"),
            0x0d => value.push_str("\\r"),
            0x22 => value.push_str("\\\""),
            0x5c => value.push_str("\\\\"),
            0x20..=0x7e => value.push(char::from_u32((*unit).into()).expect("ASCII scalar")),
            _ => value.push_str(&format!("\\u{unit:04x}")),
        }
    }
    value.push('"');
    RawValue::from_string(value).expect("escaped UTF-16 is valid JSON")
}

fn hex(bytes: impl IntoIterator<Item = u8>) -> String {
    bytes
        .into_iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn utf16le_hex(units: &[u16]) -> String {
    hex(units.iter().flat_map(|unit| unit.to_le_bytes()))
}

fn grapheme_ranges(units: &[u16], segments: &[CodePointSegment]) -> Vec<(usize, usize)> {
    debug_assert_eq!(UNICODE_VERSION, (17, 0, 0));
    let mut shadow = String::new();
    let mut byte_to_utf16 = BTreeMap::new();
    for segment in segments {
        byte_to_utf16.insert(shadow.len(), segment.source_start);
        shadow.push(if segment.unpaired {
            '\u{e000}'
        } else {
            char::from_u32(segment.code_point).expect("paired segment is a scalar")
        });
    }
    byte_to_utf16.insert(shadow.len(), units.len());
    let mut starts: Vec<usize> = shadow
        .grapheme_indices(true)
        .map(|(byte_index, _)| {
            *byte_to_utf16
                .get(&byte_index)
                .expect("grapheme starts at a scalar")
        })
        .collect();
    if !starts.is_empty() {
        starts.push(units.len());
    }
    starts
        .windows(2)
        .map(|window| (window[0], window[1]))
        .collect()
}

fn serialized_error(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("error serializes")
}

pub fn inspect(arguments: Value) -> Vec<u8> {
    let object = match require_object(&arguments, "arguments") {
        Ok(value) => value,
        Err(value) => return serialized_error(value),
    };
    if let Err(value) = assert_keys(object, &["text", "detailLimit"], &["text"]) {
        return serialized_error(value);
    }
    let units = match require_tagged_units(object.get("text"), "text") {
        Ok(value) => value,
        Err(value) => return serialized_error(value),
    };
    let actual_bytes = utf8_length_from_units(&units);
    if actual_bytes > MAX_TEXT_BYTES {
        return serialized_error(error(
            "REQUEST_TOO_LARGE",
            format!("text exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({ "field": "text", "actualBytes": actual_bytes, "limitBytes": MAX_TEXT_BYTES }),
        ));
    }
    let detail_limit = if object.contains_key("detailLimit") {
        match require_integer(
            object.get("detailLimit"),
            "detailLimit",
            0,
            MAX_DETAIL_ITEMS,
        ) {
            Ok(value) => value,
            Err(value) => return serialized_error(value),
        }
    } else {
        DEFAULT_DETAIL_ITEMS
    };
    let segments = code_point_segments(&units);
    let input_well_formed = segments.iter().all(|segment| !segment.unpaired);
    let lossy_text: String = segments
        .iter()
        .map(|segment| {
            if segment.unpaired {
                '\u{fffd}'
            } else {
                char::from_u32(segment.code_point).expect("valid scalar")
            }
        })
        .collect();
    let grapheme_ranges = grapheme_ranges(&units, &segments);
    let code_points: Vec<CodePointDetail> = segments
        .iter()
        .take(detail_limit)
        .map(|segment| {
            let utf8_hex = if segment.unpaired {
                None
            } else {
                Some(hex(char::from_u32(segment.code_point)
                    .expect("valid scalar")
                    .to_string()
                    .bytes()))
            };
            CodePointDetail {
                index_code_unit: segment.source_start,
                value: format!("U+{:04X}", segment.code_point),
                character: raw_json_string(&units[segment.source_start..segment.source_end]),
                kind: if segment.unpaired {
                    "unpaired_surrogate"
                } else {
                    "scalar"
                },
                utf8_hex,
            }
        })
        .collect();
    let graphemes: Vec<GraphemeDetail> = grapheme_ranges
        .iter()
        .take(detail_limit)
        .map(|(start, end)| GraphemeDetail {
            index_code_unit: *start,
            text: raw_json_string(&units[*start..*end]),
        })
        .collect();
    let utf8_bytes = input_well_formed.then_some(lossy_text.len());
    let utf8_hex = input_well_formed.then(|| hex(lossy_text.bytes()));
    let result = InspectResult {
        status: "ok",
        operation: "inspect",
        input_well_formed,
        counts: Counts {
            utf16_code_units: units.len(),
            code_points: segments.len(),
            graphemes: grapheme_ranges.len(),
            utf8_bytes,
            utf16le_bytes: units.len() * 2,
        },
        encodings: Encodings {
            utf8: EncodingObservation {
                well_formed: input_well_formed,
                byte_length: utf8_bytes,
                hex: utf8_hex,
            },
            utf16le: EncodingObservation {
                well_formed: input_well_formed,
                byte_length: Some(units.len() * 2),
                hex: Some(utf16le_hex(&units)),
            },
        },
        detail: Detail {
            limit: detail_limit,
            code_points_truncated: segments.len() > code_points.len(),
            code_points,
            graphemes_truncated: grapheme_ranges.len() > graphemes.len(),
            graphemes,
        },
    };
    let output = serde_json::to_vec(&result).expect("inspect result serializes");
    if let Some(value) = result_budget_error(output.len(), output.len()) {
        return serialized_error(value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::raw_json_string;

    #[test]
    fn raw_json_preserves_unpaired_utf16_units() {
        assert_eq!(raw_json_string(&[0xd800]).get(), "\"\\ud800\"");
    }
}
