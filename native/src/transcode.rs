use serde_json::{Map, Value, json};

use crate::model::{MAX_BYTE_INPUT, MAX_TEXT_BYTES, enforce_result_budget, error};
use crate::transcode_decode::{
    RawSegment, base64, bom_kind, decoded_text, encode_text, utf8_segments, utf16_segments,
    utf16le_segments,
};
use crate::validation::{
    assert_keys, require_boolean, require_bytes, require_encoding, require_enum, require_object,
    require_tagged_units, utf8_length_from_units,
};

fn witness(
    mode: &str,
    source_unit: &str,
    bom: Option<&str>,
    segments: &[RawSegment],
    target_encoding: &str,
) -> Value {
    let mut decoded_utf16 = 0;
    let mut target_byte = 0;
    let decorated: Vec<Value> = segments
        .iter()
        .map(|segment| {
            let character = char::from_u32(segment.code_point).expect("valid scalar");
            let decoded_end = decoded_utf16 + character.len_utf16();
            let target_end =
                target_byte + encode_text(&character.to_string(), target_encoding).len();
            let value = json!({
                "kind": if segment.replacement { "replacement" } else { "scalar" },
                "codePoint": format!("U+{:04X}", segment.code_point),
                "sourceStart": segment.source_start,
                "sourceEnd": segment.source_end,
                "decodedStartUtf16": decoded_utf16,
                "decodedEndUtf16": decoded_end,
                "targetStartByte": target_byte,
                "targetEndByte": target_end
            });
            decoded_utf16 = decoded_end;
            target_byte = target_end;
            value
        })
        .collect();

    let mut value = Map::from_iter([
        ("mode".into(), json!(mode)),
        ("sourceUnit".into(), json!(source_unit)),
        ("segmentCount".into(), json!(segments.len())),
        (
            "replacementCount".into(),
            json!(
                segments
                    .iter()
                    .filter(|segment| segment.replacement)
                    .count()
            ),
        ),
        (
            "bom".into(),
            json!({
                "kind": bom,
                "handling": if source_unit == "utf16_code_unit" {
                    "not_applicable"
                } else if bom.is_some() {
                    "preserved_as_character"
                } else {
                    "not_present"
                }
            }),
        ),
    ]);
    if mode == "full_required" {
        value.insert("segments".into(), Value::Array(decorated));
    }
    Value::Object(value)
}

pub fn transcode(arguments: Value) -> Value {
    let object = match require_object(&arguments, "arguments") {
        Ok(value) => value,
        Err(value) => return value,
    };
    let source_kind = match require_enum(object.get("sourceKind"), "sourceKind", &["text", "bytes"])
    {
        Ok(value) => value,
        Err(value) => return value,
    };
    let target_encoding = match require_encoding(object.get("targetEncoding"), "targetEncoding") {
        Ok(value) => value,
        Err(value) => return value,
    };
    let allow_lossy = match require_boolean(object.get("allowLossy"), "allowLossy") {
        Ok(value) => value,
        Err(value) => return value,
    };
    let byte_representation = match require_enum(
        object.get("byteRepresentation"),
        "byteRepresentation",
        &["bytes", "hex", "base64"],
    ) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let witness_mode = if object.contains_key("witnessMode") {
        match require_enum(
            object.get("witnessMode"),
            "witnessMode",
            &["none", "summary", "full_required"],
        ) {
            Ok(value) => value,
            Err(value) => return value,
        }
    } else {
        "none".to_owned()
    };

    let (segments, source, source_unit, bom, lossy, warnings) = if source_kind == "bytes" {
        if let Err(value) = assert_keys(
            object,
            &[
                "sourceKind",
                "bytes",
                "sourceEncoding",
                "targetEncoding",
                "allowLossy",
                "byteRepresentation",
                "witnessMode",
            ],
            &[
                "sourceKind",
                "bytes",
                "sourceEncoding",
                "targetEncoding",
                "allowLossy",
                "byteRepresentation",
            ],
        ) {
            return value;
        }
        let source_encoding = match require_encoding(object.get("sourceEncoding"), "sourceEncoding")
        {
            Ok(value) => value,
            Err(value) => return value,
        };
        let bytes = match require_bytes(object.get("bytes"), "bytes", MAX_BYTE_INPUT) {
            Ok(value) => value,
            Err(value) => return value,
        };
        let segments = if source_encoding == "utf-8" {
            utf8_segments(&bytes)
        } else {
            utf16le_segments(&bytes)
        };
        let first_invalid = segments
            .iter()
            .find(|segment| segment.replacement)
            .map(|segment| segment.source_start);
        if let Some(first_invalid_byte) = first_invalid {
            if !allow_lossy {
                return error(
                    "DECODE_FAILED",
                    format!("bytes are not valid {source_encoding}."),
                    json!({ "encoding": source_encoding, "firstInvalidByte": first_invalid_byte }),
                );
            }
        }
        let text = decoded_text(&segments);
        let source_bom = bom_kind(&bytes, &source_encoding);
        let exact_round_trip =
            first_invalid.is_none() && encode_text(&text, &source_encoding) == bytes;
        let source = json!({
            "kind": "bytes",
            "encoding": source_encoding,
            "byteLength": bytes.len(),
            "bom": source_bom,
            "firstInvalidByte": first_invalid,
            "decodedThenReencodedEqual": exact_round_trip
        });
        let warnings = if first_invalid.is_some() {
            vec!["Invalid source byte sequences were replaced with U+FFFD during decoding."]
        } else {
            Vec::new()
        };
        (
            segments,
            source,
            "byte",
            source_bom,
            first_invalid.is_some(),
            warnings,
        )
    } else {
        if let Err(value) = assert_keys(
            object,
            &[
                "sourceKind",
                "text",
                "targetEncoding",
                "allowLossy",
                "byteRepresentation",
                "witnessMode",
            ],
            &[
                "sourceKind",
                "text",
                "targetEncoding",
                "allowLossy",
                "byteRepresentation",
            ],
        ) {
            return value;
        }
        let units = match require_tagged_units(object.get("text"), "text") {
            Ok(value) => value,
            Err(value) => return value,
        };
        let actual_bytes = utf8_length_from_units(&units);
        if actual_bytes > MAX_TEXT_BYTES {
            return error(
                "REQUEST_TOO_LARGE",
                format!("text exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
                json!({ "field": "text", "actualBytes": actual_bytes, "limitBytes": MAX_TEXT_BYTES }),
            );
        }
        let segments = utf16_segments(&units);
        let well_formed = segments.iter().all(|segment| !segment.replacement);
        if !well_formed && !allow_lossy {
            return error(
                "INVALID_UNICODE",
                "text contains an unpaired UTF-16 surrogate.",
                json!({ "field": "text" }),
            );
        }
        let warnings = if well_formed {
            Vec::new()
        } else {
            vec!["Unpaired UTF-16 surrogates were replaced with U+FFFD before encoding."]
        };
        (
            segments,
            json!({ "kind": "text", "inputWellFormed": well_formed }),
            "utf16_code_unit",
            None,
            !well_formed,
            warnings,
        )
    };

    let text = decoded_text(&segments);
    let encoded = encode_text(&text, &target_encoding);
    let mut result = Map::from_iter([
        ("status".into(), json!("ok")),
        ("operation".into(), json!("transcode")),
        ("source".into(), source),
        ("targetEncoding".into(), json!(target_encoding)),
        ("byteRepresentation".into(), json!(byte_representation)),
        ("text".into(), json!(text)),
        ("byteLength".into(), json!(encoded.len())),
        ("lossy".into(), json!(lossy)),
        ("warnings".into(), json!(warnings)),
    ]);
    match byte_representation.as_str() {
        "bytes" => {
            result.insert("bytes".into(), json!(encoded));
        }
        "hex" => {
            result.insert(
                "hex".into(),
                json!(
                    encoded
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                ),
            );
        }
        "base64" => {
            result.insert("base64".into(), json!(base64(&encoded)));
        }
        _ => unreachable!(),
    }
    if witness_mode != "none" {
        result.insert(
            "witness".into(),
            witness(&witness_mode, source_unit, bom, &segments, &target_encoding),
        );
    }
    let result = Value::Object(result);
    enforce_result_budget(result)
}
