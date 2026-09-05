use serde::Deserialize;
use serde_json::{Value, json};
use unicode_normalization::{UNICODE_VERSION as ENGINE_UNICODE_VERSION, UnicodeNormalization};

use crate::model::{MAX_RESULT_BYTES, MAX_TEXT_BYTES, TaggedTextValue, error, invalid_input};
use crate::nfkc_casefold_data::{
    MAPPED_CODE_POINT_COUNT, MAPPING_PROPERTY, MAPPING_ROW_COUNT, NFKC_CASEFOLD_RANGES,
    SOURCE_FILE_PATH, SOURCE_FILE_SHA256, SOURCE_MANIFEST_SHA256, UNICODE_VERSION,
};

const ENGINE: &str = "rust-unicode-normalization@0.1.25";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    text: TaggedTextValue,
}

fn mapping_for(code_point: u32) -> Option<&'static str> {
    let mut low = 0usize;
    let mut high = NFKC_CASEFOLD_RANGES.len();
    while low < high {
        let middle = low + (high - low) / 2;
        let (start, end, mapping) = NFKC_CASEFOLD_RANGES[middle];
        if code_point < start {
            high = middle;
        } else if code_point > end {
            low = middle + 1;
        } else {
            return Some(mapping);
        }
    }
    None
}

pub(crate) fn apply(value: &str) -> String {
    debug_assert_eq!(ENGINE_UNICODE_VERSION, (17, 0, 0));
    let mut mapped = String::with_capacity(value.len());
    for character in value.chars() {
        if let Some(replacement) = mapping_for(character as u32) {
            mapped.push_str(replacement);
        } else {
            mapped.push(character);
        }
    }
    mapped.nfc().collect()
}

pub fn run(arguments: Value) -> Value {
    let args: Arguments = match serde_json::from_value(arguments) {
        Ok(value) => value,
        Err(_) => {
            return invalid_input(
                "arguments do not match the closed reference NFKC_Casefold request.",
                "arguments",
            );
        }
    };
    let units = args.text.tagged.units();
    let original = match String::from_utf16(&units) {
        Ok(value) => value,
        Err(_) => {
            return error(
                "INVALID_UNICODE",
                "text contains an unpaired UTF-16 surrogate.",
                json!({ "field": "text" }),
            );
        }
    };
    if original.len() > MAX_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!("text exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({ "field": "text", "actualBytes": original.len(), "limitBytes": MAX_TEXT_BYTES }),
        );
    }
    let transformed = apply(&original);
    let result = json!({
        "status": "ok",
        "operation": "reference_nfkc_casefold",
        "original": original,
        "transformed": transformed,
        "changed": original != transformed,
        "engine": ENGINE,
        "standards": {
            "specification": "Unicode Standard Annex #15",
            "unicodeVersion": UNICODE_VERSION,
            "mappingProperty": MAPPING_PROPERTY,
            "source": {
                "manifestSha256": SOURCE_MANIFEST_SHA256,
                "path": SOURCE_FILE_PATH,
                "sha256": SOURCE_FILE_SHA256,
                "mappingRowCount": MAPPING_ROW_COUNT,
                "mappedCodePointCount": MAPPED_CODE_POINT_COUNT
            }
        }
    });
    let actual_bytes = serde_json::to_vec(&result)
        .expect("reference NFKC_Casefold result serializes")
        .len();
    if actual_bytes > MAX_RESULT_BYTES {
        return error(
            "RESULT_TOO_LARGE",
            format!("The complete result exceeds the {MAX_RESULT_BYTES}-byte limit."),
            json!({ "actualBytes": actual_bytes, "limitBytes": MAX_RESULT_BYTES }),
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{apply, mapping_for, run};
    use crate::nfkc_casefold_data::{MAPPED_CODE_POINT_COUNT, MAPPING_ROW_COUNT};

    #[test]
    fn applies_mapping_then_unicode_17_nfc() {
        assert_eq!(apply("Straße"), "strasse");
        assert_eq!(apply("A\u{30a}"), "å");
        assert_eq!(apply("\u{ad}"), "");
        assert_eq!(apply("\u{212b}"), "å");
    }

    #[test]
    fn lookup_distinguishes_empty_mapping_from_identity() {
        assert_eq!(mapping_for(0x00ad), Some(""));
        assert_eq!(mapping_for(0x0040), None);
        assert_eq!(MAPPING_ROW_COUNT, 6183);
        assert_eq!(MAPPED_CODE_POINT_COUNT, 10583);
    }

    #[test]
    fn rejects_unknown_fields_before_execution() {
        let result = run(json!({
            "text": { "$text": { "kind": "unicode_scalar_string", "value": "A" } },
            "extra": true
        }));
        assert_eq!(result["status"], "error");
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
    }
}
