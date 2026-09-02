use serde::Deserialize;
use serde_json::{Value, json};
use unicode_normalization::{UNICODE_VERSION as ENGINE_UNICODE_VERSION, UnicodeNormalization};

use crate::model::{MAX_RESULT_BYTES, MAX_TEXT_BYTES, TaggedTextValue, error, invalid_input};
use crate::uts39_skeleton_data::{
    CONFUSABLE_MAPPING_ROW_COUNT, CONFUSABLE_MAPPINGS, CONFUSABLES_SOURCE_PATH,
    CONFUSABLES_SOURCE_SHA256, DEFAULT_IGNORABLE_CODE_POINT_COUNT, DEFAULT_IGNORABLE_RANGE_COUNT,
    DEFAULT_IGNORABLE_RANGES, DERIVED_CORE_SOURCE_PATH, DERIVED_CORE_SOURCE_SHA256,
    SOURCE_MANIFEST_SHA256, UNICODE_VERSION, UTS39_REVISION,
};

const ENGINE: &str = "rust-unicode-normalization@0.1.25";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    text: TaggedTextValue,
}

fn confusable_mapping(code_point: u32) -> Option<&'static str> {
    CONFUSABLE_MAPPINGS
        .binary_search_by_key(&code_point, |(source, _)| *source)
        .ok()
        .map(|index| CONFUSABLE_MAPPINGS[index].1)
}

fn is_default_ignorable(code_point: u32) -> bool {
    let mut low = 0usize;
    let mut high = DEFAULT_IGNORABLE_RANGES.len();
    while low < high {
        let middle = low + (high - low) / 2;
        let (start, end) = DEFAULT_IGNORABLE_RANGES[middle];
        if code_point < start {
            high = middle;
        } else if code_point > end {
            low = middle + 1;
        } else {
            return true;
        }
    }
    false
}

pub(crate) fn apply(value: &str) -> String {
    debug_assert_eq!(ENGINE_UNICODE_VERSION, (17, 0, 0));
    let mut mapped = String::with_capacity(value.len());
    for character in value.nfd() {
        let code_point = character as u32;
        if is_default_ignorable(code_point) {
            continue;
        }
        if let Some(replacement) = confusable_mapping(code_point) {
            mapped.push_str(replacement);
        } else {
            mapped.push(character);
        }
    }
    mapped.nfd().collect()
}

pub fn run(arguments: Value) -> Value {
    let args: Arguments = match serde_json::from_value(arguments) {
        Ok(value) => value,
        Err(_) => {
            return invalid_input(
                "arguments do not match the closed reference UTS #39 post-reorder skeleton request.",
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
    let skeleton = apply(&original);
    let result = json!({
        "status": "ok",
        "operation": "reference_uts39_post_reorder_skeleton",
        "original": original,
        "skeleton": skeleton,
        "changed": original != skeleton,
        "engine": ENGINE,
        "standards": {
            "specification": "Unicode Technical Standard #39",
            "unicodeVersion": UNICODE_VERSION,
            "uts39Revision": UTS39_REVISION,
            "stage": "post_reorder_internal_skeleton",
            "source": {
                "manifestSha256": SOURCE_MANIFEST_SHA256,
                "confusables": {
                    "path": CONFUSABLES_SOURCE_PATH,
                    "sha256": CONFUSABLES_SOURCE_SHA256,
                    "mappingRowCount": CONFUSABLE_MAPPING_ROW_COUNT
                },
                "defaultIgnorable": {
                    "path": DERIVED_CORE_SOURCE_PATH,
                    "sha256": DERIVED_CORE_SOURCE_SHA256,
                    "rangeCount": DEFAULT_IGNORABLE_RANGE_COUNT,
                    "codePointCount": DEFAULT_IGNORABLE_CODE_POINT_COUNT
                }
            }
        }
    });
    let actual_bytes = serde_json::to_vec(&result)
        .expect("reference UTS #39 skeleton result serializes")
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

    use super::{apply, confusable_mapping, is_default_ignorable, run};
    use crate::uts39_skeleton_data::{
        CONFUSABLE_MAPPING_ROW_COUNT, DEFAULT_IGNORABLE_CODE_POINT_COUNT,
        DEFAULT_IGNORABLE_RANGE_COUNT,
    };

    #[test]
    fn applies_the_declared_post_reorder_stage_order() {
        assert_eq!(apply("pаypal"), "paypal");
        assert_eq!(apply("☝\u{fe0f}"), apply("☝"));
        assert_eq!(apply("\u{3164}"), "");
        assert_eq!(apply("é"), "e\u{301}");
    }

    #[test]
    fn generated_tables_keep_mapping_and_removal_distinct() {
        assert_eq!(confusable_mapping(0x0030), Some("O"));
        assert_eq!(confusable_mapping(0x3164), Some("\u{1160}"));
        assert!(is_default_ignorable(0x3164));
        assert!(!is_default_ignorable(0x3165));
        assert_eq!(CONFUSABLE_MAPPING_ROW_COUNT, 6565);
        assert_eq!(DEFAULT_IGNORABLE_RANGE_COUNT, 27);
        assert_eq!(DEFAULT_IGNORABLE_CODE_POINT_COUNT, 4174);
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
