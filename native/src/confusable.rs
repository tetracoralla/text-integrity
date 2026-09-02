use std::collections::BTreeSet;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::bidi_reorder::{Direction, resolve};
use crate::model::{MAX_RESULT_BYTES, MAX_TEXT_BYTES, TaggedTextValue, error, invalid_input};
use crate::script_data::{
    PROPERTY_ALIASES_SOURCE_PATH, PROPERTY_ALIASES_SOURCE_SHA256, SCRIPT_EXTENSIONS_RANGE_COUNT,
    SCRIPT_EXTENSIONS_RANGES, SCRIPT_EXTENSIONS_SOURCE_PATH, SCRIPT_EXTENSIONS_SOURCE_SHA256,
    SCRIPT_RANGE_COUNT, SCRIPT_RANGES, SCRIPTS_SOURCE_PATH, SCRIPTS_SOURCE_SHA256,
    SOURCE_MANIFEST_SHA256, UNICODE_VERSION,
};
use crate::uts39_skeleton;

const MAX_COMBINED_TEXT_BYTES: usize = 4096;
const ENGINE: &str = "rust-unicode-bidi@0.3.18+text-integrity-unicode17-data";

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) enum ConfusableDirection {
    #[serde(rename = "LTR")]
    Ltr,
    #[serde(rename = "RTL")]
    Rtl,
    #[serde(rename = "FS")]
    FirstStrong,
}

impl ConfusableDirection {
    pub(crate) fn bidi(self) -> Direction {
        match self {
            Self::Ltr => Direction::Ltr,
            Self::Rtl => Direction::Rtl,
            Self::FirstStrong => Direction::FirstStrong,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ltr => "LTR",
            Self::Rtl => "RTL",
            Self::FirstStrong => "FS",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    text: TaggedTextValue,
    comparison: TaggedTextValue,
    direction: ConfusableDirection,
}

fn range_str(table: &[(u32, u32, &'static str)], code_point: u32) -> Option<&'static str> {
    table
        .binary_search_by(|(start, end, _)| {
            if code_point < *start {
                std::cmp::Ordering::Greater
            } else if code_point > *end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .ok()
        .map(|index| table[index].2)
}

pub(crate) fn script_extensions(code_point: u32) -> Vec<&'static str> {
    if let Some(explicit) = range_str(SCRIPT_EXTENSIONS_RANGES, code_point) {
        return explicit.split('+').collect();
    }
    vec![range_str(SCRIPT_RANGES, code_point).unwrap_or("Zzzz")]
}

pub(crate) fn augmented_script_set(values: Vec<&'static str>) -> Option<BTreeSet<&'static str>> {
    if values.iter().any(|value| matches!(*value, "Zyyy" | "Zinh")) {
        return None;
    }
    let mut result: BTreeSet<&str> = values.into_iter().collect();
    if result.contains("Hani") {
        result.extend(["Hanb", "Jpan", "Kore"]);
    }
    if result.contains("Hira") || result.contains("Kana") {
        result.insert("Jpan");
    }
    if result.contains("Hang") {
        result.insert("Kore");
    }
    if result.contains("Bopo") {
        result.insert("Hanb");
    }
    Some(result)
}

#[derive(Debug)]
pub(crate) struct ResolvedScripts {
    pub kind: &'static str,
    pub scripts: Vec<&'static str>,
}

pub(crate) fn resolved_script_set(text: &str) -> ResolvedScripts {
    let mut resolved: Option<BTreeSet<&str>> = None;
    for character in text.chars() {
        let Some(augmented) = augmented_script_set(script_extensions(character as u32)) else {
            continue;
        };
        resolved = Some(match resolved {
            None => augmented,
            Some(current) => current.intersection(&augmented).copied().collect(),
        });
    }
    match resolved {
        None => ResolvedScripts {
            kind: "all",
            scripts: Vec::new(),
        },
        Some(values) if values.is_empty() => ResolvedScripts {
            kind: "empty",
            scripts: Vec::new(),
        },
        Some(values) => ResolvedScripts {
            kind: "set",
            scripts: values.into_iter().collect(),
        },
    }
}

pub(crate) fn skeleton(text: &str, direction: Direction) -> (String, Vec<u8>) {
    let resolution = resolve(text, direction.base_level());
    let reordered: String = resolution
        .entries
        .iter()
        .map(|entry| entry.character)
        .collect();
    (
        uts39_skeleton::apply(&reordered),
        resolution.paragraph_levels,
    )
}

fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn resolved_json(value: &ResolvedScripts) -> Value {
    json!({ "kind": value.kind, "scripts": value.scripts })
}

pub(crate) fn compare(text: &str, comparison: &str, direction: ConfusableDirection) -> Value {
    let bidi_direction = direction.bidi();
    let (text_skeleton, text_paragraph_levels) = skeleton(text, bidi_direction);
    let (comparison_skeleton, comparison_paragraph_levels) = skeleton(comparison, bidi_direction);
    let skeletons_equal = text_skeleton == comparison_skeleton;
    let text_scripts = resolved_script_set(text);
    let comparison_scripts = resolved_script_set(comparison);
    let shared_scripts: Vec<&str> =
        if text_scripts.kind == "set" && comparison_scripts.kind == "set" {
            text_scripts
                .scripts
                .iter()
                .copied()
                .filter(|script| comparison_scripts.scripts.contains(script))
                .collect()
        } else {
            Vec::new()
        };
    let distinct_confusable = text != comparison && skeletons_equal;
    let single_script_confusable = distinct_confusable && !shared_scripts.is_empty();
    let mixed_script_confusable = distinct_confusable && shared_scripts.is_empty();
    let whole_script_confusable =
        mixed_script_confusable && text_scripts.kind == "set" && comparison_scripts.kind == "set";
    let confusable_class = if !distinct_confusable {
        Value::Null
    } else if single_script_confusable {
        json!("single_script")
    } else if whole_script_confusable {
        json!("whole_script")
    } else {
        json!("mixed_script")
    };
    let relation = if text == comparison {
        "identical"
    } else if skeletons_equal {
        "confusable"
    } else {
        "not_confusable"
    };
    json!({
        "relation": relation,
        "uts39Confusable": skeletons_equal,
        "direction": direction.label(),
        "algorithm": format!("bidiSkeleton({})", direction.label()),
        "supportedDomain": "unicode_17_full_uba",
        "skeletonsEqual": skeletons_equal,
        "confusableClass": confusable_class,
        "singleScriptConfusable": single_script_confusable,
        "mixedScriptConfusable": mixed_script_confusable,
        "wholeScriptConfusable": whole_script_confusable,
        "resolvedScripts": {
            "text": resolved_json(&text_scripts),
            "comparison": resolved_json(&comparison_scripts),
            "shared": shared_scripts
        },
        "paragraphLevels": {
            "text": text_paragraph_levels,
            "comparison": comparison_paragraph_levels
        },
        "skeletonDigests": {
            "textSha256": sha256(&text_skeleton),
            "comparisonSha256": sha256(&comparison_skeleton)
        },
        "engine": ENGINE
    })
}

pub fn run(arguments: Value) -> Value {
    let args: Arguments = match serde_json::from_value(arguments) {
        Ok(value) => value,
        Err(_) => {
            return invalid_input(
                "arguments do not match the closed reference confusable-comparison request.",
                "arguments",
            );
        }
    };
    let text = match String::from_utf16(&args.text.tagged.units()) {
        Ok(value) => value,
        Err(_) => {
            return error(
                "INVALID_UNICODE",
                "text contains an unpaired UTF-16 surrogate.",
                json!({ "field": "text" }),
            );
        }
    };
    let comparison = match String::from_utf16(&args.comparison.tagged.units()) {
        Ok(value) => value,
        Err(_) => {
            return error(
                "INVALID_UNICODE",
                "comparison contains an unpaired UTF-16 surrogate.",
                json!({ "field": "comparison" }),
            );
        }
    };
    if text.len() > MAX_TEXT_BYTES || comparison.len() > MAX_TEXT_BYTES {
        let (field, actual) = if text.len() > MAX_TEXT_BYTES {
            ("text", text.len())
        } else {
            ("comparison", comparison.len())
        };
        return error(
            "REQUEST_TOO_LARGE",
            format!("{field} exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({ "field": field, "actualBytes": actual, "limitBytes": MAX_TEXT_BYTES }),
        );
    }
    if text.len() + comparison.len() > MAX_COMBINED_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!("Combined text fields exceed the {MAX_COMBINED_TEXT_BYTES}-byte UTF-8 limit."),
            json!({
                "fields": ["text", "comparison"],
                "actualBytes": text.len() + comparison.len(),
                "limitBytes": MAX_COMBINED_TEXT_BYTES
            }),
        );
    }

    let mut result = compare(&text, &comparison, args.direction);
    let result_object = result
        .as_object_mut()
        .expect("confusable comparison value is an object");
    result_object.insert("text".into(), json!(text));
    result_object.insert("comparison".into(), json!(comparison));
    result_object.insert("operation".into(), json!("reference_confusable_comparison"));
    result_object.insert("status".into(), json!("ok"));
    result_object.insert(
        "standards".into(),
        json!({
            "specification": "Unicode Technical Standard #39",
            "unicodeVersion": UNICODE_VERSION,
            "uts39Revision": 32,
            "stage": "confusable_comparison",
            "source": {
                "manifestSha256": SOURCE_MANIFEST_SHA256,
                "scripts": {
                    "path": SCRIPTS_SOURCE_PATH,
                    "sha256": SCRIPTS_SOURCE_SHA256,
                    "rangeCount": SCRIPT_RANGE_COUNT
                },
                "scriptExtensions": {
                    "path": SCRIPT_EXTENSIONS_SOURCE_PATH,
                    "sha256": SCRIPT_EXTENSIONS_SOURCE_SHA256,
                    "rangeCount": SCRIPT_EXTENSIONS_RANGE_COUNT
                },
                "propertyValueAliases": {
                    "path": PROPERTY_ALIASES_SOURCE_PATH,
                    "sha256": PROPERTY_ALIASES_SOURCE_SHA256
                }
            }
        }),
    );
    let actual_bytes = serde_json::to_vec(&result)
        .expect("reference confusable comparison serializes")
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

    use super::{resolved_script_set, run, script_extensions};

    #[test]
    fn reproduces_augmented_script_resolution() {
        assert_eq!(script_extensions('A' as u32), vec!["Latn"]);
        assert_eq!(
            resolved_script_set("一").scripts,
            vec!["Hanb", "Hani", "Jpan", "Kore"]
        );
        assert_eq!(resolved_script_set("ひカ").scripts, vec!["Jpan"]);
        assert_eq!(resolved_script_set(" ").kind, "all");
        assert_eq!(resolved_script_set("Aא").kind, "empty");
    }

    #[test]
    fn matches_the_named_confusable_classes_without_exposing_skeletons() {
        let result = run(json!({
            "text": { "$text": { "kind": "unicode_scalar_string", "value": "pаypal" } },
            "comparison": { "$text": { "kind": "unicode_scalar_string", "value": "paypal" } },
            "direction": "LTR"
        }));
        assert_eq!(result["relation"], "confusable");
        assert_eq!(result["confusableClass"], "mixed_script");
        assert!(result.get("skeleton").is_none());
    }

    #[test]
    fn rejects_unknown_fields() {
        let result = run(json!({
            "text": { "$text": { "kind": "unicode_scalar_string", "value": "A" } },
            "comparison": { "$text": { "kind": "unicode_scalar_string", "value": "A" } },
            "direction": "LTR",
            "extra": true
        }));
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
    }
}
