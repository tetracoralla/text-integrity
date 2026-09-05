use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::confusable::{self, ConfusableDirection};
use crate::difference_alignment;
use crate::difference_support::{
    STAGE_ORDER, build_map, code_point_difference, grapheme_difference, invisible_summary,
    normalization_evaluation, projection_metadata, sha256, transformation,
};
use crate::index::line_endings;
use crate::model::{MAX_TEXT_BYTES, TaggedTextValue, enforce_result_budget, error, invalid_input};
use crate::nfkc_casefold;
use crate::security_data::{SOURCE_MANIFEST_SHA256, SOURCE_ROOT, UNICODE_VERSION, UTS39_REVISION};

const MAX_COMBINED_TEXT_BYTES: usize = 8192;
const MAX_DETAIL_ITEMS: usize = 128;
const DEFAULT_DETAIL_ITEMS: usize = 64;
const MAX_LOCALE_CHARS: usize = 128;
const MAX_COLLATION_CHARS: usize = 32;
const FORMS: [&str; 4] = ["NFC", "NFD", "NFKC", "NFKD"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Arguments {
    left: TaggedTextValue,
    right: TaggedTextValue,
    locale: String,
    options: CollationOptions,
    confusable_direction: ConfusableDirection,
    detail_limit: Option<usize>,
    witness_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct CollationOptions {
    usage: String,
    sensitivity: String,
    ignore_punctuation: bool,
    numeric: bool,
    case_first: String,
    locale_matcher: String,
    collation: String,
}

fn decode_text(value: &TaggedTextValue, field: &str) -> Result<String, Value> {
    String::from_utf16(&value.tagged.units()).map_err(|_| {
        error(
            "INVALID_UNICODE",
            format!("{field} contains an unpaired UTF-16 surrogate."),
            json!({ "field": field }),
        )
    })
}

fn validate_collation_shape(locale: &str, options: &CollationOptions) -> Option<Value> {
    let locale_chars = locale.chars().count();
    if locale_chars == 0 {
        return Some(invalid_input(
            "locale must be a non-empty string.",
            "locale",
        ));
    }
    if locale_chars > MAX_LOCALE_CHARS {
        return Some(error(
            "REQUEST_TOO_LARGE",
            format!("locale exceeds the {MAX_LOCALE_CHARS}-character limit."),
            json!({ "field": "locale", "actualChars": locale_chars, "limitChars": MAX_LOCALE_CHARS }),
        ));
    }
    if !matches!(options.usage.as_str(), "sort" | "search")
        || !matches!(
            options.sensitivity.as_str(),
            "base" | "accent" | "case" | "variant"
        )
        || !matches!(options.case_first.as_str(), "upper" | "lower" | "false")
        || !matches!(options.locale_matcher.as_str(), "lookup" | "best fit")
    {
        return Some(invalid_input(
            "options contain an unsupported collation enum.",
            "options",
        ));
    }
    let collation_chars = options.collation.chars().count();
    if collation_chars == 0 || collation_chars > MAX_COLLATION_CHARS {
        return Some(invalid_input(
            format!("options.collation must contain 1 to {MAX_COLLATION_CHARS} characters."),
            "options.collation",
        ));
    }
    let _ = (options.ignore_punctuation, options.numeric);
    None
}

pub(crate) fn raw_alignment_grid_cells(arguments: &Value) -> u64 {
    let args: Arguments = match serde_json::from_value(arguments.clone()) {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if validate_collation_shape(&args.locale, &args.options).is_some()
        || args.detail_limit.unwrap_or(DEFAULT_DETAIL_ITEMS) > MAX_DETAIL_ITEMS
        || !matches!(
            args.witness_mode.as_deref().unwrap_or("none"),
            "summary" | "full_required"
        )
    {
        return 0;
    }
    let left = match decode_text(&args.left, "left") {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let right = match decode_text(&args.right, "right") {
        Ok(value) => value,
        Err(_) => return 0,
    };
    if left.len() > MAX_TEXT_BYTES
        || right.len() > MAX_TEXT_BYTES
        || left.len() + right.len() > MAX_COMBINED_TEXT_BYTES
    {
        return 0;
    }
    let left_code_points = left.chars().count() as u64;
    let right_code_points = right.chars().count() as u64;
    2 * left_code_points * right_code_points
}

pub fn run(arguments: Value) -> Value {
    let args: Arguments = match serde_json::from_value(arguments) {
        Ok(value) => value,
        Err(_) => {
            return invalid_input(
                "arguments do not match the closed reference difference-spine request.",
                "arguments",
            );
        }
    };
    if let Some(value) = validate_collation_shape(&args.locale, &args.options) {
        return value;
    }
    let detail_limit = args.detail_limit.unwrap_or(DEFAULT_DETAIL_ITEMS);
    if detail_limit > MAX_DETAIL_ITEMS {
        return invalid_input(
            "detailLimit must be an integer from 0 through 128.",
            "detailLimit",
        );
    }
    let witness_mode = args.witness_mode.as_deref().unwrap_or("none");
    if !matches!(witness_mode, "none" | "summary" | "full_required") {
        return invalid_input("witnessMode is not supported.", "witnessMode");
    }
    let left = match decode_text(&args.left, "left") {
        Ok(value) => value,
        Err(value) => return value,
    };
    let right = match decode_text(&args.right, "right") {
        Ok(value) => value,
        Err(value) => return value,
    };
    for (field, value) in [("left", &left), ("right", &right)] {
        if value.len() > MAX_TEXT_BYTES {
            return error(
                "REQUEST_TOO_LARGE",
                format!("{field} exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
                json!({ "field": field, "actualBytes": value.len(), "limitBytes": MAX_TEXT_BYTES }),
            );
        }
    }
    let combined_bytes = left.len() + right.len();
    if combined_bytes > MAX_COMBINED_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!("Combined text fields exceed the {MAX_COMBINED_TEXT_BYTES}-byte UTF-8 limit."),
            json!({
                "fields": ["left", "right"],
                "actualBytes": combined_bytes,
                "limitBytes": MAX_COMBINED_TEXT_BYTES
            }),
        );
    }

    let left_map = build_map(&left);
    let right_map = build_map(&right);
    let input_left_sha256 = sha256(&left);
    let input_right_sha256 = sha256(&right);
    let mut normalization = Map::new();
    let mut normalization_outputs = BTreeMap::new();
    for form in FORMS {
        let (left_output, right_output, relation) = normalization_evaluation(&left, &right, form);
        normalization.insert(form.into(), relation.clone());
        normalization_outputs.insert(form, (left_output, right_output, relation));
    }
    let casefold_left = nfkc_casefold::apply(&left);
    let casefold_right = nfkc_casefold::apply(&right);
    let casefold_relation = json!({
        "equal": casefold_left == casefold_right,
        "leftChanged": casefold_left != left,
        "rightChanged": casefold_right != right,
        "leftSha256": sha256(&casefold_left),
        "rightSha256": sha256(&casefold_right)
    });
    let mut confusable = confusable::compare(&left, &right, args.confusable_direction);
    confusable
        .as_object_mut()
        .expect("confusable comparison is an object")
        .remove("engine");

    let mut result = json!({
        "status": "ok",
        "operation": "reference_explain_difference_spine",
        "consumerOperation": "explain_difference",
        "projection": projection_metadata(),
        "exact": {
            "equal": left == right,
            "utf8Bytes": { "left": left.len(), "right": right.len() },
            "utf16CodeUnits": {
                "left": left.encode_utf16().count(),
                "right": right.encode_utf16().count()
            },
            "codePoints": { "left": left_map.code_points.len(), "right": right_map.code_points.len() },
            "graphemes": { "left": left_map.graphemes.len(), "right": right_map.graphemes.len() }
        },
        "normalization": normalization,
        "nfkcCasefold": casefold_relation,
        "firstDifference": {
            "codePoint": code_point_difference(&left_map, &right_map),
            "grapheme": grapheme_difference(&left_map, &right_map)
        },
        "invisibleCharacters": {
            "left": invisible_summary(&left, detail_limit),
            "right": invisible_summary(&right, detail_limit)
        },
        "lineEndings": {
            "left": line_endings(&left_map.code_points, detail_limit),
            "right": line_endings(&right_map.code_points, detail_limit)
        },
        "identifierConfusableComparison": confusable,
        "limitations": [
            "Confusable comparison is an identifier mechanism and is not a font-specific visual judgment.",
            "This operation explains deterministic representation relations; it does not infer author intent."
        ],
        "data": {
            "unicodeVersion": UNICODE_VERSION,
            "uts39Revision": UTS39_REVISION,
            "sourceRoot": SOURCE_ROOT,
            "license": "Unicode License V3",
            "manifestSha256": SOURCE_MANIFEST_SHA256,
            "offline": true
        }
    });

    if witness_mode != "none" {
        let normalization_witness = normalization_outputs
            .iter()
            .map(|(form, (left_output, right_output, relation))| {
                (
                    (*form).to_owned(),
                    transformation(witness_mode, relation, left_output, right_output),
                )
            })
            .collect::<Map<_, _>>();
        let witness = json!({
            "mode": witness_mode,
            "stageOrder": STAGE_ORDER,
            "inputs": {
                "exactEqual": left == right,
                "leftSha256": input_left_sha256,
                "rightSha256": input_right_sha256
            },
            "transformations": {
                "normalization": normalization_witness,
                "nfkcCasefold": transformation(
                    witness_mode,
                    &casefold_relation,
                    &casefold_left,
                    &casefold_right
                )
            },
            "alignment": difference_alignment::build(&left_map, &right_map, witness_mode),
            "factBoundaries": {
                "exactRepresentation": { "authority": "explicit_input", "environmentBound": false },
                "normalization": { "authority": "bundled_unicode_17", "environmentBound": false },
                "nfkcCasefold": {
                    "authority": "bundled_unicode_17_uts39_revision_32",
                    "environmentBound": false
                },
                "coordinateMapping": {
                    "authority": "bundled_unicode_17_uax29_revision_47",
                    "environmentBound": false,
                    "leftCodePointCount": left_map.code_points.len(),
                    "rightCodePointCount": right_map.code_points.len(),
                    "leftGraphemeCount": left_map.graphemes.len(),
                    "rightGraphemeCount": right_map.graphemes.len()
                },
                "alignment": {
                    "authority": "project_core_lcs_over_explicit_unicode17_units",
                    "environmentBound": false,
                    "complete": witness_mode == "full_required"
                },
                "unicodeSignals": {
                    "authority": "bundled_unicode_17_uts39_revision_32",
                    "environmentBound": false,
                    "detailLimit": detail_limit
                },
                "lineEndings": {
                    "authority": "project_core_explicit_code_units",
                    "environmentBound": false,
                    "detailLimit": detail_limit
                },
                "collation": {
                    "authority": "runtime_icu",
                    "environmentBound": true,
                    "includedInProjection": false
                },
                "identifierConfusable": {
                    "authority": "bundled_unicode_17_uts39_revision_32_vendored_uba",
                    "environmentBound": false,
                    "direction": args.confusable_direction.label(),
                    "relation": result["identifierConfusableComparison"]["relation"],
                    "internalSkeletonDisclosed": false
                }
            }
        });
        result
            .as_object_mut()
            .expect("difference result is an object")
            .insert("witness".into(), witness);
    }
    enforce_result_budget(result)
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::run;

    fn options() -> Value {
        json!({
            "usage": "sort",
            "sensitivity": "variant",
            "ignorePunctuation": false,
            "numeric": false,
            "caseFirst": "false",
            "localeMatcher": "lookup",
            "collation": "default"
        })
    }

    #[test]
    fn composes_the_deterministic_difference_spine() {
        let result = run(json!({
            "left": { "$text": { "kind": "unicode_scalar_string", "value": "é\r\npаypal" } },
            "right": { "$text": { "kind": "unicode_scalar_string", "value": "e\u{301}\npaypal" } },
            "locale": "en",
            "options": options(),
            "confusableDirection": "LTR",
            "detailLimit": 128,
            "witnessMode": "full_required"
        }));
        assert_eq!(result["status"], "ok");
        assert_eq!(result["operation"], "reference_explain_difference_spine");
        assert_eq!(result["normalization"]["NFC"]["equal"], false);
        assert_eq!(result["lineEndings"]["left"]["counts"]["crlf"], 1);
        assert_eq!(
            result["witness"]["factBoundaries"]["collation"]["includedInProjection"],
            false
        );
    }

    #[test]
    fn rejects_unknown_fields_before_execution() {
        let result = run(json!({
            "left": { "$text": { "kind": "unicode_scalar_string", "value": "A" } },
            "right": { "$text": { "kind": "unicode_scalar_string", "value": "a" } },
            "locale": "en",
            "options": options(),
            "confusableDirection": "LTR",
            "extra": true
        }));
        assert_eq!(result["status"], "error");
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
    }
}
