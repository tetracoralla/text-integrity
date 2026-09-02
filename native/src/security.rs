use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::bidi_reorder::bidi_class_label;
use crate::confusable::{
    ConfusableDirection, augmented_script_set, compare, resolved_json, resolved_script_set,
    script_extensions,
};
use crate::model::{
    MAX_RESULT_BYTES, MAX_TEXT_BYTES, TaggedTextValue, enforce_result_budget, error, invalid_input,
};
use crate::nfkc_casefold;
use crate::security_data::{
    BIDI_CONTROL_RANGES, DECIMAL_VALUE_RANGES, DEFAULT_IGNORABLE_RANGES, FORMAT_CHARACTER_RANGES,
    IDENTIFIER_ALLOWED_RANGES, IDENTIFIER_TYPE_RANGES, RECOMMENDED_SCRIPTS, SOURCE_MANIFEST_SHA256,
    SOURCE_ROOT, UNICODE_VERSION, UTS39_REVISION, XID_CONTINUE_RANGES, XID_START_RANGES,
};

const MAX_COMBINED_TEXT_BYTES: usize = 4096;
const MAX_DETAIL_ITEMS: usize = 128;
const DEFAULT_DETAIL_ITEMS: usize = 64;

const BASE_LIMITATIONS: [&str; 2] = [
    "The result reports versioned Unicode properties and relations; it does not determine whether text is benign or harmful.",
    "An empty resolved script set can occur in legitimate multilingual text and is not a verdict.",
];

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    FreeText,
    Identifier,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Profile {
    Uax31Xid,
    Uax31NfkcCasefold,
    Uts39GeneralSecurity,
}

impl Profile {
    fn label(self) -> &'static str {
        match self {
            Self::Uax31Xid => "uax31_xid",
            Self::Uax31NfkcCasefold => "uax31_nfkc_casefold",
            Self::Uts39GeneralSecurity => "uts39_general_security",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Arguments {
    text: TaggedTextValue,
    mode: Mode,
    profile: Option<Profile>,
    comparison: Option<TaggedTextValue>,
    confusable_direction: Option<ConfusableDirection>,
    detail_limit: Option<usize>,
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

fn range_u8(table: &[(u32, u32, u8)], code_point: u32) -> Option<u8> {
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

fn code_point_label(code_point: u32) -> String {
    format!("U+{code_point:04X}")
}

fn utf16_len(character: char) -> usize {
    character.len_utf16()
}

fn identifier_allowed(code_point: u32) -> bool {
    range_str(IDENTIFIER_ALLOWED_RANGES, code_point).is_some()
}

fn identifier_types(code_point: u32) -> Vec<&'static str> {
    range_str(IDENTIFIER_TYPE_RANGES, code_point)
        .map(|value| value.split('+').collect())
        .unwrap_or_else(|| vec!["Not_Character"])
}

fn analyze_text(text: &str, mode: Mode, detail_limit: usize) -> Value {
    let mut bidi_controls = 0usize;
    let mut default_ignorables = 0usize;
    let mut format_characters = 0usize;
    let mut allowed_count = 0usize;
    let mut restricted_count = 0usize;
    let mut type_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut characters = Vec::new();
    let mut code_unit_index = 0usize;
    let mut code_point_count = 0usize;

    for character in text.chars() {
        let code_point = character as u32;
        let bidi_control = range_contains(BIDI_CONTROL_RANGES, code_point);
        let default_ignorable = range_contains(DEFAULT_IGNORABLE_RANGES, code_point);
        let format_character = range_contains(FORMAT_CHARACTER_RANGES, code_point);
        bidi_controls += usize::from(bidi_control);
        default_ignorables += usize::from(default_ignorable);
        format_characters += usize::from(format_character);

        let types = identifier_types(code_point);
        let allowed = identifier_allowed(code_point);
        if mode == Mode::Identifier {
            if allowed {
                allowed_count += 1;
            } else {
                restricted_count += 1;
            }
            for item in &types {
                *type_counts.entry(item).or_default() += 1;
            }
        }

        if characters.len() < detail_limit {
            let mut signal_kinds = Vec::new();
            if bidi_control {
                signal_kinds.push("bidi_control");
            }
            if default_ignorable {
                signal_kinds.push("default_ignorable");
            }
            if format_character {
                signal_kinds.push("format_character");
            }
            let mut observation = json!({
                "indexCodeUnit": code_unit_index,
                "codePoint": code_point_label(code_point),
                "character": character.to_string(),
                "scriptExtensions": script_extensions(code_point),
                "bidiClass": bidi_class_label(character),
                "signalKinds": signal_kinds
            });
            if mode == Mode::Identifier {
                let object = observation
                    .as_object_mut()
                    .expect("character observation is an object");
                object.insert(
                    "identifierStatus".into(),
                    json!(if allowed { "Allowed" } else { "Restricted" }),
                );
                object.insert("identifierTypes".into(), json!(types));
            }
            characters.push(observation);
        }
        code_point_count += 1;
        code_unit_index += utf16_len(character);
    }

    let mut result = json!({
        "counts": { "utf16CodeUnits": text.encode_utf16().count(), "codePoints": code_point_count },
        "signalCounts": {
            "bidiControls": bidi_controls,
            "defaultIgnorables": default_ignorables,
            "formatCharacters": format_characters
        },
        "scriptResolution": resolved_json(&resolved_script_set(text)),
        "characterDetail": {
            "limit": detail_limit,
            "characters": characters,
            "truncated": code_point_count > detail_limit
        }
    });
    if mode == Mode::Identifier {
        result
            .as_object_mut()
            .expect("security observation is an object")
            .insert(
                "identifierProperties".into(),
                json!({
                    "statusCounts": { "Allowed": allowed_count, "Restricted": restricted_count },
                    "typeCounts": type_counts.into_iter()
                        .map(|(value, count)| json!({ "value": value, "count": count }))
                        .collect::<Vec<_>>()
                }),
            );
    }
    result
}

pub(crate) fn free_text_observation(text: &str, detail_limit: usize) -> Value {
    analyze_text(text, Mode::FreeText, detail_limit)
}

fn profile_syntax(text: &str) -> Vec<Value> {
    let mut failures = Vec::new();
    let mut code_unit_index = 0usize;
    for (code_point_index, character) in text.chars().enumerate() {
        let code_point = character as u32;
        let valid = if code_point_index == 0 {
            range_contains(XID_START_RANGES, code_point)
        } else {
            range_contains(XID_CONTINUE_RANGES, code_point)
        };
        if !valid {
            failures.push(json!({
                "indexCodeUnit": code_unit_index,
                "indexCodePoint": code_point_index,
                "codePoint": code_point_label(code_point),
                "requiredProperty": if code_point_index == 0 { "XID_Start" } else { "XID_Continue" }
            }));
        }
        code_unit_index += utf16_len(character);
    }
    if text.is_empty() {
        failures.push(json!({
            "indexCodeUnit": 0,
            "indexCodePoint": 0,
            "codePoint": Value::Null,
            "requiredProperty": "XID_Start"
        }));
    }
    failures
}

fn restriction_level(text: &str) -> &'static str {
    if text
        .chars()
        .any(|character| !identifier_allowed(character as u32))
    {
        return "Unrestricted";
    }
    if text.chars().all(|character| character as u32 <= 0x7f) {
        return "ASCII-Only";
    }

    let script_sets: Vec<BTreeSet<&str>> = text
        .chars()
        .filter_map(|character| augmented_script_set(script_extensions(character as u32)))
        .collect();
    if script_sets.is_empty() {
        return "Single Script";
    }
    let mut shared = script_sets[0].clone();
    for scripts in &script_sets[1..] {
        shared = shared.intersection(scripts).copied().collect();
    }
    if !shared.is_empty() {
        return "Single Script";
    }

    let without_latin: Vec<&BTreeSet<&str>> = script_sets
        .iter()
        .filter(|scripts| !scripts.contains("Latn"))
        .collect();
    if without_latin.is_empty()
        || ["Kore", "Hanb", "Jpan"]
            .iter()
            .any(|script| without_latin.iter().all(|scripts| scripts.contains(script)))
    {
        return "Highly Restrictive";
    }
    let mut remaining_shared = without_latin[0].clone();
    for scripts in &without_latin[1..] {
        remaining_shared = remaining_shared.intersection(scripts).copied().collect();
    }
    if remaining_shared
        .iter()
        .any(|script| RECOMMENDED_SCRIPTS.contains(script) && !matches!(*script, "Cyrl" | "Grek"))
    {
        return "Moderately Restrictive";
    }
    "Minimally Restrictive"
}

fn mixed_numbers(text: &str) -> Value {
    let zero_code_points: BTreeSet<u32> = text
        .chars()
        .filter_map(|character| {
            let code_point = character as u32;
            range_u8(DECIMAL_VALUE_RANGES, code_point).map(|value| code_point - u32::from(value))
        })
        .collect();
    json!({
        "mixed": zero_code_points.len() > 1,
        "decimalSystems": zero_code_points.into_iter().map(code_point_label).collect::<Vec<_>>()
    })
}

fn identifier_profile(text: &str, profile: Profile) -> Value {
    let transformed = if matches!(profile, Profile::Uax31NfkcCasefold) {
        nfkc_casefold::apply(text)
    } else {
        text.to_owned()
    };
    let syntax_failures = profile_syntax(&transformed);
    let mut restricted = Vec::new();
    if matches!(profile, Profile::Uts39GeneralSecurity) {
        let mut code_unit_index = 0usize;
        for character in transformed.chars() {
            let code_point = character as u32;
            if !identifier_allowed(code_point) {
                restricted.push(json!({
                    "indexCodeUnit": code_unit_index,
                    "codePoint": code_point_label(code_point)
                }));
            }
            code_unit_index += utf16_len(character);
        }
    }
    json!({
        "name": profile.label(),
        "transformedText": transformed,
        "changed": transformed != text,
        "conforms": syntax_failures.is_empty() && restricted.is_empty(),
        "syntaxFailures": syntax_failures,
        "restrictedCodePoints": restricted,
        "restrictionLevel": restriction_level(&transformed),
        "mixedNumbers": mixed_numbers(&transformed)
    })
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

fn enum_error(field: &str, allowed: &[&str]) -> Value {
    error(
        "INVALID_INPUT",
        format!("{field} must be one of: {}.", allowed.join(", ")),
        json!({ "field": field, "allowed": allowed }),
    )
}

fn validate_arguments(value: &Value) -> Option<Value> {
    let Some(object) = value.as_object() else {
        return Some(invalid_input("arguments must be an object.", "arguments"));
    };
    let mode = object.get("mode").and_then(Value::as_str);
    if !matches!(mode, Some("free_text" | "identifier")) {
        return Some(enum_error("mode", &["free_text", "identifier"]));
    }
    let identifier = mode == Some("identifier");
    let allowed = if identifier {
        [
            "text",
            "mode",
            "profile",
            "comparison",
            "confusableDirection",
            "detailLimit",
        ]
        .as_slice()
    } else {
        ["text", "mode", "detailLimit"].as_slice()
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
        ["text", "mode", "profile"].as_slice()
    } else {
        ["text", "mode"].as_slice()
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
    if identifier {
        let profile = object.get("profile").and_then(Value::as_str);
        if !matches!(
            profile,
            Some("uax31_xid" | "uax31_nfkc_casefold" | "uts39_general_security")
        ) {
            return Some(enum_error(
                "profile",
                &["uax31_xid", "uax31_nfkc_casefold", "uts39_general_security"],
            ));
        }
        if object.contains_key("comparison") {
            let direction = object.get("confusableDirection").and_then(Value::as_str);
            if !matches!(direction, Some("LTR" | "RTL" | "FS")) {
                return Some(enum_error("confusableDirection", &["LTR", "RTL", "FS"]));
            }
        } else if object.contains_key("confusableDirection") {
            return Some(error(
                "INVALID_INPUT",
                "confusableDirection is allowed only when comparison is supplied.",
                json!({ "field": "confusableDirection" }),
            ));
        }
    }
    None
}

pub fn run(arguments: Value) -> Value {
    if let Some(error) = validate_arguments(&arguments) {
        return error;
    }
    let args: Arguments = match serde_json::from_value(arguments) {
        Ok(value) => value,
        Err(_) => {
            return invalid_input(
                "arguments do not match the closed scoped security request.",
                "arguments",
            );
        }
    };
    if args.mode == Mode::FreeText
        && (args.profile.is_some()
            || args.comparison.is_some()
            || args.confusable_direction.is_some())
    {
        return invalid_input(
            "free_text accepts only text, mode, and detailLimit.",
            "arguments",
        );
    }
    if args.mode == Mode::Identifier && args.profile.is_none() {
        return invalid_input("identifier mode requires profile.", "profile");
    }
    if args.comparison.is_some() != args.confusable_direction.is_some() {
        return invalid_input(
            "comparison and confusableDirection must be supplied together.",
            "confusableDirection",
        );
    }
    let detail_limit = args.detail_limit.unwrap_or(DEFAULT_DETAIL_ITEMS);
    if detail_limit > MAX_DETAIL_ITEMS {
        return invalid_input(
            "detailLimit must be an integer from 0 through 128.",
            "detailLimit",
        );
    }
    let text = match decode_text(&args.text, "text") {
        Ok(value) => value,
        Err(value) => return value,
    };
    let comparison = match args.comparison.as_ref() {
        Some(value) => match decode_text(value, "comparison") {
            Ok(value) => Some(value),
            Err(value) => return value,
        },
        None => None,
    };
    if text.len() > MAX_TEXT_BYTES
        || comparison
            .as_ref()
            .is_some_and(|value| value.len() > MAX_TEXT_BYTES)
    {
        let (field, actual) = if text.len() > MAX_TEXT_BYTES {
            ("text", text.len())
        } else {
            (
                "comparison",
                comparison.as_ref().expect("oversized comparison").len(),
            )
        };
        return error(
            "REQUEST_TOO_LARGE",
            format!("{field} exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({ "field": field, "actualBytes": actual, "limitBytes": MAX_TEXT_BYTES }),
        );
    }
    let combined_bytes = text.len() + comparison.as_ref().map_or(0, String::len);
    if combined_bytes > MAX_COMBINED_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!("Combined text fields exceed the {MAX_COMBINED_TEXT_BYTES}-byte UTF-8 limit."),
            json!({
                "fields": ["text", "comparison"],
                "actualBytes": combined_bytes,
                "limitBytes": MAX_COMBINED_TEXT_BYTES
            }),
        );
    }

    let mut result = json!({
        "status": "ok",
        "operation": "security",
        "mode": if args.mode == Mode::FreeText { "free_text" } else { "identifier" },
        "claimScope": "unicode_security_observations",
        "data": {
            "unicodeVersion": UNICODE_VERSION,
            "uts39Revision": UTS39_REVISION,
            "sourceRoot": SOURCE_ROOT,
            "license": "Unicode License V3",
            "manifestSha256": SOURCE_MANIFEST_SHA256,
            "offline": true
        },
        "limits": {
            "maxTextBytesPerField": MAX_TEXT_BYTES,
            "maxCombinedTextBytes": MAX_COMBINED_TEXT_BYTES,
            "maxDetailItems": MAX_DETAIL_ITEMS,
            "maxResultBytes": MAX_RESULT_BYTES
        },
        "observations": analyze_text(&text, args.mode, detail_limit),
        "limitations": if args.mode == Mode::FreeText {
            vec![
                BASE_LIMITATIONS[0],
                BASE_LIMITATIONS[1],
                "Identifier profiles and confusable comparison are not applied to unrestricted prose in free_text mode."
            ]
        } else {
            vec![
                BASE_LIMITATIONS[0],
                BASE_LIMITATIONS[1],
                "Profile conformance is limited to the explicitly named identifier profile; it is not an application authorization decision.",
                "A not_confusable relation is limited to Unicode 17.0.0 data and does not establish visual distinction in every font or rendering context."
            ]
        }
    });
    let result_object = result
        .as_object_mut()
        .expect("security result is an object");
    if let Some(profile) = args.profile {
        result_object.insert(
            "identifierProfile".into(),
            identifier_profile(&text, profile),
        );
    }
    if let (Some(comparison), Some(direction)) = (comparison.as_ref(), args.confusable_direction) {
        result_object.insert(
            "confusableComparison".into(),
            compare(&text, comparison, direction),
        );
    }

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
    fn reproduces_free_text_signals() {
        let result = run(json!({
            "text": tagged("a\u{202e}\u{200d}b"),
            "mode": "free_text",
            "detailLimit": 8
        }));
        assert_eq!(result["observations"]["signalCounts"]["bidiControls"], 1);
        assert_eq!(
            result["observations"]["signalCounts"]["defaultIgnorables"],
            2
        );
        assert_eq!(
            result["observations"]["signalCounts"]["formatCharacters"],
            2
        );
    }

    #[test]
    fn reproduces_identifier_profile_and_confusable_relation() {
        let result = run(json!({
            "text": tagged("pаypal"),
            "mode": "identifier",
            "profile": "uts39_general_security",
            "comparison": tagged("paypal"),
            "confusableDirection": "LTR",
            "detailLimit": 8
        }));
        assert_eq!(result["identifierProfile"]["conforms"], true);
        assert_eq!(
            result["identifierProfile"]["restrictionLevel"],
            "Minimally Restrictive"
        );
        assert_eq!(result["confusableComparison"]["relation"], "confusable");
    }

    #[test]
    fn keeps_free_text_and_identifier_keys_closed() {
        let result = run(json!({
            "text": tagged("A"),
            "mode": "free_text",
            "profile": "uax31_xid"
        }));
        assert_eq!(result["status"], "error");
    }
}
