use serde_json::{Value, json};
use unicode_normalization::char::{
    canonical_combining_class, compose, decompose_canonical, decompose_compatible,
};
use unicode_normalization::{UNICODE_VERSION, UnicodeNormalization};

use crate::model::{MAX_TEXT_BYTES, enforce_result_budget, error};
use crate::validation::{
    assert_keys, require_enum, require_object, require_tagged_units, utf8_length_from_units,
};

pub(crate) fn apply(value: &str, form: &str) -> String {
    debug_assert_eq!(UNICODE_VERSION, (17, 0, 0));
    match form {
        "NFC" => value.nfc().collect(),
        "NFD" => value.nfd().collect(),
        "NFKC" => value.nfkc().collect(),
        "NFKD" => value.nfkd().collect(),
        _ => unreachable!(),
    }
}

fn label(value: char) -> String {
    format!("U+{:04X}", value as u32)
}

fn raw_decomposition(value: &str, compatibility: bool) -> Vec<char> {
    let mut output = Vec::new();
    for character in value.chars() {
        if compatibility {
            decompose_compatible(character, |part| output.push(part));
        } else {
            decompose_canonical(character, |part| output.push(part));
        }
    }
    output
}

fn ordered_decomposition(value: &str, compatibility: bool) -> Vec<char> {
    if compatibility {
        value.nfkd().collect()
    } else {
        value.nfd().collect()
    }
}

fn compose_with_steps(ordered: &[char], capture_steps: bool) -> (Vec<char>, usize, Vec<Value>) {
    let Some(&first) = ordered.first() else {
        return (Vec::new(), 0, Vec::new());
    };
    let mut output = vec![first];
    let mut starter_position = 0usize;
    let mut starter = first;
    let mut preceding_class = canonical_combining_class(first);
    let mut count = 0usize;
    let mut steps = Vec::new();

    for &current in &ordered[1..] {
        let current_class = canonical_combining_class(current);
        let composite = compose(starter, current);
        if let Some(composite) = composite
            && (preceding_class == 0 || preceding_class < current_class)
        {
            if capture_steps {
                steps.push(json!({
                    "starter": label(starter),
                    "current": label(current),
                    "composite": label(composite),
                    "outputIndexCodePoint": starter_position
                }));
            }
            output[starter_position] = composite;
            starter = composite;
            count += 1;
            continue;
        }
        if current_class == 0 {
            starter_position = output.len();
            starter = current;
        }
        output.push(current);
        preceding_class = current_class;
    }
    (output, count, steps)
}

fn apply_with_witness(value: &str, form: &str, mode: &str) -> (String, Value) {
    let compatibility = matches!(form, "NFKC" | "NFKD");
    let input: Vec<char> = value.chars().collect();
    let decomposed = raw_decomposition(value, compatibility);
    let ordered = ordered_decomposition(value, compatibility);
    let (output, composition_count, compositions) = if matches!(form, "NFC" | "NFKC") {
        compose_with_steps(&ordered, mode == "full_required")
    } else {
        (ordered.clone(), 0, Vec::new())
    };
    let normalized: String = output.iter().collect();
    let reordered_positions = decomposed
        .iter()
        .zip(&ordered)
        .filter(|(left, right)| left != right)
        .count();
    let mut witness = json!({
        "mode": mode,
        "specification": "Unicode Standard Annex #15",
        "unicodeVersion": "17.0.0",
        "inputCodePointCount": input.len(),
        "decomposedCodePointCount": decomposed.len(),
        "decompositionChanged": input != decomposed,
        "canonicalReorderedPositionCount": reordered_positions,
        "compositionCount": composition_count,
        "outputCodePointCount": output.len()
    });
    if mode == "full_required" {
        witness
            .as_object_mut()
            .expect("witness is an object")
            .insert(
                "stages".to_owned(),
                json!({
                    "input": input.into_iter().map(label).collect::<Vec<_>>(),
                    "decomposed": decomposed.into_iter().map(label).collect::<Vec<_>>(),
                    "canonicalOrdered": ordered.into_iter().map(label).collect::<Vec<_>>(),
                    "compositions": compositions
                }),
            );
    }
    (normalized, witness)
}

pub fn normalize(arguments: Value) -> Value {
    let object = match require_object(&arguments, "arguments") {
        Ok(value) => value,
        Err(value) => return value,
    };
    if let Err(value) = assert_keys(object, &["text", "form", "witnessMode"], &["text", "form"]) {
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
    let form = match require_enum(object.get("form"), "form", &["NFC", "NFD", "NFKC", "NFKD"]) {
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
    let (normalized, witness) = if witness_mode == "none" {
        (apply(&original, &form), None)
    } else {
        let (normalized, witness) = apply_with_witness(&original, &form, &witness_mode);
        (normalized, Some(witness))
    };
    let mut result = json!({
        "status": "ok",
        "operation": "normalize",
        "form": form,
        "original": original,
        "normalized": normalized,
        "changed": original != normalized,
        "canonicalEquivalent": original.nfd().eq(normalized.nfd()),
        "compatibilityEquivalent": original.nfkd().eq(normalized.nfkd()),
        "bytes": {
            "originalUtf8": original.len(),
            "normalizedUtf8": normalized.len()
        }
    });
    if let Some(witness) = witness {
        result
            .as_object_mut()
            .expect("normalize result is an object")
            .insert("witness".to_owned(), witness);
    }
    enforce_result_budget(result)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{apply, apply_with_witness};

    #[test]
    fn canonical_and_compatibility_composition_are_separate() {
        assert_eq!(apply("e\u{301}", "NFC"), "é");
        assert_eq!(apply("①", "NFKC"), "1");
        assert_eq!(apply("①", "NFC"), "①");
    }

    #[test]
    fn witness_reports_decomposition_ordering_and_composition() {
        let (normalized, witness) = apply_with_witness("①A\u{315}\u{300}", "NFKC", "full_required");
        assert_eq!(normalized, "1À\u{315}");
        assert_eq!(witness["canonicalReorderedPositionCount"], 2);
        assert_eq!(witness["compositionCount"], 1);
        assert_eq!(
            witness["stages"]["canonicalOrdered"],
            json!(["U+0031", "U+0041", "U+0300", "U+0315"])
        );
    }
}
