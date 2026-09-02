use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::index::{assign_graphemes, assign_lines, boundaries, raw_code_points};
use crate::index_types::{CodePointEntry, Coordinate, GraphemeEntry};
use crate::normalize;
use crate::security;

pub(crate) const STAGE_ORDER: [&str; 9] = [
    "exact_representation",
    "normalization",
    "nfkc_casefold",
    "coordinate_mapping",
    "alignment",
    "unicode_signals",
    "line_endings",
    "collation",
    "identifier_confusable",
];

const INCLUDED_STAGES: [&str; 8] = [
    "exact_representation",
    "normalization",
    "nfkc_casefold",
    "coordinate_mapping",
    "alignment",
    "unicode_signals",
    "line_endings",
    "identifier_confusable",
];

pub(crate) struct TextMap {
    pub(crate) code_points: Vec<CodePointEntry>,
    pub(crate) graphemes: Vec<GraphemeEntry>,
    pub(crate) boundaries: BTreeMap<usize, Coordinate>,
}

pub(crate) fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn build_map(text: &str) -> TextMap {
    let mut code_points = raw_code_points(text);
    let graphemes = assign_graphemes(text, &mut code_points);
    let final_line = assign_lines(&mut code_points);
    let boundaries = boundaries(text, &code_points, graphemes.len(), final_line);
    TextMap {
        code_points,
        graphemes,
        boundaries,
    }
}

pub(crate) fn normalization_evaluation(
    left: &str,
    right: &str,
    form: &str,
) -> (String, String, Value) {
    let left_output = normalize::apply(left, form);
    let right_output = normalize::apply(right, form);
    let relation = json!({
        "equal": left_output == right_output,
        "leftChanged": left_output != left,
        "rightChanged": right_output != right,
        "leftSha256": sha256(&left_output),
        "rightSha256": sha256(&right_output)
    });
    (left_output, right_output, relation)
}

fn final_coordinate(map: &TextMap) -> &Coordinate {
    let final_utf16 = map
        .code_points
        .last()
        .map_or(0, |item| item.end.utf16_code_unit);
    &map.boundaries[&final_utf16]
}

pub(crate) fn code_point_difference(left: &TextMap, right: &TextMap) -> Value {
    let length = left.code_points.len().max(right.code_points.len());
    for index in 0..length {
        let left_entry = left.code_points.get(index);
        let right_entry = right.code_points.get(index);
        if left_entry.map(|item| item.character.as_str())
            == right_entry.map(|item| item.character.as_str())
        {
            continue;
        }
        let left_value = left_entry.map_or_else(
            || {
                json!({
                    "character": Value::Null,
                    "value": Value::Null,
                    "position": final_coordinate(left)
                })
            },
            |item| {
                json!({
                    "character": item.character,
                    "value": item.value,
                    "position": item.start
                })
            },
        );
        let right_value = right_entry.map_or_else(
            || {
                json!({
                    "character": Value::Null,
                    "value": Value::Null,
                    "position": final_coordinate(right)
                })
            },
            |item| {
                json!({
                    "character": item.character,
                    "value": item.value,
                    "position": item.start
                })
            },
        );
        return json!({ "index": index, "left": left_value, "right": right_value });
    }
    Value::Null
}

pub(crate) fn grapheme_difference(left: &TextMap, right: &TextMap) -> Value {
    let length = left.graphemes.len().max(right.graphemes.len());
    for index in 0..length {
        let left_entry = left.graphemes.get(index);
        let right_entry = right.graphemes.get(index);
        if left_entry.map(|item| item.text.as_str()) == right_entry.map(|item| item.text.as_str()) {
            continue;
        }
        let left_value = left_entry.map_or_else(
            || json!({ "text": Value::Null, "position": final_coordinate(left) }),
            |item| json!({ "text": item.text, "position": left.boundaries[&item.start_utf16] }),
        );
        let right_value = right_entry.map_or_else(
            || json!({ "text": Value::Null, "position": final_coordinate(right) }),
            |item| json!({ "text": item.text, "position": right.boundaries[&item.start_utf16] }),
        );
        return json!({ "index": index, "left": left_value, "right": right_value });
    }
    Value::Null
}

pub(crate) fn invisible_summary(text: &str, detail_limit: usize) -> Value {
    let observation = security::free_text_observation(text, detail_limit);
    let items = observation["characterDetail"]["characters"]
        .as_array()
        .expect("free-text character detail is an array")
        .iter()
        .filter(|item| {
            item["signalKinds"]
                .as_array()
                .is_some_and(|values| !values.is_empty())
        })
        .map(|item| {
            json!({
                "indexCodeUnit": item["indexCodeUnit"],
                "codePoint": item["codePoint"],
                "character": item["character"],
                "signalKinds": item["signalKinds"]
            })
        })
        .collect::<Vec<_>>();
    json!({
        "counts": observation["signalCounts"],
        "items": items,
        "truncated": observation["characterDetail"]["truncated"]
    })
}

pub(crate) fn transformation(
    mode: &str,
    relation: &Value,
    left_output: &str,
    right_output: &str,
) -> Value {
    let mut value = relation.clone();
    let object = value
        .as_object_mut()
        .expect("normalization relation is an object");
    object.insert(
        "leftCodePointCount".into(),
        json!(left_output.chars().count()),
    );
    object.insert(
        "rightCodePointCount".into(),
        json!(right_output.chars().count()),
    );
    if mode == "full_required" {
        object.insert("leftOutput".into(), json!(left_output));
        object.insert("rightOutput".into(), json!(right_output));
    }
    value
}

pub(crate) fn projection_metadata() -> Value {
    json!({
        "kind": "deterministic_spine",
        "consumerOperation": "explain_difference",
        "includedStages": INCLUDED_STAGES,
        "excludedStages": ["collation"],
        "excludedFields": ["collation", "runtime", "identifierConfusableComparison.engine"],
        "completeConsumerParity": false
    })
}
