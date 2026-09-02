use serde::Deserialize;
use serde_json::{Value, json};

pub const MAX_TEXT_BYTES: usize = 4096;
pub const MAX_BYTE_INPUT: usize = 4096;
pub const MAX_RESULT_BYTES: usize = 65536;
pub const RESULT_METADATA_RESERVATION_BYTES: usize = 512;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub operation: String,
    pub arguments: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaggedTextValue {
    #[serde(rename = "$text")]
    pub tagged: TaggedText,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TaggedText {
    UnicodeScalarString { value: String },
    Utf16CodeUnits { units: Vec<u16> },
}

impl TaggedText {
    pub fn units(&self) -> Vec<u16> {
        match self {
            Self::UnicodeScalarString { value } => value.encode_utf16().collect(),
            Self::Utf16CodeUnits { units } => units.clone(),
        }
    }
}

pub fn error(code: &str, message: impl Into<String>, details: Value) -> Value {
    json!({
        "status": "error",
        "error": {
            "code": code,
            "message": message.into(),
            "details": details
        }
    })
}

pub fn invalid_input(message: impl Into<String>, field: &str) -> Value {
    error("INVALID_INPUT", message, json!({ "field": field }))
}

fn semantic_result_projection(value: &Value) -> Value {
    let mut semantic = value.clone();
    let Some(object) = semantic.as_object_mut() else {
        return semantic;
    };
    object.remove("runtime");
    match object.get("operation").and_then(Value::as_str) {
        Some("security") => {
            if let Some(comparison) = object
                .get_mut("confusableComparison")
                .and_then(Value::as_object_mut)
            {
                comparison.remove("engine");
            }
        }
        Some("protocol_profile") => {
            if let Some(standards) = object.get_mut("standards").and_then(Value::as_object_mut) {
                standards.remove("engine");
            }
            if let Some(witness) = object.get_mut("witness").and_then(Value::as_object_mut) {
                witness.remove("engine");
            }
        }
        _ => {}
    }
    semantic
}

pub fn result_budget_error(actual_bytes: usize, semantic_bytes: usize) -> Option<Value> {
    let metadata_bytes = actual_bytes.saturating_sub(semantic_bytes);
    if metadata_bytes > RESULT_METADATA_RESERVATION_BYTES {
        return Some(error(
            "INTERNAL_ERROR",
            "Non-semantic result metadata exceeds its reserved byte budget.",
            json!({
                "actualBytes": actual_bytes,
                "semanticBytes": semantic_bytes,
                "metadataBytes": metadata_bytes,
                "metadataReservationBytes": RESULT_METADATA_RESERVATION_BYTES,
                "limitBytes": MAX_RESULT_BYTES
            }),
        ));
    }
    let budgeted_bytes = semantic_bytes + RESULT_METADATA_RESERVATION_BYTES;
    if budgeted_bytes <= MAX_RESULT_BYTES {
        return None;
    }
    Some(error(
        "RESULT_TOO_LARGE",
        format!(
            "The complete result cannot fit the {MAX_RESULT_BYTES}-byte budget after reserving {RESULT_METADATA_RESERVATION_BYTES} bytes for non-semantic metadata."
        ),
        json!({
            "actualBytes": actual_bytes,
            "semanticBytes": semantic_bytes,
            "budgetedBytes": budgeted_bytes,
            "metadataBytes": metadata_bytes,
            "metadataReservationBytes": RESULT_METADATA_RESERVATION_BYTES,
            "limitBytes": MAX_RESULT_BYTES
        }),
    ))
}

pub fn enforce_result_budget(value: Value) -> Value {
    let actual_bytes = serde_json::to_vec(&value).expect("result serializes").len();
    let semantic_bytes = serde_json::to_vec(&semantic_result_projection(&value))
        .expect("semantic result serializes")
        .len();
    result_budget_error(actual_bytes, semantic_bytes).unwrap_or(value)
}
