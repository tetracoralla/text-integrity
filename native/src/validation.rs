use serde_json::{Map, Value, json};

use crate::model::{MAX_TEXT_BYTES, TaggedTextValue, error};

pub(crate) fn require_object<'a>(
    value: &'a Value,
    field: &str,
) -> Result<&'a Map<String, Value>, Value> {
    value.as_object().ok_or_else(|| {
        error(
            "INVALID_INPUT",
            format!("{field} must be an object."),
            json!({ "field": field }),
        )
    })
}

pub(crate) fn assert_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), Value> {
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return Err(error(
            "INVALID_INPUT",
            "Unknown fields are not allowed.",
            json!({ "unknownFields": unknown }),
        ));
    }
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|key| !object.contains_key(*key))
        .collect();
    if !missing.is_empty() {
        return Err(error(
            "INVALID_INPUT",
            "Required fields are missing.",
            json!({ "missingFields": missing }),
        ));
    }
    Ok(())
}

pub(crate) fn require_enum(
    value: Option<&Value>,
    field: &str,
    allowed: &[&str],
) -> Result<String, Value> {
    let candidate = value.and_then(Value::as_str);
    if !candidate.is_some_and(|item| allowed.contains(&item)) {
        return Err(error(
            "INVALID_INPUT",
            format!("{field} must be one of: {}.", allowed.join(", ")),
            json!({ "field": field, "allowed": allowed }),
        ));
    }
    Ok(candidate.expect("checked enum candidate").to_owned())
}

pub(crate) fn require_boolean(value: Option<&Value>, field: &str) -> Result<bool, Value> {
    value.and_then(Value::as_bool).ok_or_else(|| {
        error(
            "INVALID_INPUT",
            format!("{field} must be a boolean."),
            json!({ "field": field }),
        )
    })
}

pub(crate) fn require_integer(
    value: Option<&Value>,
    field: &str,
    minimum: usize,
    maximum: usize,
) -> Result<usize, Value> {
    let candidate = value.and_then(Value::as_u64);
    if !candidate.is_some_and(|item| item >= minimum as u64 && item <= maximum as u64) {
        return Err(error(
            "INVALID_INPUT",
            format!("{field} must be an integer from {minimum} to {maximum}."),
            json!({ "field": field, "minimum": minimum, "maximum": maximum }),
        ));
    }
    Ok(candidate.expect("checked integer candidate") as usize)
}

pub(crate) fn require_tagged_units(value: Option<&Value>, field: &str) -> Result<Vec<u16>, Value> {
    let tagged: TaggedTextValue = serde_json::from_value(value.cloned().unwrap_or(Value::Null))
        .map_err(|_| {
            error(
                "INVALID_INPUT",
                format!("{field} must be a string."),
                json!({ "field": field }),
            )
        })?;
    Ok(tagged.tagged.units())
}

pub(crate) fn utf8_length_from_units(units: &[u16]) -> usize {
    String::from_utf16_lossy(units).len()
}

pub(crate) fn require_encoding(value: Option<&Value>, field: &str) -> Result<String, Value> {
    let candidate = value.and_then(Value::as_str);
    if !candidate.is_some_and(|item| matches!(item, "utf-8" | "utf-16le")) {
        let requested_type = match value {
            None => "undefined",
            Some(Value::Null) => "null",
            Some(Value::Array(_)) => "array",
            Some(Value::Bool(_)) => "boolean",
            Some(Value::Number(_)) => "number",
            Some(Value::Object(_)) => "object",
            Some(Value::String(_)) => "string",
        };
        return Err(error(
            "UNSUPPORTED_ENCODING",
            format!("{field} is not supported."),
            json!({
                "field": field,
                "requestedType": requested_type,
                "supported": ["utf-8", "utf-16le"]
            }),
        ));
    }
    Ok(candidate.expect("checked encoding candidate").to_owned())
}

pub(crate) fn require_bytes(
    value: Option<&Value>,
    field: &str,
    maximum: usize,
) -> Result<Vec<u8>, Value> {
    let values = value.and_then(Value::as_array).ok_or_else(|| {
        error(
            "INVALID_INPUT",
            format!("{field} must be an array."),
            json!({ "field": field }),
        )
    })?;
    if values.len() > maximum {
        return Err(error(
            "REQUEST_TOO_LARGE",
            format!("{field} exceeds the {maximum}-item limit."),
            json!({ "field": field, "actualItems": values.len(), "limitItems": maximum }),
        ));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_u64()
                .filter(|byte| *byte <= u8::MAX as u64)
                .map(|byte| byte as u8)
                .ok_or_else(|| {
                    error(
                        "INVALID_INPUT",
                        "Every byte must be an integer from 0 to 255.",
                        json!({ "field": field, "index": index }),
                    )
                })
        })
        .collect()
}

pub(crate) fn require_text(value: Option<&Value>, field: &str) -> Result<String, Value> {
    let units = require_tagged_units(value, field)?;
    let actual_bytes = utf8_length_from_units(&units);
    if actual_bytes > MAX_TEXT_BYTES {
        return Err(error(
            "REQUEST_TOO_LARGE",
            format!("{field} exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({
                "field": field,
                "actualBytes": actual_bytes,
                "limitBytes": MAX_TEXT_BYTES
            }),
        ));
    }
    String::from_utf16(&units).map_err(|_| {
        error(
            "INVALID_UNICODE",
            format!("{field} contains an unpaired UTF-16 surrogate."),
            json!({ "field": field }),
        )
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{require_bytes, require_encoding, require_integer};

    #[test]
    fn shared_base_validators_preserve_public_error_details() {
        assert_eq!(
            require_integer(Some(&json!(1.5)), "detailLimit", 0, 128).unwrap_err(),
            json!({
                "status": "error",
                "error": {
                    "code": "INVALID_INPUT",
                    "message": "detailLimit must be an integer from 0 to 128.",
                    "details": { "field": "detailLimit", "minimum": 0, "maximum": 128 }
                }
            })
        );
        assert_eq!(
            require_encoding(None, "targetEncoding").unwrap_err()["error"]["details"]["requestedType"],
            "undefined"
        );
        assert_eq!(
            require_bytes(Some(&json!([0, 256])), "bytes", 4096).unwrap_err()["error"]["details"],
            json!({ "field": "bytes", "index": 1 })
        );
    }
}
