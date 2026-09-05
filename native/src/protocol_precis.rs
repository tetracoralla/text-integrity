use serde_json::{Value, json};

use crate::model::{enforce_result_budget, error};
use crate::precis_core::{Profile, enforce};
use crate::precis_witness::{SideTrace, WitnessMode, build_witness};
use crate::validation::{assert_keys, require_enum, require_object, require_text};

const MAX_COMBINED_TEXT_BYTES: usize = 8192;

struct Arguments {
    profile: Profile,
    action: String,
    text: String,
    comparison: Option<String>,
    witness_mode: WitnessMode,
}

fn parse_arguments(value: &Value) -> Result<Arguments, Value> {
    let object = require_object(value, "arguments")?;
    let compare = object.get("action").and_then(Value::as_str) == Some("compare");
    let mut required = vec!["profile", "action", "text"];
    if compare {
        required.push("comparison");
    }
    assert_keys(
        object,
        &["profile", "action", "text", "comparison", "witnessMode"],
        &required,
    )?;
    let action = require_enum(object.get("action"), "action", &["enforce", "compare"])?;
    let witness_label = if object.contains_key("witnessMode") {
        require_enum(
            object.get("witnessMode"),
            "witnessMode",
            &["none", "summary", "full_required"],
        )?
    } else {
        "none".to_owned()
    };
    if action == "enforce" && object.contains_key("comparison") {
        return Err(error(
            "INVALID_INPUT",
            "comparison is allowed only for the compare action.",
            json!({ "field": "comparison" }),
        ));
    }
    let text = require_text(object.get("text"), "text")?;
    let comparison = if action == "compare" {
        Some(require_text(object.get("comparison"), "comparison")?)
    } else {
        None
    };
    if text.len() + comparison.as_ref().map_or(0, String::len) > MAX_COMBINED_TEXT_BYTES {
        return Err(error(
            "REQUEST_TOO_LARGE",
            format!("Combined text fields exceed the {MAX_COMBINED_TEXT_BYTES}-byte UTF-8 limit."),
            json!({
                "fields": ["text", "comparison"],
                "actualBytes": text.len() + comparison.as_ref().map_or(0, String::len),
                "limitBytes": MAX_COMBINED_TEXT_BYTES
            }),
        ));
    }
    let profile = Profile::parse(
        object
            .get("profile")
            .and_then(Value::as_str)
            .expect("shared profile validation"),
    )
    .expect("shared profile routes PRECIS profiles");
    Ok(Arguments {
        profile,
        action,
        text,
        comparison,
        witness_mode: WitnessMode::parse(Some(&witness_label)).expect("validated witness mode"),
    })
}

pub(crate) fn run(arguments: Value) -> Value {
    let arguments = match parse_arguments(&arguments) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let profile = arguments.profile;
    let witness_mode = arguments.witness_mode;
    let text = arguments.text;
    let comparison = arguments.comparison;

    let mut text_trace = SideTrace::new(witness_mode, "text");
    let output = match enforce(&text, profile, &mut text_trace) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let mut comparison_trace = comparison
        .as_ref()
        .map(|_| SideTrace::new(witness_mode, "comparison"));
    let comparison_output = match (&comparison, &mut comparison_trace) {
        (Some(value), Some(trace)) => match enforce(value, profile, trace) {
            Ok(value) => Some(value),
            Err(value) => return value,
        },
        _ => None,
    };

    let mut result = json!({
        "status": "ok",
        "operation": "protocol_profile",
        "profile": profile.label(),
        "action": arguments.action,
        "output": output,
        "changed": output != text,
        "standards": {
            "framework": "RFC 8264",
            "profile": "RFC 8265",
            "unicodeVersion": "17.0.0"
        }
    });
    let object = result.as_object_mut().expect("PRECIS result is an object");
    if let (Some(comparison), Some(comparison_output)) = (&comparison, comparison_output) {
        object.insert("comparisonOutput".to_owned(), json!(comparison_output));
        object.insert(
            "comparisonChanged".to_owned(),
            json!(comparison_output != *comparison),
        );
        object.insert("equal".to_owned(), json!(output == comparison_output));
    }
    if witness_mode != WitnessMode::None {
        let mut traces = vec![text_trace];
        if let Some(trace) = comparison_trace {
            traces.push(trace);
        }
        object.insert(
            "witness".to_owned(),
            build_witness(witness_mode, profile.label(), traces),
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
    fn returns_the_complete_profile_result_and_witness() {
        let result = run(json!({
            "profile": "precis_username_case_mapped",
            "action": "enforce",
            "text": tagged("Ｕser"),
            "witnessMode": "full_required"
        }));
        assert_eq!(result["output"], "user");
        assert_eq!(result["witness"]["sides"][0]["stabilizedAfterPass"], 2);
        assert_eq!(
            result["witness"]["sides"][0]["passes"][0]["events"][0]["stage"],
            "width_mapping"
        );
    }

    #[test]
    fn compares_each_side_after_enforcement() {
        let result = run(json!({
            "profile": "precis_username_case_mapped",
            "action": "compare",
            "text": tagged("User"),
            "comparison": tagged("user"),
            "witnessMode": "summary"
        }));
        assert_eq!(result["equal"], true);
        assert_eq!(result["comparisonChanged"], false);
        assert_eq!(result["witness"]["sides"][1]["side"], "comparison");
    }
}
