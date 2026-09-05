use std::collections::HashSet;

use idna::punycode;
use idna_adapter::{
    Adapter, FIRST_BC_MASK, LAST_LTR_MASK, LAST_RTL_MASK, LEFT_OR_DUAL_JOINING_MASK,
    MIDDLE_LTR_MASK, MIDDLE_RTL_MASK, RIGHT_OR_DUAL_JOINING_MASK, RTL_MASK,
};
use serde_json::{Value, json};

use crate::model::{enforce_result_budget, error};
use crate::validation::{assert_keys, require_boolean, require_enum, require_object, require_text};

const ENGINE: &str = "rust-idna@1.1.0+idna_adapter@1.2.1";

struct Options {
    check_bidi: bool,
    check_hyphens: bool,
    check_joiners: bool,
    ignore_invalid_punycode: bool,
    transitional_processing: bool,
    use_std3_ascii_rules: bool,
    verify_dns_length: Option<bool>,
}

struct Arguments {
    action: String,
    text: String,
    options: Options,
    witness_mode: String,
}

fn protocol_error(action: &str) -> Value {
    error(
        "PROTOCOL_STRING_INVALID",
        "The domain name fails the selected UTS #46 processing rules.",
        json!({ "profile": "uts46_domain", "action": action }),
    )
}

fn transitional_map(input: &str, enabled: bool) -> String {
    if !enabled {
        return input.to_owned();
    }
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            'ß' | 'ẞ' => output.push_str("ss"),
            'ς' => output.push('σ'),
            '\u{200C}' | '\u{200D}' => {}
            _ => output.push(character),
        }
    }
    output
}

fn map_and_normalize(adapter: &Adapter, input: &str, transitional: bool) -> String {
    let transitional = transitional_map(input, transitional);
    adapter.map_normalize(transitional.chars()).collect()
}

fn is_std3_ascii(code_point: char) -> bool {
    code_point.is_ascii_lowercase() || code_point.is_ascii_digit() || code_point == '-'
}

fn has_valid_mapping_status(adapter: &Adapter, label: &str, use_std3: bool) -> bool {
    if label.contains('\u{FFFD}') {
        return false;
    }
    if adapter.normalize_validate(label.chars()).ne(label.chars()) {
        return false;
    }
    !use_std3
        || label
            .chars()
            .all(|code_point| !code_point.is_ascii() || is_std3_ascii(code_point))
}

fn has_valid_joiners(adapter: &Adapter, label: &[char]) -> bool {
    for (index, code_point) in label.iter().copied().enumerate() {
        if !matches!(code_point, '\u{200C}' | '\u{200D}') {
            continue;
        }
        let Some(previous) = index
            .checked_sub(1)
            .and_then(|value| label.get(value))
            .copied()
        else {
            return false;
        };
        if adapter.is_virama(previous) {
            continue;
        }
        if code_point == '\u{200D}' {
            return false;
        }

        let before = label[..index].iter().rev().copied().find_map(|character| {
            let joining = adapter.joining_type(character);
            (!joining.is_transparent()).then_some(joining)
        });
        let after = label[index + 1..].iter().copied().find_map(|character| {
            let joining = adapter.joining_type(character);
            (!joining.is_transparent()).then_some(joining)
        });
        if !before.is_some_and(|joining| joining.to_mask().intersects(LEFT_OR_DUAL_JOINING_MASK))
            || !after
                .is_some_and(|joining| joining.to_mask().intersects(RIGHT_OR_DUAL_JOINING_MASK))
        {
            return false;
        }
    }
    true
}

fn is_bidi_domain(adapter: &Adapter, labels: &[String]) -> bool {
    labels.iter().any(|label| {
        let decoded = label
            .strip_prefix("xn--")
            .and_then(punycode::decode_to_string);
        decoded
            .as_deref()
            .unwrap_or(label)
            .chars()
            .any(|code_point| RTL_MASK.intersects(adapter.bidi_class(code_point).to_mask()))
    })
}

fn has_valid_bidi(adapter: &Adapter, label: &[char], is_bidi: bool) -> bool {
    if !is_bidi || label.is_empty() {
        return true;
    }
    let first = adapter.bidi_class(label[0]);
    if !FIRST_BC_MASK.intersects(first.to_mask()) {
        return false;
    }
    let is_ltr = first.is_ltr();
    let middle_mask = if is_ltr {
        MIDDLE_LTR_MASK
    } else {
        MIDDLE_RTL_MASK
    };
    if label[1..]
        .iter()
        .copied()
        .any(|code_point| !middle_mask.intersects(adapter.bidi_class(code_point).to_mask()))
    {
        return false;
    }
    let Some(last) = label
        .iter()
        .rev()
        .copied()
        .find(|code_point| !adapter.bidi_class(*code_point).is_nonspacing_mark())
    else {
        return false;
    };
    let last_mask = if is_ltr { LAST_LTR_MASK } else { LAST_RTL_MASK };
    if !last_mask.intersects(adapter.bidi_class(last).to_mask()) {
        return false;
    }
    if !is_ltr {
        let has_european = label
            .iter()
            .copied()
            .any(|code_point| adapter.bidi_class(code_point).is_european_number());
        let has_arabic = label
            .iter()
            .copied()
            .any(|code_point| adapter.bidi_class(code_point).is_arabic_number());
        if has_european && has_arabic {
            return false;
        }
    }
    true
}

fn validate_label(
    adapter: &Adapter,
    label: &str,
    options: &Options,
    transitional: bool,
    is_bidi: bool,
) -> bool {
    if label.is_empty() {
        return true;
    }
    let code_points: Vec<char> = label.chars().collect();
    if options.check_hyphens
        && ((code_points.get(2) == Some(&'-') && code_points.get(3) == Some(&'-'))
            || label.starts_with('-')
            || label.ends_with('-'))
    {
        return false;
    }
    if !options.check_hyphens && label.starts_with("xn--") {
        return false;
    }
    if label.contains('.') || adapter.is_mark(code_points[0]) {
        return false;
    }
    if !has_valid_mapping_status(adapter, label, options.use_std3_ascii_rules) {
        return false;
    }
    if transitional
        && code_points
            .iter()
            .any(|code_point| matches!(code_point, 'ß' | 'ς' | '\u{200C}' | '\u{200D}'))
    {
        return false;
    }
    if options.check_joiners && !has_valid_joiners(adapter, &code_points) {
        return false;
    }
    has_valid_bidi(adapter, &code_points, options.check_bidi && is_bidi)
}

fn process(input: &str, options: &Options) -> Result<String, ()> {
    let adapter = Adapter::new();
    let mapped = map_and_normalize(&adapter, input, options.transitional_processing);
    let source_labels: Vec<String> = mapped.split('.').map(str::to_owned).collect();
    let is_bidi = is_bidi_domain(&adapter, &source_labels);
    let mut labels = Vec::with_capacity(source_labels.len());
    for source in source_labels {
        let mut label = source;
        let mut transitional = options.transitional_processing;
        if let Some(encoded) = label.strip_prefix("xn--") {
            if !label.is_ascii() {
                return Err(());
            }
            match punycode::decode_to_string(encoded) {
                Some(decoded) => label = decoded,
                None if !options.ignore_invalid_punycode => return Err(()),
                None => {}
            }
            if label.is_empty() || label.is_ascii() {
                return Err(());
            }
            transitional = false;
        }
        if !validate_label(&adapter, &label, options, transitional, is_bidi) {
            return Err(());
        }
        labels.push(label);
    }
    Ok(labels.join("."))
}

fn to_ascii(input: &str, options: &Options) -> Result<String, ()> {
    let unicode = process(input, options)?;
    let mut labels = Vec::new();
    for label in unicode.split('.') {
        if label.is_ascii() {
            labels.push(label.to_owned());
        } else {
            let encoded = punycode::encode_str(label).ok_or(())?;
            labels.push(format!("xn--{encoded}"));
        }
    }
    let output = labels.join(".");
    if options.verify_dns_length == Some(true)
        && (output.is_empty()
            || output.len() > 253
            || labels
                .iter()
                .any(|label| label.is_empty() || label.len() > 63))
    {
        return Err(());
    }
    Ok(output)
}

pub(crate) fn raw_punycode_scan_units(arguments: &Value) -> u64 {
    let arguments = match parse_arguments(arguments) {
        Ok(value) if value.action == "to_ascii" => value,
        _ => return 0,
    };
    let unicode = match process(&arguments.text, &arguments.options) {
        Ok(value) => value,
        Err(()) => return 0,
    };
    unicode
        .split('.')
        .filter(|label| !label.is_ascii())
        .map(|label| {
            let code_point_count = label.chars().count() as u64;
            let distinct_non_ascii = label
                .chars()
                .filter(|code_point| !code_point.is_ascii())
                .collect::<HashSet<_>>()
                .len() as u64;
            code_point_count * distinct_non_ascii
        })
        .sum()
}

fn stage(stage: &str, text: &str) -> Value {
    json!({
        "stage": stage,
        "text": text,
        "codePointCount": text.chars().count(),
        "ascii": text.is_ascii()
    })
}

fn witness(mode: &str, action: &str, input: &str, output: &str) -> Value {
    let mut value = json!({
        "kind": "uts46",
        "mode": mode,
        "specification": "UTS #46 revision 35",
        "engine": ENGINE,
        "action": action,
        "inputCodePointCount": input.chars().count(),
        "outputCodePointCount": output.chars().count(),
        "inputAscii": input.is_ascii(),
        "outputAscii": output.is_ascii(),
        "inputTrailingRoot": input.ends_with('.'),
        "outputTrailingRoot": output.ends_with('.'),
        "changed": input != output
    });
    if mode == "full_required" {
        value["stages"] = json!([stage("input", input), stage("engine_output", output)]);
    }
    value
}

fn has_compatibility_empty_label(output: &str) -> bool {
    if output.is_empty() {
        return true;
    }
    let labels: Vec<&str> = output.split('.').collect();
    labels[..labels.len().saturating_sub(1)]
        .iter()
        .any(|label| label.is_empty())
}

fn parse_arguments(value: &Value) -> Result<Arguments, Value> {
    let object = require_object(value, "arguments")?;
    assert_keys(
        object,
        &["profile", "action", "text", "options", "witnessMode"],
        &["profile", "action", "text", "options"],
    )?;
    let action = require_enum(object.get("action"), "action", &["to_ascii", "to_unicode"])?;
    let witness_mode = if object.contains_key("witnessMode") {
        require_enum(
            object.get("witnessMode"),
            "witnessMode",
            &["none", "summary", "full_required"],
        )?
    } else {
        "none".to_owned()
    };
    let text = require_text(object.get("text"), "text")?;
    let option_object = require_object(object.get("options").expect("required option"), "options")?;
    let mut option_fields = vec![
        "checkBidi",
        "checkHyphens",
        "checkJoiners",
        "ignoreInvalidPunycode",
        "transitionalProcessing",
        "useSTD3ASCIIRules",
    ];
    if action == "to_ascii" {
        option_fields.push("verifyDNSLength");
    }
    assert_keys(option_object, &option_fields, &option_fields)?;
    let options = Options {
        check_bidi: require_boolean(option_object.get("checkBidi"), "options.checkBidi")?,
        check_hyphens: require_boolean(option_object.get("checkHyphens"), "options.checkHyphens")?,
        check_joiners: require_boolean(option_object.get("checkJoiners"), "options.checkJoiners")?,
        ignore_invalid_punycode: require_boolean(
            option_object.get("ignoreInvalidPunycode"),
            "options.ignoreInvalidPunycode",
        )?,
        transitional_processing: require_boolean(
            option_object.get("transitionalProcessing"),
            "options.transitionalProcessing",
        )?,
        use_std3_ascii_rules: require_boolean(
            option_object.get("useSTD3ASCIIRules"),
            "options.useSTD3ASCIIRules",
        )?,
        verify_dns_length: if action == "to_ascii" {
            Some(require_boolean(
                option_object.get("verifyDNSLength"),
                "options.verifyDNSLength",
            )?)
        } else {
            None
        },
    };
    Ok(Arguments {
        action,
        text,
        options,
        witness_mode,
    })
}

pub fn run(arguments: Value) -> Value {
    let arguments = match parse_arguments(&arguments) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let input = arguments.text;

    let output = if arguments.action == "to_ascii" {
        match to_ascii(&input, &arguments.options) {
            Ok(value) => value,
            Err(()) => return protocol_error(&arguments.action),
        }
    } else {
        match process(&input, &arguments.options) {
            Ok(value) if !has_compatibility_empty_label(&value) => value,
            _ => return protocol_error(&arguments.action),
        }
    };

    let witness_mode = arguments.witness_mode.as_str();
    let mut result = json!({
        "status": "ok",
        "operation": "protocol_profile",
        "profile": "uts46_domain",
        "action": arguments.action,
        "output": output,
        "changed": output != input,
        "options": {
            "checkBidi": arguments.options.check_bidi,
            "checkHyphens": arguments.options.check_hyphens,
            "checkJoiners": arguments.options.check_joiners,
            "ignoreInvalidPunycode": arguments.options.ignore_invalid_punycode,
            "transitionalProcessing": arguments.options.transitional_processing,
            "useSTD3ASCIIRules": arguments.options.use_std3_ascii_rules,
            "verifyDNSLength": arguments.options.verify_dns_length
        },
        "standards": {
            "specification": "UTS #46 revision 35",
            "unicodeVersion": "17.0.0",
            "engine": ENGINE
        },
        "witness": witness(witness_mode, &arguments.action, &input, &output)
    });
    let object = result.as_object_mut().expect("static result object");
    if arguments.action == "to_unicode" {
        object
            .get_mut("options")
            .and_then(Value::as_object_mut)
            .expect("static options object")
            .remove("verifyDNSLength");
    }
    if witness_mode == "none" {
        object.remove("witness");
    }
    enforce_result_budget(result)
}

#[cfg(test)]
mod tests {
    use super::{ENGINE, run};
    use serde_json::json;

    fn request(check_bidi: bool) -> serde_json::Value {
        json!({
            "profile": "uts46_domain",
            "action": "to_ascii",
            "text": { "$text": { "kind": "unicode_scalar_string", "value": "faß.de" } },
            "options": {
                "checkBidi": check_bidi,
                "checkHyphens": true,
                "checkJoiners": true,
                "ignoreInvalidPunycode": false,
                "transitionalProcessing": false,
                "useSTD3ASCIIRules": true,
                "verifyDNSLength": true
            },
            "witnessMode": "summary"
        })
    }

    #[test]
    fn preserves_the_independent_engine_identity() {
        let result = run(request(true));
        assert_eq!(result["output"], "xn--fa-hia.de");
        assert_eq!(result["standards"]["engine"], ENGINE);
        assert_eq!(result["witness"]["engine"], ENGINE);
    }

    #[test]
    fn accepts_each_configurable_bidi_mode() {
        let result = run(request(false));
        assert_eq!(result["output"], "xn--fa-hia.de");
        assert_eq!(result["options"]["checkBidi"], false);
    }
}
