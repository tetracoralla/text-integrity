use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::bidi_reorder::{self, Direction};
use crate::model::{MAX_RESULT_BYTES, MAX_TEXT_BYTES, enforce_result_budget, error};
use crate::security_data::{SOURCE_MANIFEST_SHA256, SOURCE_ROOT, UNICODE_VERSION, UTS39_REVISION};
use crate::validation::{assert_keys, require_boolean, require_enum, require_object, require_text};

const MAX_ITEMS: usize = 512;
const MAX_RELATIONS: usize = 5;
const MAX_CUMULATIVE_TEXT_BYTES: usize = 65536;
const MAX_ID_CHARS: usize = 128;
const MAX_SCOPE_CHARS: usize = 64;
const SIMPLE_RELATIONS: &[&str] = &["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable"];
const PROTOCOL_PROFILES: &[&str] = &[
    "uts46_domain",
    "precis_username_case_mapped",
    "precis_username_case_preserved",
    "precis_opaque_string",
];
const DIRECTIONS: &[&str] = &["LTR", "RTL", "FS"];

#[derive(Clone, Debug)]
struct Item {
    id: String,
    text: String,
    scope: String,
}

#[derive(Clone, Debug)]
enum Plan {
    Simple {
        relation: String,
    },
    Protocol {
        definition: Value,
        configuration_sha256: String,
    },
}

impl Plan {
    fn relation(&self) -> &str {
        match self {
            Self::Simple { relation } => relation,
            Self::Protocol { .. } => "protocol",
        }
    }

    fn identity(&self) -> String {
        match self {
            Self::Simple { relation } => format!("simple:{relation}"),
            Self::Protocol {
                configuration_sha256,
                ..
            } => format!("protocol:{configuration_sha256}"),
        }
    }

    fn configuration_sha256(&self) -> Option<&str> {
        match self {
            Self::Simple { .. } => None,
            Self::Protocol {
                configuration_sha256,
                ..
            } => Some(configuration_sha256),
        }
    }
}

fn sha256(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn tagged_text(value: &str) -> Value {
    json!({ "$text": { "kind": "unicode_scalar_string", "value": value } })
}

fn require_array<'a>(
    value: Option<&'a Value>,
    field: &str,
    maximum: usize,
) -> Result<&'a Vec<Value>, Value> {
    let array = value.and_then(Value::as_array).ok_or_else(|| {
        error(
            "INVALID_INPUT",
            format!("{field} must be an array."),
            json!({ "field": field }),
        )
    })?;
    if array.len() > maximum {
        return Err(error(
            "REQUEST_TOO_LARGE",
            format!("{field} exceeds the {maximum}-item limit."),
            json!({ "field": field, "actualItems": array.len(), "limitItems": maximum }),
        ));
    }
    Ok(array)
}

fn bounded_string(value: Option<&Value>, field: &str, maximum: usize) -> Result<String, Value> {
    let text = value.and_then(Value::as_str).ok_or_else(|| {
        error(
            "INVALID_INPUT",
            format!("{field} must be a string."),
            json!({ "field": field }),
        )
    })?;
    let length = text.encode_utf16().count();
    if text.is_empty() || length > maximum {
        return Err(error(
            "INVALID_INPUT",
            format!("{field} must contain 1 to {maximum} characters."),
            json!({ "field": field, "minimum": 1, "maximum": maximum }),
        ));
    }
    Ok(text.to_owned())
}

fn parse_uts46_options(value: Option<&Value>, action: &str, field: &str) -> Result<Value, Value> {
    let options = require_object(value.unwrap_or(&Value::Null), field)?;
    let mut keys = vec![
        "checkBidi",
        "checkHyphens",
        "checkJoiners",
        "ignoreInvalidPunycode",
        "transitionalProcessing",
        "useSTD3ASCIIRules",
    ];
    if action == "to_ascii" {
        keys.push("verifyDNSLength");
    }
    assert_keys(options, &keys, &keys)?;
    let mut output = Map::new();
    for key in keys {
        output.insert(
            key.to_owned(),
            json!(require_boolean(
                options.get(key),
                &format!("{field}.{key}")
            )?),
        );
    }
    Ok(Value::Object(output))
}

fn bool_literal(value: &Value, key: &str) -> &'static str {
    if value[key].as_bool().expect("validated Boolean option") {
        "true"
    } else {
        "false"
    }
}

fn protocol_configuration_json(profile: &str, action: &str, options: Option<&Value>) -> String {
    if let Some(options) = options {
        let mut output = format!(
            "{{\"kind\":\"protocol\",\"profile\":\"{profile}\",\"action\":\"{action}\",\"options\":{{"
        );
        let mut keys = vec![
            "checkBidi",
            "checkHyphens",
            "checkJoiners",
            "ignoreInvalidPunycode",
            "transitionalProcessing",
            "useSTD3ASCIIRules",
        ];
        if action == "to_ascii" {
            keys.push("verifyDNSLength");
        }
        for (index, key) in keys.into_iter().enumerate() {
            if index > 0 {
                output.push(',');
            }
            output.push_str(&format!("\"{key}\":{}", bool_literal(options, key)));
        }
        output.push_str("}}");
        output
    } else {
        format!("{{\"kind\":\"protocol\",\"profile\":\"{profile}\",\"action\":\"{action}\"}}")
    }
}

fn parse_relation(input: &Value, index: usize) -> Result<Plan, Value> {
    let field = format!("relations[{index}]");
    if input.is_string() {
        return Ok(Plan::Simple {
            relation: require_enum(Some(input), &field, SIMPLE_RELATIONS)?,
        });
    }
    let object = require_object(input, &field)?;
    let kind = require_enum(
        object.get("kind"),
        &format!("{field}.kind"),
        &["protocol", "declared_collation"],
    )?;
    if kind == "declared_collation" {
        return Err(error(
            "UNSUPPORTED_REFERENCE_SCOPE",
            "The independent namespace reference does not execute declared_collation.",
            json!({ "field": field, "excludedRelation": "declared_collation" }),
        ));
    }
    let profile = require_enum(
        object.get("profile"),
        &format!("{field}.profile"),
        PROTOCOL_PROFILES,
    )?;
    let (action, options) = if profile == "uts46_domain" {
        assert_keys(
            object,
            &["kind", "profile", "action", "options"],
            &["kind", "profile", "action", "options"],
        )?;
        let action = require_enum(
            object.get("action"),
            &format!("{field}.action"),
            &["to_ascii", "to_unicode"],
        )?;
        let options =
            parse_uts46_options(object.get("options"), &action, &format!("{field}.options"))?;
        (action, Some(options))
    } else {
        assert_keys(
            object,
            &["kind", "profile", "action"],
            &["kind", "profile", "action"],
        )?;
        (
            require_enum(
                object.get("action"),
                &format!("{field}.action"),
                &["enforce"],
            )?,
            None,
        )
    };
    let configuration_json = protocol_configuration_json(&profile, &action, options.as_ref());
    let mut definition = Map::new();
    definition.insert("kind".to_owned(), json!("protocol"));
    definition.insert("profile".to_owned(), json!(profile));
    definition.insert("action".to_owned(), json!(action));
    if let Some(options) = options {
        definition.insert("options".to_owned(), options);
    }
    Ok(Plan::Protocol {
        definition: Value::Object(definition),
        configuration_sha256: sha256(&configuration_json),
    })
}

fn relation_key(item: &Item, plan: &Plan, direction: Option<Direction>) -> Result<String, Value> {
    match plan {
        Plan::Simple { relation } => match relation.as_str() {
            "exact" => Ok(item.text.clone()),
            "nfc" => Ok(crate::normalize::apply(&item.text, "NFC")),
            "nfkc" => Ok(crate::normalize::apply(&item.text, "NFKC")),
            "nfkc_casefold" => Ok(crate::nfkc_casefold::apply(&item.text)),
            "uts39_confusable" => Ok(bidi_reorder::skeleton(
                &item.text,
                direction.expect("confusable relation requires direction"),
            )),
            _ => unreachable!("simple relation is closed"),
        },
        Plan::Protocol { definition, .. } => {
            let mut arguments = definition
                .as_object()
                .expect("protocol definition is an object")
                .clone();
            arguments.remove("kind");
            arguments.insert("text".to_owned(), tagged_text(&item.text));
            let result = crate::protocol::run(Value::Object(arguments));
            if result.get("status").and_then(Value::as_str) == Some("error") {
                return Err(result);
            }
            Ok(result["output"]
                .as_str()
                .expect("successful protocol result has output")
                .to_owned())
        }
    }
}

fn groups_for_plan(
    items: &[Item],
    plan: &Plan,
    direction: Option<Direction>,
) -> Result<Vec<Value>, Value> {
    let mut scopes: HashMap<String, HashMap<String, Vec<&Item>>> = HashMap::new();
    for item in items {
        let key = relation_key(item, plan, direction)?;
        scopes
            .entry(item.scope.clone())
            .or_default()
            .entry(key)
            .or_default()
            .push(item);
    }
    let mut ordered_scopes: Vec<_> = scopes.into_iter().collect();
    ordered_scopes.sort_by(|(left, _), (right, _)| compare_utf16(left, right));
    let mut groups = Vec::new();
    for (scope, buckets) in ordered_scopes {
        for (key, bucket) in buckets {
            if bucket.len() < 2 {
                continue;
            }
            let distinct_text_count = bucket
                .iter()
                .map(|item| item.text.as_str())
                .collect::<HashSet<_>>()
                .len();
            if plan.relation() != "exact" && distinct_text_count < 2 {
                continue;
            }
            let mut member_ids: Vec<_> = bucket.iter().map(|item| item.id.clone()).collect();
            member_ids.sort_by(|left, right| compare_utf16(left, right));
            let mut group = Map::new();
            group.insert("relation".to_owned(), json!(plan.relation()));
            if let Some(configuration_sha256) = plan.configuration_sha256() {
                group.insert(
                    "configurationSha256".to_owned(),
                    json!(configuration_sha256),
                );
            }
            group.insert("scope".to_owned(), json!(scope));
            group.insert("keySha256".to_owned(), json!(sha256(&key)));
            group.insert("distinctTextCount".to_owned(), json!(distinct_text_count));
            group.insert("memberIds".to_owned(), json!(member_ids));
            groups.push(Value::Object(group));
        }
    }
    groups.sort_by(|left, right| {
        compare_utf16(
            left["scope"].as_str().expect("group scope is a string"),
            right["scope"].as_str().expect("group scope is a string"),
        )
        .then_with(|| {
            compare_utf16(
                left["keySha256"]
                    .as_str()
                    .expect("group key hash is a string"),
                right["keySha256"]
                    .as_str()
                    .expect("group key hash is a string"),
            )
        })
    });
    Ok(groups)
}

fn relation_summary(plan: &Plan, group_count: usize) -> Value {
    match plan {
        Plan::Simple { relation } => json!({
            "relation": relation,
            "groupCount": group_count
        }),
        Plan::Protocol {
            definition,
            configuration_sha256,
        } => json!({
            "relation": "protocol",
            "configurationSha256": configuration_sha256,
            "definition": definition,
            "groupCount": group_count
        }),
    }
}

fn parse_direction(value: Option<&Value>) -> Result<(String, Direction), Value> {
    let label = require_enum(value, "confusableDirection", DIRECTIONS)?;
    let direction = match label.as_str() {
        "LTR" => Direction::Ltr,
        "RTL" => Direction::Rtl,
        "FS" => Direction::FirstStrong,
        _ => unreachable!("direction is closed"),
    };
    Ok((label, direction))
}

pub(crate) fn run(arguments: Value) -> Value {
    let object = match require_object(&arguments, "arguments") {
        Ok(value) => value,
        Err(value) => return value,
    };
    if let Err(value) = assert_keys(
        object,
        &["items", "relations", "confusableDirection"],
        &["items", "relations"],
    ) {
        return value;
    }
    let input_items = match require_array(object.get("items"), "items", MAX_ITEMS) {
        Ok(value) => value,
        Err(value) => return value,
    };
    let input_relations = match require_array(object.get("relations"), "relations", MAX_RELATIONS) {
        Ok(value) => value,
        Err(value) => return value,
    };
    if input_relations.is_empty() {
        return error(
            "INVALID_INPUT",
            "relations must contain at least one named relation.",
            json!({ "field": "relations", "minimum": 1, "maximum": MAX_RELATIONS }),
        );
    }
    let mut plans = Vec::with_capacity(input_relations.len());
    for (index, relation) in input_relations.iter().enumerate() {
        match parse_relation(relation, index) {
            Ok(plan) => plans.push(plan),
            Err(value) => return value,
        }
    }
    let identities: HashSet<_> = plans.iter().map(Plan::identity).collect();
    if identities.len() != plans.len() {
        return error(
            "INVALID_INPUT",
            "relations must not contain duplicates.",
            json!({ "field": "relations" }),
        );
    }

    let needs_direction = plans
        .iter()
        .any(|plan| plan.relation() == "uts39_confusable");
    let (direction_label, direction) = if needs_direction {
        if !object.contains_key("confusableDirection") {
            return error(
                "INVALID_INPUT",
                "confusableDirection is required for uts39_confusable.",
                json!({ "field": "confusableDirection" }),
            );
        }
        match parse_direction(object.get("confusableDirection")) {
            Ok((label, direction)) => (Some(label), Some(direction)),
            Err(value) => return value,
        }
    } else if object.contains_key("confusableDirection") {
        return error(
            "INVALID_INPUT",
            "confusableDirection is allowed only for uts39_confusable.",
            json!({ "field": "confusableDirection" }),
        );
    } else {
        (None, None)
    };

    let mut ids = HashSet::new();
    let mut items = Vec::with_capacity(input_items.len());
    let mut cumulative_text_utf8_bytes = 0usize;
    for (index, input) in input_items.iter().enumerate() {
        let field = format!("items[{index}]");
        let input = match require_object(input, &field) {
            Ok(value) => value,
            Err(value) => return value,
        };
        if let Err(value) = assert_keys(input, &["id", "text", "scope"], &["id", "text", "scope"]) {
            return value;
        }
        let id = match bounded_string(input.get("id"), &format!("{field}.id"), MAX_ID_CHARS) {
            Ok(value) => value,
            Err(value) => return value,
        };
        if !ids.insert(id.clone()) {
            return error(
                "DUPLICATE_ITEM_ID",
                "Namespace item IDs must be unique.",
                json!({ "id": id }),
            );
        }
        let scope = match bounded_string(
            input.get("scope"),
            &format!("{field}.scope"),
            MAX_SCOPE_CHARS,
        ) {
            Ok(value) => value,
            Err(value) => return value,
        };
        let text = match require_text(input.get("text"), &format!("{field}.text")) {
            Ok(value) => value,
            Err(value) => return value,
        };
        cumulative_text_utf8_bytes += text.len();
        items.push(Item { id, text, scope });
    }
    if cumulative_text_utf8_bytes > MAX_CUMULATIVE_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!(
                "Namespace text exceeds the {MAX_CUMULATIVE_TEXT_BYTES}-byte cumulative limit."
            ),
            json!({
                "field": "items[].text",
                "actualBytes": cumulative_text_utf8_bytes,
                "limitBytes": MAX_CUMULATIVE_TEXT_BYTES
            }),
        );
    }

    let mut groups = Vec::new();
    let mut relations = Vec::with_capacity(plans.len());
    for plan in &plans {
        let plan_groups = match groups_for_plan(&items, plan, direction) {
            Ok(value) => value,
            Err(value) => return value,
        };
        relations.push(relation_summary(plan, plan_groups.len()));
        groups.extend(plan_groups);
    }
    let grouped_ids: HashSet<_> = groups
        .iter()
        .flat_map(|group| {
            group["memberIds"]
                .as_array()
                .expect("group member IDs are an array")
                .iter()
                .map(|id| id.as_str().expect("group member ID is a string"))
        })
        .collect();
    let mut isolated_ids: Vec<_> = items
        .iter()
        .filter(|item| !grouped_ids.contains(item.id.as_str()))
        .map(|item| item.id.clone())
        .collect();
    isolated_ids.sort_by(|left, right| compare_utf16(left, right));
    let scope_count = items
        .iter()
        .map(|item| item.scope.as_str())
        .collect::<HashSet<_>>()
        .len();

    enforce_result_budget(json!({
        "status": "ok",
        "operation": "namespace_integrity",
        "relations": relations,
        "confusableDirection": direction_label,
        "groups": groups,
        "isolatedIds": isolated_ids,
        "summary": {
            "inputCount": items.len(),
            "scopeCount": scope_count,
            "relationCount": plans.len(),
            "collisionGroupCount": groups.len(),
            "groupedItemCount": grouped_ids.len(),
            "isolatedItemCount": isolated_ids.len(),
            "cumulativeTextUtf8Bytes": cumulative_text_utf8_bytes
        },
        "limits": {
            "maxItems": MAX_ITEMS,
            "maxRelations": MAX_RELATIONS,
            "maxTextBytesPerItem": MAX_TEXT_BYTES,
            "maxCumulativeTextBytes": MAX_CUMULATIVE_TEXT_BYTES,
            "maxResultBytes": MAX_RESULT_BYTES
        },
        "data": {
            "unicodeVersion": UNICODE_VERSION,
            "uts39Revision": UTS39_REVISION,
            "sourceRoot": SOURCE_ROOT,
            "license": "Unicode License V3",
            "manifestSha256": SOURCE_MANIFEST_SHA256,
            "offline": true
        },
        "limitations": [
            "Groups report equality under only the explicitly requested relation and scope.",
            "Protocol key material is represented only by SHA-256; normalization outputs, protocol outputs, and confusable skeletons are not returned as replacement text.",
            "Key digests are identities, not anonymization; low-entropy normalization, protocol, or skeleton values can be enumerated offline.",
            "Declared collation groups use the current runtime-resolved ICU comparator and a member-set digest because ICU does not expose a stable public sort key.",
            "The result does not decide whether a name is malicious, acceptable, unique under an application policy, or authorized for registration."
        ]
    }))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::run;

    fn tagged(value: &str) -> Value {
        json!({ "$text": { "kind": "unicode_scalar_string", "value": value } })
    }

    #[test]
    fn uses_deterministic_utf16_order_for_scopes_and_members() {
        let result = run(json!({
            "items": [
                { "id": "\u{e000}", "text": tagged("first"), "scope": "\u{e000}" },
                { "id": "\u{e001}", "text": tagged("first"), "scope": "\u{e000}" },
                { "id": "\u{10000}", "text": tagged("second"), "scope": "\u{10000}" },
                { "id": "\u{10001}", "text": tagged("second"), "scope": "\u{10000}" }
            ],
            "relations": ["exact"]
        }));
        assert_eq!(result["status"], "ok");
        assert_eq!(result["groups"].as_array().unwrap().len(), 2);
        assert_eq!(result["groups"][0]["scope"], "\u{10000}");
        assert_eq!(result["groups"][1]["scope"], "\u{e000}");
    }

    #[test]
    fn composes_protocol_outputs_and_propagates_profile_errors() {
        let options = json!({
            "checkBidi": true,
            "checkHyphens": true,
            "checkJoiners": true,
            "ignoreInvalidPunycode": false,
            "transitionalProcessing": false,
            "useSTD3ASCIIRules": true,
            "verifyDNSLength": true
        });
        let result = run(json!({
            "items": [
                { "id": "unicode", "text": tagged("faß.de"), "scope": "domains" },
                { "id": "ascii", "text": tagged("xn--fa-hia.de"), "scope": "domains" }
            ],
            "relations": [{
                "kind": "protocol", "profile": "uts46_domain", "action": "to_ascii",
                "options": options
            }]
        }));
        assert_eq!(result["status"], "ok");
        assert_eq!(
            result["groups"][0]["memberIds"],
            json!(["ascii", "unicode"])
        );

        let invalid = run(json!({
            "items": [{ "id": "bad", "text": tagged("-bad"), "scope": "domains" }],
            "relations": [{
                "kind": "protocol", "profile": "uts46_domain", "action": "to_ascii",
                "options": options
            }]
        }));
        assert_eq!(invalid["error"]["code"], "PROTOCOL_STRING_INVALID");
    }
}
