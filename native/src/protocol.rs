use serde_json::Value;

use crate::validation::{require_enum, require_object};

const PROFILES: &[&str] = &[
    "uts46_domain",
    "precis_username_case_mapped",
    "precis_username_case_preserved",
    "precis_opaque_string",
];

pub(crate) fn run(arguments: Value) -> Value {
    let object = match require_object(&arguments, "arguments") {
        Ok(value) => value,
        Err(value) => return value,
    };
    let profile = match require_enum(object.get("profile"), "profile", PROFILES) {
        Ok(value) => value,
        Err(value) => return value,
    };
    if profile == "uts46_domain" {
        crate::protocol_uts46::run(arguments)
    } else {
        crate::protocol_precis::run(arguments)
    }
}
