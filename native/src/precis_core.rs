use serde_json::{Value, json};
use unicode_normalization::char::canonical_combining_class;

use crate::bidi_reorder::bidi_class_label;
use crate::confusable::script_extensions;
use crate::model::error;
use crate::normalize;
use crate::precis_data::{
    CASE_IGNORABLE_RANGES, CASED_RANGES, DEFAULT_IGNORABLE_RANGES, GENERAL_CATEGORY_NAMES,
    GENERAL_CATEGORY_RANGES, JOIN_CONTROL_RANGES, JOINING_TYPE_NAMES, JOINING_TYPE_RANGES,
    LOWERCASE_MAPPINGS, NONCHARACTER_RANGES, OLD_HANGUL_JAMO_RANGES, UNASSIGNED_RANGES,
    WIDTH_MAPPINGS,
};
use crate::precis_witness::SideTrace;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    UsernameCaseMapped,
    UsernameCasePreserved,
    OpaqueString,
}

impl Profile {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "precis_username_case_mapped" => Some(Self::UsernameCaseMapped),
            "precis_username_case_preserved" => Some(Self::UsernameCasePreserved),
            "precis_opaque_string" => Some(Self::OpaqueString),
            _ => None,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::UsernameCaseMapped => "precis_username_case_mapped",
            Self::UsernameCasePreserved => "precis_username_case_preserved",
            Self::OpaqueString => "precis_opaque_string",
        }
    }

    fn is_username(self) -> bool {
        self != Self::OpaqueString
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Property {
    Pvalid,
    ContextJ,
    ContextO,
    Disallowed,
    Unassigned,
}

impl Property {
    fn label(self) -> &'static str {
        match self {
            Self::Pvalid => "PVALID",
            Self::ContextJ => "CONTEXTJ",
            Self::ContextO => "CONTEXTO",
            Self::Disallowed => "DISALLOWED",
            Self::Unassigned => "UNASSIGNED",
        }
    }
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

fn mapping(table: &[(u32, &'static str)], code_point: u32) -> Option<&'static str> {
    table
        .binary_search_by_key(&code_point, |(source, _)| *source)
        .ok()
        .map(|index| table[index].1)
}

fn general_category(code_point: u32) -> &'static str {
    let code = range_u8(GENERAL_CATEGORY_RANGES, code_point)
        .expect("generated General_Category table covers every code point");
    GENERAL_CATEGORY_NAMES[usize::from(code)]
}

fn joining_type(code_point: u32) -> &'static str {
    range_u8(JOINING_TYPE_RANGES, code_point)
        .map(|code| JOINING_TYPE_NAMES[usize::from(code)])
        .unwrap_or("U")
}

fn exception(code_point: u32) -> Option<Property> {
    match code_point {
        0x00df | 0x03c2 | 0x06fd | 0x06fe | 0x0f0b | 0x3007 => Some(Property::Pvalid),
        0x00b7 | 0x0375 | 0x05f3 | 0x05f4 | 0x30fb | 0x0660..=0x0669 | 0x06f0..=0x06f9 => {
            Some(Property::ContextO)
        }
        0x0640 | 0x07fa | 0x302e | 0x302f | 0x3031..=0x3035 | 0x303b => Some(Property::Disallowed),
        _ => None,
    }
}

fn precis_property(code_point: u32, freeform: bool) -> Property {
    if let Some(property) = exception(code_point) {
        return property;
    }
    if range_contains(UNASSIGNED_RANGES, code_point)
        && !range_contains(NONCHARACTER_RANGES, code_point)
    {
        return Property::Unassigned;
    }
    if (0x21..=0x7e).contains(&code_point) {
        return Property::Pvalid;
    }
    if range_contains(JOIN_CONTROL_RANGES, code_point) {
        return Property::ContextJ;
    }
    if range_contains(OLD_HANGUL_JAMO_RANGES, code_point) {
        return Property::Disallowed;
    }
    if range_contains(DEFAULT_IGNORABLE_RANGES, code_point)
        || range_contains(NONCHARACTER_RANGES, code_point)
    {
        return Property::Disallowed;
    }
    let category = general_category(code_point);
    if category == "Cc" {
        return Property::Disallowed;
    }
    let character = char::from_u32(code_point).expect("PRECIS input is a Unicode scalar");
    let source = character.to_string();
    if normalize::apply(&source, "NFKC") != source {
        return if freeform {
            Property::Pvalid
        } else {
            Property::Disallowed
        };
    }
    if matches!(category, "Ll" | "Lu" | "Lo" | "Nd" | "Lm" | "Mn" | "Mc") {
        return Property::Pvalid;
    }
    if matches!(
        category,
        "Lt" | "Nl"
            | "No"
            | "Me"
            | "Zs"
            | "Sm"
            | "Sc"
            | "Sk"
            | "So"
            | "Pc"
            | "Pd"
            | "Ps"
            | "Pe"
            | "Pi"
            | "Pf"
            | "Po"
    ) {
        return if freeform {
            Property::Pvalid
        } else {
            Property::Disallowed
        };
    }
    Property::Disallowed
}

fn script_is(code_point: u32, script: &str) -> bool {
    script_extensions(code_point).contains(&script)
}

fn context_rule(code_points: &[u32], index: usize) -> bool {
    let code_point = code_points[index];
    let previous = index.checked_sub(1).map(|position| code_points[position]);
    let next = code_points.get(index + 1).copied();

    if code_point == 0x200d {
        return previous
            .and_then(char::from_u32)
            .is_some_and(|character| canonical_combining_class(character) == 9);
    }
    if code_point == 0x200c {
        if previous
            .and_then(char::from_u32)
            .is_some_and(|character| canonical_combining_class(character) == 9)
        {
            return true;
        }
        let mut before = index;
        while before > 0 && joining_type(code_points[before - 1]) == "T" {
            before -= 1;
        }
        let mut after = index + 1;
        while after < code_points.len() && joining_type(code_points[after]) == "T" {
            after += 1;
        }
        let before_type = before
            .checked_sub(1)
            .map(|position| joining_type(code_points[position]))
            .unwrap_or("U");
        let after_type = code_points
            .get(after)
            .map(|value| joining_type(*value))
            .unwrap_or("U");
        return matches!(before_type, "L" | "D") && matches!(after_type, "R" | "D");
    }
    if code_point == 0x00b7 {
        return previous == Some(0x006c) && next == Some(0x006c);
    }
    if code_point == 0x0375 {
        return next.is_some_and(|value| script_is(value, "Grek"));
    }
    if matches!(code_point, 0x05f3 | 0x05f4) {
        return previous.is_some_and(|value| script_is(value, "Hebr"));
    }
    if code_point == 0x30fb {
        return code_points.iter().copied().any(|value| {
            ["Hira", "Kana", "Hani"]
                .iter()
                .any(|script| script_is(value, script))
        });
    }
    if (0x0660..=0x0669).contains(&code_point) {
        return !code_points
            .iter()
            .any(|value| (0x06f0..=0x06f9).contains(value));
    }
    if (0x06f0..=0x06f9).contains(&code_point) {
        return !code_points
            .iter()
            .any(|value| (0x0660..=0x0669).contains(value));
    }
    false
}

fn code_point_label(code_point: u32) -> String {
    format!("U+{code_point:04X}")
}

fn assert_precis_class(text: &str, freeform: bool) -> Result<(), Value> {
    let code_points: Vec<u32> = text.chars().map(u32::from).collect();
    let mut index_utf16 = 0usize;
    for (index, code_point) in code_points.iter().copied().enumerate() {
        let property = precis_property(code_point, freeform);
        if matches!(property, Property::ContextJ | Property::ContextO) {
            if !context_rule(&code_points, index) {
                return Err(error(
                    "PROTOCOL_STRING_INVALID",
                    "A context-dependent code point fails its PRECIS rule.",
                    json!({
                        "indexUtf16": index_utf16,
                        "codePoint": code_point_label(code_point),
                        "property": property.label()
                    }),
                ));
            }
        } else if property != Property::Pvalid {
            return Err(error(
                "PROTOCOL_STRING_INVALID",
                "A code point is not allowed by the selected PRECIS base class.",
                json!({
                    "indexUtf16": index_utf16,
                    "codePoint": code_point_label(code_point),
                    "property": property.label()
                }),
            ));
        }
        index_utf16 += char::from_u32(code_point)
            .expect("PRECIS input is a Unicode scalar")
            .len_utf16();
    }
    Ok(())
}

fn assert_bidi_rule(text: &str) -> Result<(), Value> {
    let classes: Vec<&str> = text.chars().map(bidi_class_label).collect();
    if !classes
        .iter()
        .any(|value| matches!(*value, "R" | "AL" | "AN"))
    {
        return Ok(());
    }
    let allowed = ["R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"];
    let first_valid = classes
        .first()
        .is_some_and(|value| matches!(*value, "R" | "AL"));
    let all_allowed = classes.iter().all(|value| allowed.contains(value));
    let last_valid = classes
        .iter()
        .rev()
        .find(|value| **value != "NSM")
        .is_some_and(|value| matches!(*value, "R" | "AL" | "EN" | "AN"));
    let mixed_digits = classes.contains(&"EN") && classes.contains(&"AN");
    if first_valid && all_allowed && last_valid && !mixed_digits {
        return Ok(());
    }
    Err(error(
        "PROTOCOL_STRING_INVALID",
        "The string fails the RFC 5893 Bidi Rule.",
        json!({ "rule": "RFC5893" }),
    ))
}

fn width_map(text: &str) -> String {
    text.chars()
        .map(|character| {
            mapping(WIDTH_MAPPINGS, character as u32)
                .map(str::to_owned)
                .unwrap_or_else(|| character.to_string())
        })
        .collect()
}

fn has_cased_before(code_points: &[u32], index: usize) -> bool {
    for code_point in code_points[..index].iter().rev().copied() {
        if range_contains(CASED_RANGES, code_point) {
            return true;
        }
        if !range_contains(CASE_IGNORABLE_RANGES, code_point) {
            return false;
        }
    }
    false
}

fn has_cased_after(code_points: &[u32], index: usize) -> bool {
    for code_point in code_points[index + 1..].iter().copied() {
        if range_contains(CASED_RANGES, code_point) {
            return true;
        }
        if !range_contains(CASE_IGNORABLE_RANGES, code_point) {
            return false;
        }
    }
    false
}

fn lowercase(text: &str) -> String {
    let code_points: Vec<u32> = text.chars().map(u32::from).collect();
    let mut output = String::new();
    for (index, code_point) in code_points.iter().copied().enumerate() {
        if code_point == 0x03a3
            && has_cased_before(&code_points, index)
            && !has_cased_after(&code_points, index)
        {
            output.push('\u{03c2}');
        } else if let Some(value) = mapping(LOWERCASE_MAPPINGS, code_point) {
            output.push_str(value);
        } else {
            output.push(char::from_u32(code_point).expect("PRECIS input is a Unicode scalar"));
        }
    }
    output
}

fn no_details_error(message: &str) -> Value {
    json!({
        "status": "error",
        "error": { "code": "PROTOCOL_STRING_INVALID", "message": message }
    })
}

fn enforce_once(text: &str, profile: Profile, trace: &mut SideTrace) -> Result<String, Value> {
    let username = profile.is_username();
    let mut output = text.to_owned();
    if username {
        let mapped = width_map(&output);
        trace.transform("width_mapping", &output, &mapped);
        output = mapped;
    }
    assert_precis_class(&output, !username)?;
    trace.validate(if username {
        "identifier_class"
    } else {
        "freeform_class"
    });
    if !username {
        let mapped = output
            .chars()
            .map(|character| {
                if general_category(character as u32) == "Zs" && character != ' ' {
                    ' '
                } else {
                    character
                }
            })
            .collect::<String>();
        trace.transform("additional_mapping", &output, &mapped);
        output = mapped;
    }
    if profile == Profile::UsernameCaseMapped {
        let mapped = lowercase(&output);
        trace.transform("case_mapping", &output, &mapped);
        output = mapped;
    }
    let normalized = normalize::apply(&output, "NFC");
    trace.transform("nfc", &output, &normalized);
    output = normalized;
    if username {
        assert_bidi_rule(&output)?;
        trace.validate("bidi_rule");
    }
    if output.is_empty() {
        return Err(no_details_error(
            "The selected PRECIS profile does not allow an empty result.",
        ));
    }
    trace.validate("non_empty");
    Ok(output)
}

pub(crate) fn enforce(
    text: &str,
    profile: Profile,
    trace: &mut SideTrace,
) -> Result<String, Value> {
    let mut output = text.to_owned();
    for _ in 0..4 {
        trace.start_pass(&output, false);
        let next = enforce_once(&output, profile, trace)?;
        let stabilized = next == output;
        trace.finish_pass(&next, stabilized);
        if stabilized {
            return Ok(output);
        }
        output = next;
    }
    trace.start_pass(&output, true);
    let verification = enforce_once(&output, profile, trace)?;
    let stabilized = verification == output;
    trace.finish_pass(&verification, stabilized);
    if !stabilized {
        return Err(no_details_error(
            "PRECIS processing did not stabilize after four passes.",
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::{Profile, enforce};
    use crate::precis_witness::{SideTrace, WitnessMode};

    fn apply(text: &str, profile: Profile) -> Result<String, serde_json::Value> {
        enforce(
            text,
            profile,
            &mut SideTrace::new(WitnessMode::None, "text"),
        )
    }

    #[test]
    fn applies_width_case_nfc_and_freeform_space_mapping() {
        assert_eq!(apply("Ｕser", Profile::UsernameCaseMapped).unwrap(), "user");
        assert_eq!(apply("A\u{00a0}B", Profile::OpaqueString).unwrap(), "A B");
        assert_eq!(
            apply("A\u{301}\u{3a3}", Profile::UsernameCaseMapped).unwrap(),
            "áς"
        );
    }

    #[test]
    fn distinguishes_identifier_and_freeform_classes() {
        assert_eq!(
            apply("a b", Profile::UsernameCaseMapped).unwrap_err()["error"]["details"]["property"],
            "DISALLOWED"
        );
        assert_eq!(apply("¹", Profile::OpaqueString).unwrap(), "¹");
        assert_eq!(
            apply("\u{378}", Profile::UsernameCaseMapped).unwrap_err()["error"]["details"]["property"],
            "UNASSIGNED"
        );
    }
}
