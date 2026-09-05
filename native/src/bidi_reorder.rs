use serde::Deserialize;
use serde_json::{Value, json};
use unicode_bidi::data_source::BidiMatchedOpeningBracket;
use unicode_bidi::{BidiClass, BidiDataSource, BidiInfo, LTR_LEVEL, Level, RTL_LEVEL};

use crate::bidi_data::{
    BIDI_BRACKET_ENTRY_COUNT, BIDI_BRACKETS, BIDI_BRACKETS_SOURCE_PATH,
    BIDI_BRACKETS_SOURCE_SHA256, BIDI_CLASS_RANGE_COUNT, BIDI_CLASS_RANGES, BIDI_CLASS_SOURCE_PATH,
    BIDI_CLASS_SOURCE_SHA256, BIDI_MIRRORING, BIDI_MIRRORING_ENTRY_COUNT,
    BIDI_MIRRORING_SOURCE_PATH, BIDI_MIRRORING_SOURCE_SHA256, COMBINING_CLASS_CODE_POINT_COUNT,
    COMBINING_CLASS_RANGE_COUNT, COMBINING_CLASS_RANGES, SOURCE_MANIFEST_SHA256,
    UNICODE_DATA_SOURCE_PATH, UNICODE_DATA_SOURCE_SHA256, UNICODE_VERSION,
};
use crate::model::{MAX_RESULT_BYTES, MAX_TEXT_BYTES, TaggedTextValue, error, invalid_input};
use crate::uts39_skeleton;

const ENGINE: &str = "rust-unicode-bidi@0.3.18+text-integrity-unicode17-data";

#[derive(Clone, Copy, Debug, Deserialize)]
pub(crate) enum Direction {
    #[serde(rename = "LTR")]
    Ltr,
    #[serde(rename = "RTL")]
    Rtl,
    #[serde(rename = "first_strong")]
    FirstStrong,
}

impl Direction {
    pub(crate) fn base_level(self) -> Option<Level> {
        match self {
            Self::Ltr => Some(LTR_LEVEL),
            Self::Rtl => Some(RTL_LEVEL),
            Self::FirstStrong => None,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ltr => "LTR",
            Self::Rtl => "RTL",
            Self::FirstStrong => "first_strong",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Arguments {
    text: TaggedTextValue,
    direction: Direction,
}

pub(crate) struct Unicode17BidiData;

fn range_value(table: &[(u32, u32, u8)], code_point: u32) -> Option<u8> {
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

fn class_from_code(code: u8) -> BidiClass {
    match code {
        0 => BidiClass::L,
        1 => BidiClass::R,
        2 => BidiClass::EN,
        3 => BidiClass::ES,
        4 => BidiClass::ET,
        5 => BidiClass::AN,
        6 => BidiClass::CS,
        7 => BidiClass::B,
        8 => BidiClass::S,
        9 => BidiClass::WS,
        10 => BidiClass::ON,
        11 => BidiClass::BN,
        12 => BidiClass::NSM,
        13 => BidiClass::AL,
        14 => BidiClass::LRO,
        15 => BidiClass::RLO,
        16 => BidiClass::LRE,
        17 => BidiClass::RLE,
        18 => BidiClass::PDF,
        19 => BidiClass::LRI,
        20 => BidiClass::RLI,
        21 => BidiClass::FSI,
        22 => BidiClass::PDI,
        _ => unreachable!("generated Bidi_Class code is closed"),
    }
}

pub(crate) fn bidi_class_label(character: char) -> &'static str {
    match range_value(BIDI_CLASS_RANGES, character as u32)
        .expect("generated Bidi_Class table covers all Unicode code points")
    {
        0 => "L",
        1 => "R",
        2 => "EN",
        3 => "ES",
        4 => "ET",
        5 => "AN",
        6 => "CS",
        7 => "B",
        8 => "S",
        9 => "WS",
        10 => "ON",
        11 => "BN",
        12 => "NSM",
        13 => "AL",
        14 => "LRO",
        15 => "RLO",
        16 => "LRE",
        17 => "RLE",
        18 => "PDF",
        19 => "LRI",
        20 => "RLI",
        21 => "FSI",
        22 => "PDI",
        _ => unreachable!("generated Bidi_Class code is closed"),
    }
}

impl BidiDataSource for Unicode17BidiData {
    fn bidi_class(&self, character: char) -> BidiClass {
        class_from_code(
            range_value(BIDI_CLASS_RANGES, character as u32)
                .expect("generated Bidi_Class table covers all Unicode code points"),
        )
    }

    fn bidi_matched_opening_bracket(&self, character: char) -> Option<BidiMatchedOpeningBracket> {
        let code_point = character as u32;
        BIDI_BRACKETS
            .binary_search_by_key(&code_point, |(source, _, _)| *source)
            .ok()
            .map(|index| {
                let (_, opening, is_open) = BIDI_BRACKETS[index];
                BidiMatchedOpeningBracket {
                    opening: char::from_u32(opening).expect("generated bracket opening is scalar"),
                    is_open,
                }
            })
    }
}

fn combining_class(character: char) -> u8 {
    range_value(COMBINING_CLASS_RANGES, character as u32).unwrap_or(0)
}

fn mirrored(character: char) -> Option<char> {
    let code_point = character as u32;
    BIDI_MIRRORING
        .binary_search_by_key(&code_point, |(source, _)| *source)
        .ok()
        .map(|index| char::from_u32(BIDI_MIRRORING[index].1).expect("generated mirror is scalar"))
}

#[derive(Clone, Debug)]
pub(crate) struct ReorderedEntry {
    pub character: char,
    pub logical_code_point_index: usize,
    pub level: u8,
}

#[derive(Clone, Debug)]
pub(crate) struct BidiResolution {
    pub resolved_levels: Vec<u8>,
    pub visual_order: Vec<usize>,
    pub entries: Vec<ReorderedEntry>,
    pub paragraph_levels: Vec<u8>,
}

fn apply_combining_mark_reordering(entries: &mut Vec<ReorderedEntry>) {
    let mut index = 0usize;
    while index < entries.len() {
        let combining = combining_class(entries[index].character);
        if combining == 0 || entries[index].level % 2 == 0 {
            index += 1;
            continue;
        }

        let start = index;
        while index < entries.len() {
            let entry = &entries[index];
            if combining_class(entry.character) == 0 || entry.level % 2 == 0 {
                break;
            }
            index += 1;
        }
        if index < entries.len() && entries[index].level % 2 == 1 {
            entries[start..=index].reverse();
            index += 1;
        }
    }
}

pub(crate) fn resolve(text: &str, base_level: Option<Level>) -> BidiResolution {
    let info = BidiInfo::new_with_data_source(&Unicode17BidiData, text, base_level);
    let characters: Vec<char> = text.chars().collect();
    let char_byte_starts: Vec<usize> = text.char_indices().map(|(index, _)| index).collect();
    let mut resolved_levels: Vec<u8> = char_byte_starts
        .iter()
        .map(|index| info.levels[*index].number())
        .collect();
    let mut visual_order = Vec::with_capacity(characters.len());

    for paragraph in &info.paragraphs {
        let start = char_byte_starts.partition_point(|index| *index < paragraph.range.start);
        let end = char_byte_starts.partition_point(|index| *index < paragraph.range.end);
        let reordered = info.reordered_levels_per_char(paragraph, paragraph.range.clone());
        for index in start..end {
            resolved_levels[index] = reordered[index].number();
        }
        let local_order = BidiInfo::reorder_visual(&reordered[start..end]);
        visual_order.extend(local_order.into_iter().map(|index| start + index));
    }
    debug_assert_eq!(visual_order.len(), characters.len());

    let mut entries: Vec<ReorderedEntry> = visual_order
        .iter()
        .map(|index| ReorderedEntry {
            character: characters[*index],
            logical_code_point_index: *index,
            level: resolved_levels[*index],
        })
        .collect();
    apply_combining_mark_reordering(&mut entries);
    for entry in &mut entries {
        if entry.level % 2 == 1 {
            if let Some(replacement) = mirrored(entry.character) {
                entry.character = replacement;
            }
        }
    }

    BidiResolution {
        resolved_levels,
        visual_order: entries
            .iter()
            .map(|entry| entry.logical_code_point_index)
            .collect(),
        entries,
        paragraph_levels: info
            .paragraphs
            .iter()
            .map(|paragraph| paragraph.level.number())
            .collect(),
    }
}

pub(crate) fn skeleton(text: &str, direction: Direction) -> String {
    let resolution = resolve(text, direction.base_level());
    let reordered: String = resolution
        .entries
        .iter()
        .map(|entry| entry.character)
        .collect();
    uts39_skeleton::apply(&reordered)
}

pub fn run(arguments: Value) -> Value {
    let args: Arguments = match serde_json::from_value(arguments) {
        Ok(value) => value,
        Err(_) => {
            return invalid_input(
                "arguments do not match the closed reference bidiSkeleton request.",
                "arguments",
            );
        }
    };
    let units = args.text.tagged.units();
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
    if original.len() > MAX_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!("text exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({ "field": "text", "actualBytes": original.len(), "limitBytes": MAX_TEXT_BYTES }),
        );
    }

    let resolution = resolve(&original, args.direction.base_level());
    let reordered: String = resolution
        .entries
        .iter()
        .map(|entry| entry.character)
        .collect();
    let skeleton = uts39_skeleton::apply(&reordered);
    let entries: Vec<Value> = resolution
        .entries
        .iter()
        .map(|entry| {
            json!({
                "character": entry.character.to_string(),
                "logicalCodePointIndex": entry.logical_code_point_index,
                "level": entry.level
            })
        })
        .collect();
    let result = json!({
        "status": "ok",
        "operation": "reference_bidi_skeleton",
        "original": original,
        "direction": args.direction.label(),
        "resolvedLevels": resolution.resolved_levels,
        "visualOrder": resolution.visual_order,
        "entries": entries,
        "reordered": reordered,
        "skeleton": skeleton,
        "changed": original != skeleton,
        "paragraphLevels": resolution.paragraph_levels,
        "engine": ENGINE,
        "standards": {
            "specification": "Unicode Standard Annex #9 + Unicode Technical Standard #39",
            "unicodeVersion": UNICODE_VERSION,
            "uts39Revision": 32,
            "stage": "complete_bidi_skeleton",
            "uba": {
                "algorithm": "unicode-bidi@0.3.18",
                "hardcodedDataFeature": false,
                "dataSource": "text-integrity-unicode-17",
                "conformance": {
                    "bidiTestParagraphModeCases": 770241,
                    "bidiCharacterTestCases": 91707
                },
                "source": {
                    "manifestSha256": SOURCE_MANIFEST_SHA256,
                    "bidiClass": {
                        "path": BIDI_CLASS_SOURCE_PATH,
                        "sha256": BIDI_CLASS_SOURCE_SHA256,
                        "rangeCount": BIDI_CLASS_RANGE_COUNT
                    },
                    "bidiBrackets": {
                        "path": BIDI_BRACKETS_SOURCE_PATH,
                        "sha256": BIDI_BRACKETS_SOURCE_SHA256,
                        "entryCount": BIDI_BRACKET_ENTRY_COUNT
                    },
                    "unicodeData": {
                        "path": UNICODE_DATA_SOURCE_PATH,
                        "sha256": UNICODE_DATA_SOURCE_SHA256,
                        "combiningClassRangeCount": COMBINING_CLASS_RANGE_COUNT,
                        "combiningClassCodePointCount": COMBINING_CLASS_CODE_POINT_COUNT
                    },
                    "bidiMirroring": {
                        "path": BIDI_MIRRORING_SOURCE_PATH,
                        "sha256": BIDI_MIRRORING_SOURCE_SHA256,
                        "entryCount": BIDI_MIRRORING_ENTRY_COUNT
                    }
                }
            }
        }
    });
    let actual_bytes = serde_json::to_vec(&result)
        .expect("reference bidiSkeleton result serializes")
        .len();
    if actual_bytes > MAX_RESULT_BYTES {
        return error(
            "RESULT_TOO_LARGE",
            format!("The complete result exceeds the {MAX_RESULT_BYTES}-byte limit."),
            json!({ "actualBytes": actual_bytes, "limitBytes": MAX_RESULT_BYTES }),
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use unicode_bidi::{LTR_LEVEL, RTL_LEVEL};

    use super::{Unicode17BidiData, resolve, run};
    use unicode_bidi::{BidiClass, BidiDataSource};

    #[test]
    fn uses_the_generated_unicode_17_data_source() {
        assert_eq!(Unicode17BidiData.bidi_class('A'), BidiClass::L);
        assert_eq!(Unicode17BidiData.bidi_class('\u{5d0}'), BidiClass::R);
        assert_eq!(Unicode17BidiData.bidi_class('\u{10d40}'), BidiClass::AN);
        let normalized = Unicode17BidiData
            .bidi_matched_opening_bracket('\u{232a}')
            .expect("U+232A is a paired bracket");
        assert_eq!(normalized.opening, '\u{3008}');
        assert!(!normalized.is_open);
    }

    #[test]
    fn composes_uba_l3_l4_and_the_internal_skeleton() {
        let ltr = resolve("A1<\u{5e9}\u{5c2}", Some(LTR_LEVEL));
        let rtl = resolve("A1<\u{5e9}\u{5c2}", Some(RTL_LEVEL));
        let ltr_text: String = ltr.entries.iter().map(|entry| entry.character).collect();
        let rtl_text: String = rtl.entries.iter().map(|entry| entry.character).collect();
        assert_ne!(ltr_text, rtl_text);
        assert_eq!(ltr.paragraph_levels, vec![0]);
        assert_eq!(rtl.paragraph_levels, vec![1]);

        let result = run(json!({
            "text": { "$text": { "kind": "unicode_scalar_string", "value": "pаypal" } },
            "direction": "LTR"
        }));
        assert_eq!(result["status"], "ok");
        assert_eq!(result["skeleton"], "paypal");
    }

    #[test]
    fn rejects_unknown_fields_before_execution() {
        let result = run(json!({
            "text": { "$text": { "kind": "unicode_scalar_string", "value": "A" } },
            "direction": "LTR",
            "extra": true
        }));
        assert_eq!(result["status"], "error");
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
    }
}
