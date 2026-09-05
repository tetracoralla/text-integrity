use std::io::Read;

use flate2::read::GzDecoder;
use unicode_bidi::{BidiInfo, LTR_LEVEL, Level, RTL_LEVEL};

use crate::bidi_reorder::Unicode17BidiData;

const BIDI_TEST_GZIP: &[u8] =
    include_bytes!("../../vendor/unicode/17.0.0/conformance/BidiTest.txt.gz");
const BIDI_CHARACTER_TEST_GZIP: &[u8] =
    include_bytes!("../../vendor/unicode/17.0.0/conformance/BidiCharacterTest.txt.gz");

fn corpus(bytes: &[u8]) -> String {
    let mut decoder = GzDecoder::new(bytes);
    let mut result = String::new();
    decoder
        .read_to_string(&mut result)
        .expect("pinned bidi corpus is valid UTF-8 gzip");
    result
}

fn type_character(value: &str) -> char {
    match value {
        "L" => 'A',
        "R" => '\u{5d0}',
        "EN" => '0',
        "ES" => '+',
        "ET" => '#',
        "AN" => '\u{660}',
        "CS" => ',',
        "B" => '\u{2029}',
        "S" => '\t',
        "WS" => ' ',
        "ON" => '!',
        "BN" => '\u{ad}',
        "NSM" => '\u{36f}',
        "AL" => '\u{6d5}',
        "LRO" => '\u{202d}',
        "RLO" => '\u{202e}',
        "LRE" => '\u{202a}',
        "RLE" => '\u{202b}',
        "PDF" => '\u{202c}',
        "LRI" => '\u{2066}',
        "RLI" => '\u{2067}',
        "FSI" => '\u{2068}',
        "PDI" => '\u{2069}',
        _ => panic!("unknown BidiTest class {value}"),
    }
}

fn from_hex_list(value: &str) -> String {
    value
        .split_whitespace()
        .map(|item| {
            char::from_u32(u32::from_str_radix(item, 16).expect("valid hexadecimal code point"))
                .expect("BidiCharacterTest contains Unicode scalar values")
        })
        .collect()
}

fn parse_levels(value: &str) -> Vec<Option<u8>> {
    value
        .split_whitespace()
        .map(|item| {
            if item == "x" {
                None
            } else {
                Some(item.parse().expect("valid expected embedding level"))
            }
        })
        .collect()
}

fn parse_order(value: &str) -> Vec<usize> {
    value
        .split_whitespace()
        .map(|item| item.parse().expect("valid expected visual index"))
        .collect()
}

fn check_case(
    text: &str,
    default_level: Option<Level>,
    expected_paragraph_level: Option<u8>,
    expected_levels: &[Option<u8>],
    expected_order: &[usize],
) {
    let info = BidiInfo::new_with_data_source(&Unicode17BidiData, text, default_level);
    let paragraph = info
        .paragraphs
        .first()
        .expect("official bidi case contains one paragraph");
    if let Some(expected) = expected_paragraph_level {
        assert_eq!(
            paragraph.level.number(),
            expected,
            "paragraph level for {text:?}"
        );
    }
    let reordered_levels = info.reordered_levels_per_char(paragraph, paragraph.range.clone());
    let actual_levels: Vec<u8> = reordered_levels.iter().map(Level::number).collect();
    assert_eq!(actual_levels.len(), expected_levels.len());
    for (index, expected) in expected_levels.iter().enumerate() {
        if let Some(expected) = expected {
            assert_eq!(
                actual_levels[index], *expected,
                "embedding level {index} for {text:?}"
            );
        }
    }

    let actual_order: Vec<usize> = BidiInfo::reorder_visual(&reordered_levels)
        .into_iter()
        .filter(|index| expected_levels[*index].is_some())
        .collect();
    assert_eq!(actual_order, expected_order, "visual order for {text:?}");
}

#[test]
fn unicode_17_bidi_test_all_paragraph_modes() {
    let corpus = corpus(BIDI_TEST_GZIP);
    let mut expected_levels = Vec::new();
    let mut expected_order = Vec::new();
    let mut count = 0usize;

    for source_line in corpus.lines() {
        let line = source_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if let Some(value) = line.strip_prefix("@Levels:") {
            expected_levels = parse_levels(value);
            continue;
        }
        if let Some(value) = line.strip_prefix("@Reorder:") {
            expected_order = parse_order(value);
            continue;
        }
        let mut fields = line.split(';').map(str::trim);
        let text: String = fields
            .next()
            .expect("BidiTest types")
            .split_whitespace()
            .map(type_character)
            .collect();
        let modes: u8 = fields
            .next()
            .expect("BidiTest modes")
            .parse()
            .expect("valid BidiTest modes");
        for (bit, level) in [(1, None), (2, Some(LTR_LEVEL)), (4, Some(RTL_LEVEL))] {
            if modes & bit == 0 {
                continue;
            }
            check_case(
                &text,
                level,
                level.map(|value| value.number()),
                &expected_levels,
                &expected_order,
            );
            count += 1;
        }
    }
    assert_eq!(count, 770_241);
}

#[test]
fn unicode_17_bidi_character_test() {
    let corpus = corpus(BIDI_CHARACTER_TEST_GZIP);
    let mut count = 0usize;

    for source_line in corpus.lines() {
        let line = source_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<&str> = line.split(';').map(str::trim).collect();
        assert_eq!(fields.len(), 5);
        let text = from_hex_list(fields[0]);
        let default_level = match fields[1] {
            "0" => Some(LTR_LEVEL),
            "1" => Some(RTL_LEVEL),
            "2" => None,
            value => panic!("unknown paragraph mode {value}"),
        };
        let paragraph_level = fields[2].parse().expect("valid paragraph level");
        let expected_levels = parse_levels(fields[3]);
        let expected_order = parse_order(fields[4]);
        check_case(
            &text,
            default_level,
            Some(paragraph_level),
            &expected_levels,
            &expected_order,
        );
        count += 1;
    }
    assert_eq!(count, 91_707);
}
