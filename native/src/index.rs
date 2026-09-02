use std::collections::BTreeMap;

use serde_json::{Value, json};
use unicode_segmentation::UnicodeSegmentation;

use crate::index_types::{
    Chunk, Chunking, CodePointEntry, Coordinate, Counts, Detail, GraphemeDetail, GraphemeEntry,
    IndexResult, LineEndingCounts, LineEndingItem, LineEndings, PairDetail,
};
use crate::model::{MAX_TEXT_BYTES, enforce_result_budget, error};
use crate::validation::{
    assert_keys, require_integer, require_object, require_tagged_units, utf8_length_from_units,
};

const DEFAULT_DETAIL_ITEMS: usize = 64;
const MAX_DETAIL_ITEMS: usize = 128;
const MAX_CHUNK_BYTES: usize = 4096;
const MAX_CHUNKS: usize = 128;

pub(crate) fn raw_code_points(text: &str) -> Vec<CodePointEntry> {
    let mut entries = Vec::new();
    let mut utf16_index = 0;
    for (code_point_index, (utf8_index, character)) in text.char_indices().enumerate() {
        let utf16_length = character.len_utf16();
        entries.push(CodePointEntry {
            character: character.to_string(),
            value: format!("U+{:04X}", character as u32),
            grapheme: 0,
            start: Coordinate {
                utf8_byte: utf8_index,
                utf16_code_unit: utf16_index,
                code_point: code_point_index,
                grapheme: None,
                line: 0,
                column_code_point: 0,
                column_utf16_code_unit: 0,
            },
            end: Coordinate {
                utf8_byte: utf8_index + character.len_utf8(),
                utf16_code_unit: utf16_index + utf16_length,
                code_point: code_point_index + 1,
                grapheme: None,
                line: 0,
                column_code_point: 0,
                column_utf16_code_unit: 0,
            },
        });
        utf16_index += utf16_length;
    }
    entries
}

pub(crate) fn assign_graphemes(text: &str, entries: &mut [CodePointEntry]) -> Vec<GraphemeEntry> {
    let utf16_by_utf8: BTreeMap<usize, usize> = entries
        .iter()
        .map(|entry| (entry.start.utf8_byte, entry.start.utf16_code_unit))
        .chain(std::iter::once((text.len(), text.encode_utf16().count())))
        .collect();
    let starts: Vec<(usize, &str)> = text.grapheme_indices(true).collect();
    let mut graphemes = Vec::new();
    let mut entry_index = 0;
    for (grapheme_index, (start_utf8, grapheme)) in starts.into_iter().enumerate() {
        let end_utf8 = start_utf8 + grapheme.len();
        let start_utf16 = *utf16_by_utf8
            .get(&start_utf8)
            .expect("grapheme starts at code point");
        let end_utf16 = *utf16_by_utf8
            .get(&end_utf8)
            .expect("grapheme ends at code point");
        while entry_index < entries.len() && entries[entry_index].start.utf16_code_unit < end_utf16
        {
            entries[entry_index].grapheme = grapheme_index;
            entry_index += 1;
        }
        graphemes.push(GraphemeEntry {
            text: grapheme.to_string(),
            index: grapheme_index,
            start_utf16,
            end_utf16,
        });
    }
    graphemes
}

pub(crate) fn assign_lines(entries: &mut [CodePointEntry]) -> (usize, usize, usize) {
    let mut line = 1;
    let mut column_code_point = 0;
    let mut column_utf16 = 0;
    for index in 0..entries.len() {
        entries[index].start.line = line;
        entries[index].start.column_code_point = column_code_point;
        entries[index].start.column_utf16_code_unit = column_utf16;
        let next = entries.get(index + 1).map(|entry| entry.character.as_str());
        let character = entries[index].character.as_str();
        let is_crlf_head = character == "\r" && next == Some("\n");
        let is_break = character == "\n"
            || (character == "\r" && !is_crlf_head)
            || matches!(character, "\u{0085}" | "\u{2028}" | "\u{2029}");
        if is_break {
            line += 1;
            column_code_point = 0;
            column_utf16 = 0;
        } else {
            column_code_point += 1;
            column_utf16 += entries[index].character.encode_utf16().count();
        }
        entries[index].end.line = line;
        entries[index].end.column_code_point = column_code_point;
        entries[index].end.column_utf16_code_unit = column_utf16;
    }
    (line, column_code_point, column_utf16)
}

pub(crate) fn boundaries(
    text: &str,
    entries: &[CodePointEntry],
    grapheme_count: usize,
    final_line: (usize, usize, usize),
) -> BTreeMap<usize, Coordinate> {
    let mut values: BTreeMap<usize, Coordinate> = entries
        .iter()
        .map(|entry| {
            let mut coordinate = entry.start.clone();
            coordinate.grapheme = Some(entry.grapheme);
            (entry.start.utf16_code_unit, coordinate)
        })
        .collect();
    values.insert(
        text.encode_utf16().count(),
        Coordinate {
            utf8_byte: text.len(),
            utf16_code_unit: text.encode_utf16().count(),
            code_point: entries.len(),
            grapheme: Some(grapheme_count),
            line: final_line.0,
            column_code_point: final_line.1,
            column_utf16_code_unit: final_line.2,
        },
    );
    values
}

pub(crate) fn line_endings(entries: &[CodePointEntry], limit: usize) -> LineEndings {
    let mut counts = LineEndingCounts::default();
    let mut items = Vec::new();
    let mut index = 0;
    while index < entries.len() {
        let entry = &entries[index];
        let (kind, end) = if entry.character == "\r"
            && entries.get(index + 1).map(|item| item.character.as_str()) == Some("\n")
        {
            index += 1;
            (Some("crlf"), entries[index].end.clone())
        } else {
            let kind = match entry.character.as_str() {
                "\n" => Some("lf"),
                "\r" => Some("cr"),
                "\u{0085}" => Some("nel"),
                "\u{2028}" => Some("lineSeparator"),
                "\u{2029}" => Some("paragraphSeparator"),
                _ => None,
            };
            (kind, entry.end.clone())
        };
        if let Some(kind) = kind {
            match kind {
                "crlf" => counts.crlf += 1,
                "lf" => counts.lf += 1,
                "cr" => counts.cr += 1,
                "nel" => counts.nel += 1,
                "lineSeparator" => counts.line_separator += 1,
                "paragraphSeparator" => counts.paragraph_separator += 1,
                _ => unreachable!(),
            }
            if items.len() < limit {
                items.push(LineEndingItem {
                    kind,
                    start: entry.start.clone(),
                    end,
                });
            }
        }
        index += 1;
    }
    let total = counts.crlf
        + counts.lf
        + counts.cr
        + counts.nel
        + counts.line_separator
        + counts.paragraph_separator;
    LineEndings {
        counts,
        total,
        truncated: total > items.len(),
        items,
    }
}

fn chunk_text(
    text: &str,
    graphemes: &[GraphemeEntry],
    boundaries: &BTreeMap<usize, Coordinate>,
    max_bytes: usize,
) -> Result<Vec<Chunk>, Value> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_start = 0;
    let mut current_bytes = 0;
    let publish = |end: usize,
                   chunks: &mut Vec<Chunk>,
                   current: &mut String,
                   current_start: &mut usize,
                   current_bytes: &mut usize| {
        if current.is_empty() {
            return;
        }
        chunks.push(Chunk {
            index: chunks.len(),
            text: std::mem::take(current),
            utf8_bytes: *current_bytes,
            start: boundaries[current_start].clone(),
            end: boundaries[&end].clone(),
        });
        *current_bytes = 0;
        *current_start = end;
    };
    for grapheme in graphemes {
        let bytes = grapheme.text.len();
        if bytes > max_bytes {
            return Err(error(
                "CHUNK_GRAPHEME_TOO_LARGE",
                "A single grapheme exceeds the requested UTF-8 chunk budget.",
                json!({
                    "graphemeIndex": grapheme.index,
                    "graphemeUtf8Bytes": bytes,
                    "maxChunkUtf8Bytes": max_bytes
                }),
            ));
        }
        if current_bytes > 0 && current_bytes + bytes > max_bytes {
            publish(
                grapheme.start_utf16,
                &mut chunks,
                &mut current,
                &mut current_start,
                &mut current_bytes,
            );
        }
        current.push_str(&grapheme.text);
        current_bytes += bytes;
    }
    publish(
        text.encode_utf16().count(),
        &mut chunks,
        &mut current,
        &mut current_start,
        &mut current_bytes,
    );
    if chunks.len() > MAX_CHUNKS {
        return Err(error(
            "TOO_MANY_CHUNKS",
            format!("Chunking would exceed the {MAX_CHUNKS}-chunk result limit."),
            json!({ "actualChunks": chunks.len(), "limitChunks": MAX_CHUNKS }),
        ));
    }
    Ok(chunks)
}

pub fn index(arguments: Value) -> Value {
    let object = match require_object(&arguments, "arguments") {
        Ok(value) => value,
        Err(value) => return value,
    };
    if let Err(value) = assert_keys(
        object,
        &["text", "detailLimit", "maxChunkUtf8Bytes"],
        &["text"],
    ) {
        return value;
    }
    let units = match require_tagged_units(object.get("text"), "text") {
        Ok(value) => value,
        Err(value) => return value,
    };
    let actual_bytes = utf8_length_from_units(&units);
    if actual_bytes > MAX_TEXT_BYTES {
        return error(
            "REQUEST_TOO_LARGE",
            format!("text exceeds the {MAX_TEXT_BYTES}-byte UTF-8 limit."),
            json!({ "field": "text", "actualBytes": actual_bytes, "limitBytes": MAX_TEXT_BYTES }),
        );
    }
    let text = match String::from_utf16(&units) {
        Ok(value) => value,
        Err(_) => {
            return error(
                "INVALID_UNICODE",
                "text contains an unpaired UTF-16 surrogate.",
                json!({ "field": "text" }),
            );
        }
    };
    let detail_limit = if object.contains_key("detailLimit") {
        match require_integer(
            object.get("detailLimit"),
            "detailLimit",
            0,
            MAX_DETAIL_ITEMS,
        ) {
            Ok(value) => value,
            Err(value) => return value,
        }
    } else {
        DEFAULT_DETAIL_ITEMS
    };
    let max_chunk_utf8_bytes = if object.contains_key("maxChunkUtf8Bytes") {
        match require_integer(
            object.get("maxChunkUtf8Bytes"),
            "maxChunkUtf8Bytes",
            1,
            MAX_CHUNK_BYTES,
        ) {
            Ok(value) => Some(value),
            Err(value) => return value,
        }
    } else {
        None
    };

    let mut code_point_entries = raw_code_points(&text);
    let grapheme_entries = assign_graphemes(&text, &mut code_point_entries);
    let final_line = assign_lines(&mut code_point_entries);
    let boundaries = boundaries(
        &text,
        &code_point_entries,
        grapheme_entries.len(),
        final_line,
    );
    let code_points: Vec<PairDetail> = code_point_entries
        .iter()
        .take(detail_limit)
        .map(|entry| PairDetail {
            character: entry.character.clone(),
            value: entry.value.clone(),
            grapheme: entry.grapheme,
            start: entry.start.clone(),
            end: entry.end.clone(),
        })
        .collect();
    let graphemes: Vec<GraphemeDetail> = grapheme_entries
        .iter()
        .take(detail_limit)
        .map(|entry| GraphemeDetail {
            index: entry.index,
            text: entry.text.clone(),
            start: boundaries[&entry.start_utf16].clone(),
            end: boundaries[&entry.end_utf16].clone(),
        })
        .collect();
    let chunking = if let Some(max_bytes) = max_chunk_utf8_bytes {
        match chunk_text(&text, &grapheme_entries, &boundaries, max_bytes) {
            Ok(chunks) => Some(Chunking {
                max_chunk_utf8_bytes: max_bytes,
                boundary: "extended_grapheme_cluster",
                chunks,
            }),
            Err(value) => return value,
        }
    } else {
        None
    };
    let final_boundary = &boundaries[&units.len()];
    let result = IndexResult {
        status: "ok",
        operation: "index",
        counts: Counts {
            utf8_bytes: text.len(),
            utf16_code_units: units.len(),
            code_points: code_point_entries.len(),
            graphemes: grapheme_entries.len(),
            lines: if code_point_entries.is_empty() {
                1
            } else {
                final_boundary.line
            },
        },
        detail: Detail {
            limit: detail_limit,
            code_points_truncated: code_point_entries.len() > code_points.len(),
            code_points,
            graphemes_truncated: grapheme_entries.len() > graphemes.len(),
            graphemes,
        },
        line_endings: line_endings(&code_point_entries, detail_limit),
        chunking,
    };
    let value = serde_json::to_value(result).expect("index result serializes");
    enforce_result_budget(value)
}
