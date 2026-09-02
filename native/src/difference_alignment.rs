use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::difference_support::TextMap;

pub(crate) const ALGORITHM: &str = "text-integrity.lcs-insert-delete-alignment/1";
pub(crate) const TIE_BREAK: &str = "highest_right_split_then_first_match";
pub(crate) const REPLACEMENT_GROUPING: &str = "contiguous_non_equal";
const SEGMENT_IDENTITY_SCHEMA: &str = "text-integrity.alignment-segment-indexes/1";

#[derive(Clone, Debug)]
struct Segment {
    kind: &'static str,
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
}

fn lcs_lengths(
    left: &[String],
    left_start: usize,
    left_end: usize,
    right: &[String],
    right_start: usize,
    right_end: usize,
    reverse: bool,
) -> Vec<u16> {
    let right_length = right_end - right_start;
    let mut previous = vec![0_u16; right_length + 1];
    let mut current = vec![0_u16; right_length + 1];
    for left_offset in 0..(left_end - left_start) {
        current[0] = 0;
        let left_value = if reverse {
            &left[left_end - left_offset - 1]
        } else {
            &left[left_start + left_offset]
        };
        for right_offset in 0..right_length {
            let right_value = if reverse {
                &right[right_end - right_offset - 1]
            } else {
                &right[right_start + right_offset]
            };
            current[right_offset + 1] = if left_value == right_value {
                previous[right_offset] + 1
            } else {
                previous[right_offset + 1].max(current[right_offset])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous
}

fn append_atomic(
    segments: &mut Vec<Segment>,
    kind: &'static str,
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) {
    if left_start == left_end && right_start == right_end {
        return;
    }
    if let Some(previous) = segments.last_mut()
        && previous.kind == kind
        && previous.left_end == left_start
        && previous.right_end == right_start
    {
        previous.left_end = left_end;
        previous.right_end = right_end;
        return;
    }
    segments.push(Segment {
        kind,
        left_start,
        left_end,
        right_start,
        right_end,
    });
}

fn align_range(
    left: &[String],
    left_start: usize,
    left_end: usize,
    right: &[String],
    right_start: usize,
    right_end: usize,
    segments: &mut Vec<Segment>,
) {
    let left_length = left_end - left_start;
    let right_length = right_end - right_start;
    if left_length == 0 {
        append_atomic(
            segments,
            "insert",
            left_start,
            left_end,
            right_start,
            right_end,
        );
        return;
    }
    if right_length == 0 {
        append_atomic(
            segments,
            "delete",
            left_start,
            left_end,
            right_start,
            right_end,
        );
        return;
    }
    if left_length == 1 {
        let matched = (right_start..right_end).find(|index| left[left_start] == right[*index]);
        if let Some(matched) = matched {
            append_atomic(
                segments,
                "insert",
                left_start,
                left_start,
                right_start,
                matched,
            );
            append_atomic(
                segments,
                "equal",
                left_start,
                left_end,
                matched,
                matched + 1,
            );
            append_atomic(
                segments,
                "insert",
                left_end,
                left_end,
                matched + 1,
                right_end,
            );
        } else {
            append_atomic(
                segments,
                "delete",
                left_start,
                left_end,
                right_start,
                right_start,
            );
            append_atomic(
                segments,
                "insert",
                left_end,
                left_end,
                right_start,
                right_end,
            );
        }
        return;
    }

    let left_middle = left_start + left_length / 2;
    let forward = lcs_lengths(
        left,
        left_start,
        left_middle,
        right,
        right_start,
        right_end,
        false,
    );
    let backward = lcs_lengths(
        left,
        left_middle,
        left_end,
        right,
        right_start,
        right_end,
        true,
    );
    let mut best_right_offset = 0;
    let mut best_length = 0_u16;
    for offset in 0..=right_length {
        let length = forward[offset] + backward[right_length - offset];
        if length >= best_length {
            best_length = length;
            best_right_offset = offset;
        }
    }
    let right_middle = right_start + best_right_offset;
    align_range(
        left,
        left_start,
        left_middle,
        right,
        right_start,
        right_middle,
        segments,
    );
    align_range(
        left,
        left_middle,
        left_end,
        right,
        right_middle,
        right_end,
        segments,
    );
}

fn group_changes(atomic: &[Segment]) -> Vec<Segment> {
    let mut grouped = Vec::new();
    let mut index = 0;
    while index < atomic.len() {
        if atomic[index].kind == "equal" {
            grouped.push(atomic[index].clone());
            index += 1;
            continue;
        }
        let mut change = atomic[index].clone();
        index += 1;
        while index < atomic.len() && atomic[index].kind != "equal" {
            change.left_end = atomic[index].left_end;
            change.right_end = atomic[index].right_end;
            index += 1;
        }
        let left_length = change.left_end - change.left_start;
        let right_length = change.right_end - change.right_start;
        change.kind = if left_length > 0 && right_length > 0 {
            "replace"
        } else if left_length > 0 {
            "delete"
        } else {
            "insert"
        };
        grouped.push(change);
    }
    grouped
}

fn segment_index_sha256(unit: &str, segments: &[Segment]) -> String {
    let mut digest = Sha256::new();
    digest.update(SEGMENT_IDENTITY_SCHEMA.as_bytes());
    digest.update([0]);
    digest.update(unit.as_bytes());
    for segment in segments {
        for value in [
            segment.kind.to_owned(),
            segment.left_start.to_string(),
            segment.left_end.to_string(),
            segment.right_start.to_string(),
            segment.right_end.to_string(),
        ] {
            digest.update([0]);
            digest.update(value.as_bytes());
        }
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn boundary(map: &TextMap, unit: &str, index: usize) -> Value {
    let utf16 = if unit == "code_point" {
        map.code_points.get(index).map_or_else(
            || {
                map.code_points
                    .last()
                    .map_or(0, |item| item.end.utf16_code_unit)
            },
            |item| item.start.utf16_code_unit,
        )
    } else {
        map.graphemes.get(index).map_or_else(
            || map.graphemes.last().map_or(0, |item| item.end_utf16),
            |item| item.start_utf16,
        )
    };
    json!(map.boundaries[&utf16])
}

fn public_segment(segment: &Segment, left: &TextMap, right: &TextMap, unit: &str) -> Value {
    json!({
        "kind": segment.kind,
        "left": {
            "startIndex": segment.left_start,
            "endIndex": segment.left_end,
            "start": boundary(left, unit, segment.left_start),
            "end": boundary(left, unit, segment.left_end)
        },
        "right": {
            "startIndex": segment.right_start,
            "endIndex": segment.right_end,
            "start": boundary(right, unit, segment.right_start),
            "end": boundary(right, unit, segment.right_end)
        }
    })
}

fn build_alignment(
    left_tokens: &[String],
    right_tokens: &[String],
    left_map: &TextMap,
    right_map: &TextMap,
    unit: &str,
    mode: &str,
) -> Value {
    let mut atomic = Vec::new();
    align_range(
        left_tokens,
        0,
        left_tokens.len(),
        right_tokens,
        0,
        right_tokens.len(),
        &mut atomic,
    );
    let segments = group_changes(&atomic);
    let mut matched_item_count = 0;
    let mut inserted_item_count = 0;
    let mut deleted_item_count = 0;
    let mut change_segment_count = 0;
    for segment in &segments {
        let left_length = segment.left_end - segment.left_start;
        let right_length = segment.right_end - segment.right_start;
        if segment.kind == "equal" {
            matched_item_count += left_length;
        } else {
            change_segment_count += 1;
            inserted_item_count += right_length;
            deleted_item_count += left_length;
        }
    }
    let mut value = json!({
        "unit": unit,
        "leftItemCount": left_tokens.len(),
        "rightItemCount": right_tokens.len(),
        "matchedItemCount": matched_item_count,
        "insertedItemCount": inserted_item_count,
        "deletedItemCount": deleted_item_count,
        "segmentCount": segments.len(),
        "changeSegmentCount": change_segment_count,
        "segmentIndexSha256": segment_index_sha256(unit, &segments)
    });
    if mode == "full_required" {
        value
            .as_object_mut()
            .expect("alignment is an object")
            .insert(
                "segments".into(),
                Value::Array(
                    segments
                        .iter()
                        .map(|segment| public_segment(segment, left_map, right_map, unit))
                        .collect(),
                ),
            );
    }
    value
}

pub(crate) fn build(left: &TextMap, right: &TextMap, mode: &str) -> Value {
    let left_code_points = left
        .code_points
        .iter()
        .map(|item| item.character.clone())
        .collect::<Vec<_>>();
    let right_code_points = right
        .code_points
        .iter()
        .map(|item| item.character.clone())
        .collect::<Vec<_>>();
    let left_graphemes = left
        .graphemes
        .iter()
        .map(|item| item.text.clone())
        .collect::<Vec<_>>();
    let right_graphemes = right
        .graphemes
        .iter()
        .map(|item| item.text.clone())
        .collect::<Vec<_>>();
    json!({
        "algorithm": ALGORITHM,
        "tieBreak": TIE_BREAK,
        "replacementGrouping": REPLACEMENT_GROUPING,
        "codePoint": build_alignment(
            &left_code_points,
            &right_code_points,
            left,
            right,
            "code_point",
            mode
        ),
        "grapheme": build_alignment(
            &left_graphemes,
            &right_graphemes,
            left,
            right,
            "extended_grapheme_cluster",
            mode
        )
    })
}
