import { createHash } from "node:crypto";
import { coordinateAtUtf16 } from "./text-position.js";

export const DIFFERENCE_ALIGNMENT_ALGORITHM = "text-integrity.lcs-insert-delete-alignment/1";
export const DIFFERENCE_ALIGNMENT_TIE_BREAK = "highest_right_split_then_first_match";
export const DIFFERENCE_ALIGNMENT_REPLACEMENT_GROUPING = "contiguous_non_equal";

const SEGMENT_IDENTITY_SCHEMA = "text-integrity.alignment-segment-indexes/1";

function lcsLengths(left, leftStart, leftEnd, right, rightStart, rightEnd, reverse) {
  const rightLength = rightEnd - rightStart;
  let previous = new Uint16Array(rightLength + 1);
  let current = new Uint16Array(rightLength + 1);
  const leftLength = leftEnd - leftStart;
  for (let leftOffset = 0; leftOffset < leftLength; leftOffset += 1) {
    current[0] = 0;
    const leftValue = reverse
      ? left[leftEnd - leftOffset - 1]
      : left[leftStart + leftOffset];
    for (let rightOffset = 0; rightOffset < rightLength; rightOffset += 1) {
      const rightValue = reverse
        ? right[rightEnd - rightOffset - 1]
        : right[rightStart + rightOffset];
      current[rightOffset + 1] = leftValue === rightValue
        ? previous[rightOffset] + 1
        : Math.max(previous[rightOffset + 1], current[rightOffset]);
    }
    [previous, current] = [current, previous];
  }
  return previous;
}

function appendAtomic(segments, kind, leftStart, leftEnd, rightStart, rightEnd) {
  if (leftStart === leftEnd && rightStart === rightEnd) return;
  const previous = segments.at(-1);
  if (previous?.kind === kind
    && previous.leftEnd === leftStart
    && previous.rightEnd === rightStart) {
    previous.leftEnd = leftEnd;
    previous.rightEnd = rightEnd;
    return;
  }
  segments.push({ kind, leftStart, leftEnd, rightStart, rightEnd });
}

function alignRange(left, leftStart, leftEnd, right, rightStart, rightEnd, segments) {
  const leftLength = leftEnd - leftStart;
  const rightLength = rightEnd - rightStart;
  if (leftLength === 0) {
    appendAtomic(segments, "insert", leftStart, leftEnd, rightStart, rightEnd);
    return;
  }
  if (rightLength === 0) {
    appendAtomic(segments, "delete", leftStart, leftEnd, rightStart, rightEnd);
    return;
  }
  if (leftLength === 1) {
    let match = -1;
    for (let index = rightStart; index < rightEnd; index += 1) {
      if (left[leftStart] === right[index]) {
        match = index;
        break;
      }
    }
    if (match === -1) {
      appendAtomic(segments, "delete", leftStart, leftEnd, rightStart, rightStart);
      appendAtomic(segments, "insert", leftEnd, leftEnd, rightStart, rightEnd);
      return;
    }
    appendAtomic(segments, "insert", leftStart, leftStart, rightStart, match);
    appendAtomic(segments, "equal", leftStart, leftEnd, match, match + 1);
    appendAtomic(segments, "insert", leftEnd, leftEnd, match + 1, rightEnd);
    return;
  }

  const leftMiddle = leftStart + Math.floor(leftLength / 2);
  const forward = lcsLengths(left, leftStart, leftMiddle, right, rightStart, rightEnd, false);
  const backward = lcsLengths(left, leftMiddle, leftEnd, right, rightStart, rightEnd, true);
  let bestRightOffset = 0;
  let bestLength = -1;
  for (let offset = 0; offset <= rightLength; offset += 1) {
    const length = forward[offset] + backward[rightLength - offset];
    if (length >= bestLength) {
      bestLength = length;
      bestRightOffset = offset;
    }
  }
  const rightMiddle = rightStart + bestRightOffset;
  alignRange(left, leftStart, leftMiddle, right, rightStart, rightMiddle, segments);
  alignRange(left, leftMiddle, leftEnd, right, rightMiddle, rightEnd, segments);
}

function groupChanges(atomic) {
  const grouped = [];
  for (let index = 0; index < atomic.length;) {
    const segment = atomic[index];
    if (segment.kind === "equal") {
      grouped.push({ ...segment });
      index += 1;
      continue;
    }
    const change = {
      leftStart: segment.leftStart,
      leftEnd: segment.leftEnd,
      rightStart: segment.rightStart,
      rightEnd: segment.rightEnd
    };
    index += 1;
    while (index < atomic.length && atomic[index].kind !== "equal") {
      change.leftEnd = atomic[index].leftEnd;
      change.rightEnd = atomic[index].rightEnd;
      index += 1;
    }
    const leftLength = change.leftEnd - change.leftStart;
    const rightLength = change.rightEnd - change.rightStart;
    grouped.push({
      kind: leftLength > 0 && rightLength > 0
        ? "replace"
        : leftLength > 0 ? "delete" : "insert",
      ...change
    });
  }
  return grouped;
}

function segmentIndexSha256(unit, segments) {
  const digest = createHash("sha256");
  digest.update(SEGMENT_IDENTITY_SCHEMA);
  digest.update("\0");
  digest.update(unit);
  for (const segment of segments) {
    for (const value of [
      segment.kind,
      segment.leftStart,
      segment.leftEnd,
      segment.rightStart,
      segment.rightEnd
    ]) {
      digest.update("\0");
      digest.update(String(value));
    }
  }
  return digest.digest("hex");
}

function boundary(map, unit, index) {
  const utf16 = unit === "code_point"
    ? map.codePoints[index]?.start.utf16CodeUnit ?? map.codePoints.at(-1)?.end.utf16CodeUnit ?? 0
    : map.graphemes[index]?.startUtf16CodeUnit ?? map.graphemes.at(-1)?.endUtf16CodeUnit ?? 0;
  return coordinateAtUtf16(map, utf16);
}

function publicSegment(segment, leftMap, rightMap, unit) {
  return {
    kind: segment.kind,
    left: {
      startIndex: segment.leftStart,
      endIndex: segment.leftEnd,
      start: boundary(leftMap, unit, segment.leftStart),
      end: boundary(leftMap, unit, segment.leftEnd)
    },
    right: {
      startIndex: segment.rightStart,
      endIndex: segment.rightEnd,
      start: boundary(rightMap, unit, segment.rightStart),
      end: boundary(rightMap, unit, segment.rightEnd)
    }
  };
}

function buildAlignment(leftTokens, rightTokens, leftMap, rightMap, unit, mode) {
  const atomic = [];
  alignRange(leftTokens, 0, leftTokens.length, rightTokens, 0, rightTokens.length, atomic);
  const segments = groupChanges(atomic);
  let matchedItemCount = 0;
  let insertedItemCount = 0;
  let deletedItemCount = 0;
  let changeSegmentCount = 0;
  for (const segment of segments) {
    const leftLength = segment.leftEnd - segment.leftStart;
    const rightLength = segment.rightEnd - segment.rightStart;
    if (segment.kind === "equal") matchedItemCount += leftLength;
    else {
      changeSegmentCount += 1;
      insertedItemCount += rightLength;
      deletedItemCount += leftLength;
    }
  }
  return {
    unit,
    leftItemCount: leftTokens.length,
    rightItemCount: rightTokens.length,
    matchedItemCount,
    insertedItemCount,
    deletedItemCount,
    segmentCount: segments.length,
    changeSegmentCount,
    segmentIndexSha256: segmentIndexSha256(unit, segments),
    ...(mode === "full_required"
      ? { segments: segments.map((segment) => publicSegment(segment, leftMap, rightMap, unit)) }
      : {})
  };
}

export function buildDifferenceAlignments(leftMap, rightMap, mode) {
  return {
    algorithm: DIFFERENCE_ALIGNMENT_ALGORITHM,
    tieBreak: DIFFERENCE_ALIGNMENT_TIE_BREAK,
    replacementGrouping: DIFFERENCE_ALIGNMENT_REPLACEMENT_GROUPING,
    codePoint: buildAlignment(
      leftMap.codePoints.map((item) => item.character),
      rightMap.codePoints.map((item) => item.character),
      leftMap,
      rightMap,
      "code_point",
      mode
    ),
    grapheme: buildAlignment(
      leftMap.graphemes.map((item) => item.text),
      rightMap.graphemes.map((item) => item.text),
      leftMap,
      rightMap,
      "extended_grapheme_cluster",
      mode
    )
  };
}
