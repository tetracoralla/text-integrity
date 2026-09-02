import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertTextBudget } from "./limits.js";
import { runtimeInfo } from "./runtime.js";
import { segmentGraphemesUnicode17 } from "./grapheme.js";
import { assertKeys, requireInteger, requireObject, requireString } from "./validation.js";

function assertWellFormed(text, field = "text") {
  if (!text.isWellFormed()) {
    throw new TextIntegrityError("INVALID_UNICODE", `${field} contains an unpaired UTF-16 surrogate.`, { field });
  }
}

function rawCodePoints(text) {
  const entries = [];
  let utf16CodeUnit = 0;
  let utf8Byte = 0;
  let codePoint = 0;
  for (const character of text) {
    const utf8Bytes = Buffer.byteLength(character, "utf8");
    entries.push({
      character,
      value: `U+${character.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`,
      start: { utf8Byte, utf16CodeUnit, codePoint },
      end: {
        utf8Byte: utf8Byte + utf8Bytes,
        utf16CodeUnit: utf16CodeUnit + character.length,
        codePoint: codePoint + 1
      }
    });
    utf8Byte += utf8Bytes;
    utf16CodeUnit += character.length;
    codePoint += 1;
  }
  return entries;
}

function assignGraphemes(text, entries) {
  const graphemes = [];
  let entryIndex = 0;
  for (const [graphemeIndex, part] of segmentGraphemesUnicode17(text).entries()) {
    const endUtf16 = part.index + part.segment.length;
    while (entryIndex < entries.length && entries[entryIndex].start.utf16CodeUnit < endUtf16) {
      entries[entryIndex].grapheme = graphemeIndex;
      entryIndex += 1;
    }
    graphemes.push({
      text: part.segment,
      index: graphemeIndex,
      startUtf16CodeUnit: part.index,
      endUtf16CodeUnit: endUtf16
    });
  }
  return graphemes;
}

function assignLines(entries) {
  let line = 1;
  let columnCodePoint = 0;
  let columnUtf16CodeUnit = 0;
  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index];
    entry.start.line = line;
    entry.start.columnCodePoint = columnCodePoint;
    entry.start.columnUtf16CodeUnit = columnUtf16CodeUnit;

    const next = entries[index + 1]?.character;
    const isCrLfHead = entry.character === "\r" && next === "\n";
    const isBreak = entry.character === "\n"
      || (entry.character === "\r" && !isCrLfHead)
      || entry.character === "\u0085"
      || entry.character === "\u2028"
      || entry.character === "\u2029";

    if (isBreak) {
      line += 1;
      columnCodePoint = 0;
      columnUtf16CodeUnit = 0;
    } else {
      columnCodePoint += 1;
      columnUtf16CodeUnit += entry.character.length;
    }
    entry.end.line = line;
    entry.end.columnCodePoint = columnCodePoint;
    entry.end.columnUtf16CodeUnit = columnUtf16CodeUnit;
  }
  return { line, columnCodePoint, columnUtf16CodeUnit };
}

export function buildTextMap(text) {
  assertWellFormed(text);
  const codePoints = rawCodePoints(text);
  const graphemes = assignGraphemes(text, codePoints);
  const finalLine = assignLines(codePoints);
  const boundariesByUtf16 = new Map();
  for (const entry of codePoints) {
    boundariesByUtf16.set(entry.start.utf16CodeUnit, {
      ...entry.start,
      grapheme: entry.grapheme
    });
  }
  boundariesByUtf16.set(text.length, {
    utf8Byte: Buffer.byteLength(text, "utf8"),
    utf16CodeUnit: text.length,
    codePoint: codePoints.length,
    grapheme: graphemes.length,
    ...finalLine
  });
  return { codePoints, graphemes, boundariesByUtf16 };
}

export function coordinateAtUtf16(map, index, field = "indexUtf16") {
  const coordinate = map.boundariesByUtf16.get(index);
  if (!coordinate) {
    throw new TextIntegrityError("INVALID_SPAN", `${field} must be a Unicode code-point boundary.`, {
      field,
      indexUtf16: index
    });
  }
  return coordinate;
}

export function lineEndingObservations(text, detailLimit = LIMITS.defaultDetailItems) {
  const map = buildTextMap(text);
  const counts = { crlf: 0, lf: 0, cr: 0, nel: 0, lineSeparator: 0, paragraphSeparator: 0 };
  const items = [];
  for (let index = 0; index < map.codePoints.length; index += 1) {
    const entry = map.codePoints[index];
    let kind;
    let end = entry.end;
    if (entry.character === "\r" && map.codePoints[index + 1]?.character === "\n") {
      kind = "crlf";
      end = map.codePoints[index + 1].end;
      index += 1;
    } else if (entry.character === "\n") kind = "lf";
    else if (entry.character === "\r") kind = "cr";
    else if (entry.character === "\u0085") kind = "nel";
    else if (entry.character === "\u2028") kind = "lineSeparator";
    else if (entry.character === "\u2029") kind = "paragraphSeparator";
    if (!kind) continue;
    counts[kind] += 1;
    if (items.length < detailLimit) items.push({ kind, start: entry.start, end });
  }
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  return { counts, total, items, truncated: total > items.length };
}

function chunkText(text, map, maxChunkUtf8Bytes) {
  const chunks = [];
  let currentText = "";
  let currentStartUtf16 = 0;
  let currentBytes = 0;

  function publish(endUtf16) {
    if (currentText === "") return;
    chunks.push({
      index: chunks.length,
      text: currentText,
      utf8Bytes: currentBytes,
      start: coordinateAtUtf16(map, currentStartUtf16),
      end: coordinateAtUtf16(map, endUtf16)
    });
    currentText = "";
    currentBytes = 0;
    currentStartUtf16 = endUtf16;
  }

  for (const grapheme of map.graphemes) {
    const bytes = Buffer.byteLength(grapheme.text, "utf8");
    if (bytes > maxChunkUtf8Bytes) {
      throw new TextIntegrityError(
        "CHUNK_GRAPHEME_TOO_LARGE",
        "A single grapheme exceeds the requested UTF-8 chunk budget.",
        {
          graphemeIndex: grapheme.index,
          graphemeUtf8Bytes: bytes,
          maxChunkUtf8Bytes
        }
      );
    }
    if (currentBytes > 0 && currentBytes + bytes > maxChunkUtf8Bytes) {
      publish(grapheme.startUtf16CodeUnit);
    }
    currentText += grapheme.text;
    currentBytes += bytes;
  }
  publish(text.length);

  if (chunks.length > LIMITS.maxChunks) {
    throw new TextIntegrityError(
      "TOO_MANY_CHUNKS",
      `Chunking would exceed the ${LIMITS.maxChunks}-chunk result limit.`,
      { actualChunks: chunks.length, limitChunks: LIMITS.maxChunks }
    );
  }
  return chunks;
}

export function indexText(args) {
  requireObject(args);
  assertKeys(args, ["text", "detailLimit", "maxChunkUtf8Bytes"], ["text"]);
  const text = requireString(args.text, "text");
  assertTextBudget(text, "text");
  assertWellFormed(text);
  const detailLimit = Object.hasOwn(args, "detailLimit")
    ? requireInteger(args.detailLimit, "detailLimit", 0, LIMITS.maxDetailItems)
    : LIMITS.defaultDetailItems;
  const maxChunkUtf8Bytes = Object.hasOwn(args, "maxChunkUtf8Bytes")
    ? requireInteger(args.maxChunkUtf8Bytes, "maxChunkUtf8Bytes", 1, LIMITS.maxChunkBytes)
    : undefined;

  const map = buildTextMap(text);
  const codePoints = map.codePoints.slice(0, detailLimit).map((entry) => ({
    character: entry.character,
    value: entry.value,
    grapheme: entry.grapheme,
    start: entry.start,
    end: entry.end
  }));
  const graphemes = map.graphemes.slice(0, detailLimit).map((entry) => ({
    index: entry.index,
    text: entry.text,
    start: coordinateAtUtf16(map, entry.startUtf16CodeUnit),
    end: coordinateAtUtf16(map, entry.endUtf16CodeUnit)
  }));

  return {
    status: "ok",
    operation: "index",
    counts: {
      utf8Bytes: Buffer.byteLength(text, "utf8"),
      utf16CodeUnits: text.length,
      codePoints: map.codePoints.length,
      graphemes: map.graphemes.length,
      lines: map.codePoints.length === 0 ? 1 : coordinateAtUtf16(map, text.length).line
    },
    detail: {
      limit: detailLimit,
      codePoints,
      codePointsTruncated: map.codePoints.length > codePoints.length,
      graphemes,
      graphemesTruncated: map.graphemes.length > graphemes.length
    },
    lineEndings: lineEndingObservations(text, detailLimit),
    ...(maxChunkUtf8Bytes === undefined ? {} : {
      chunking: {
        maxChunkUtf8Bytes,
        boundary: "extended_grapheme_cluster",
        chunks: chunkText(text, map, maxChunkUtf8Bytes)
      }
    }),
    runtime: runtimeInfo()
  };
}
