// Generate the Rust verifier's complete Unicode 17 UBA data source and the
// project-owned L3/L4 tables from the pinned source bundle. The Rust algorithm
// is supplied by unicode-bidi with its hardcoded Unicode data disabled.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const MANIFEST_PATH = new URL("../vendor/unicode/17.0.0/MANIFEST.json", import.meta.url);
const DATA_ROOT = new URL("../vendor/unicode/17.0.0/", import.meta.url);
const OUTPUT_PATH = new URL("../native/src/bidi_data.rs", import.meta.url);
const BIDI_CLASS_PATH = "ucd/extracted/DerivedBidiClass.txt";
const BIDI_BRACKETS_PATH = "ucd/BidiBrackets.txt";
const BIDI_MIRRORING_PATH = "ucd/BidiMirroring.txt";
const UNICODE_DATA_PATH = "ucd/UnicodeData.txt";
const mode = process.argv[2] ?? "--check";

if (!new Set(["--check", "--write"]).has(mode)) {
  process.stderr.write("usage: node scripts/build-native-bidi-data.mjs [--check|--write]\n");
  process.exit(2);
}

const CLASS_CODES = Object.freeze([
  "L", "R", "EN", "ES", "ET", "AN", "CS", "B", "S", "WS", "ON", "BN", "NSM",
  "AL", "LRO", "RLO", "LRE", "RLE", "PDF", "LRI", "RLI", "FSI", "PDI"
]);
const CLASS_ALIASES = Object.freeze({
  Left_To_Right: "L",
  Right_To_Left: "R",
  Arabic_Letter: "AL",
  European_Terminator: "ET"
});

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseRange(value) {
  const [first, last = first] = value.trim().split("..");
  const start = Number.parseInt(first, 16);
  const end = Number.parseInt(last, 16);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end > 0x10ffff) {
    throw new Error(`invalid code-point range: ${value}`);
  }
  return { start, end };
}

function rows(text) {
  return text.split(/\r?\n/u).flatMap((sourceLine) => {
    const content = sourceLine.split("#", 1)[0].trim();
    return content === "" ? [] : [content.split(";").map((field) => field.trim())];
  });
}

const manifestBytes = readFileSync(MANIFEST_PATH);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
if (manifest.unicodeVersion !== "17.0.0") {
  throw new Error(`expected Unicode 17.0.0, received ${manifest.unicodeVersion}`);
}

function verifiedSource(relativePath) {
  const bytes = readFileSync(new URL(relativePath, DATA_ROOT));
  const entry = manifest.files.find((item) => item.path === relativePath);
  if (!entry || entry.bytes !== bytes.length || entry.sha256 !== sha256(bytes)) {
    throw new Error(`${relativePath} does not match the pinned Unicode manifest`);
  }
  return { bytes, entry };
}

const bidiClassSource = verifiedSource(BIDI_CLASS_PATH);
const bidiBracketsSource = verifiedSource(BIDI_BRACKETS_PATH);
const bidiMirroringSource = verifiedSource(BIDI_MIRRORING_PATH);
const unicodeDataSource = verifiedSource(UNICODE_DATA_PATH);

function canonicalClass(value) {
  const result = CLASS_ALIASES[value] ?? value;
  if (!CLASS_CODES.includes(result)) throw new Error(`unsupported Bidi_Class value: ${value}`);
  return result;
}

const explicitClasses = rows(bidiClassSource.bytes.toString("utf8")).map((fields) => ({
  ...parseRange(fields[0]),
  value: canonicalClass(fields[1])
})).sort((left, right) => left.start - right.start || left.end - right.end);
for (let index = 1; index < explicitClasses.length; index += 1) {
  if (explicitClasses[index - 1].end >= explicitClasses[index].start) {
    throw new Error("explicit Bidi_Class ranges overlap or are unsorted");
  }
}

const missingClasses = bidiClassSource.bytes.toString("utf8").split(/\r?\n/u).flatMap((line) => {
  const match = line.match(/#\s*@missing:\s*([^;]+);\s*([A-Za-z_]+)/u);
  return match ? [{ ...parseRange(match[1]), value: canonicalClass(match[2]) }] : [];
});
if (missingClasses.length === 0 || missingClasses[0].start !== 0 || missingClasses[0].end !== 0x10ffff) {
  throw new Error("DerivedBidiClass.txt is missing its complete default range");
}

function classFor(codePoint) {
  let low = 0;
  let high = explicitClasses.length;
  while (low < high) {
    const middle = low + ((high - low) >>> 1);
    const range = explicitClasses[middle];
    if (codePoint < range.start) high = middle;
    else if (codePoint > range.end) low = middle + 1;
    else return range.value;
  }
  for (let index = missingClasses.length - 1; index >= 0; index -= 1) {
    const range = missingClasses[index];
    if (codePoint >= range.start && codePoint <= range.end) return range.value;
  }
  throw new Error(`Bidi_Class is not closed for U+${codePoint.toString(16)}`);
}

const bidiClassRanges = [];
let rangeStart = 0;
let rangeClass = classFor(0);
for (let codePoint = 1; codePoint <= 0x10ffff; codePoint += 1) {
  const value = classFor(codePoint);
  if (value === rangeClass) continue;
  bidiClassRanges.push({ start: rangeStart, end: codePoint - 1, value: rangeClass });
  rangeStart = codePoint;
  rangeClass = value;
}
bidiClassRanges.push({ start: rangeStart, end: 0x10ffff, value: rangeClass });

const canonicalDecompositions = new Map();
const combiningClassRows = [];
for (const line of unicodeDataSource.bytes.toString("utf8").split(/\r?\n/u)) {
  if (line === "") continue;
  const fields = line.split(";");
  if (fields.length < 15) throw new Error("malformed UnicodeData row");
  const codePoint = Number.parseInt(fields[0], 16);
  const combiningClass = Number.parseInt(fields[3], 10);
  if (combiningClass !== 0) combiningClassRows.push({ start: codePoint, end: codePoint, value: combiningClass });
  if (fields[5] !== "" && !fields[5].startsWith("<")) {
    canonicalDecompositions.set(
      codePoint,
      fields[5].split(/\s+/u).map((item) => Number.parseInt(item, 16))
    );
  }
}

function canonicalNfd(codePoint, stack = new Set()) {
  const mapping = canonicalDecompositions.get(codePoint);
  if (!mapping) return [codePoint];
  if (stack.has(codePoint)) throw new Error(`canonical decomposition cycle at U+${codePoint.toString(16)}`);
  const nextStack = new Set(stack).add(codePoint);
  return mapping.flatMap((item) => canonicalNfd(item, nextStack));
}

const brackets = rows(bidiBracketsSource.bytes.toString("utf8")).map((fields) => {
  const codePoint = Number.parseInt(fields[0], 16);
  const paired = Number.parseInt(fields[1], 16);
  const isOpen = fields[2] === "o";
  if (!isOpen && fields[2] !== "c") throw new Error("unsupported Bidi_Paired_Bracket_Type");
  const opening = isOpen ? codePoint : paired;
  const normalized = canonicalNfd(opening);
  if (normalized.length !== 1) throw new Error(`opening bracket U+${opening.toString(16)} does not normalize to one scalar`);
  return { codePoint, opening: normalized[0], isOpen };
}).sort((left, right) => left.codePoint - right.codePoint);
for (let index = 1; index < brackets.length; index += 1) {
  if (brackets[index - 1].codePoint >= brackets[index].codePoint) {
    throw new Error("Bidi bracket entries are duplicated or unsorted");
  }
}

const mirroring = rows(bidiMirroringSource.bytes.toString("utf8")).map((fields) => ({
  source: Number.parseInt(fields[0], 16),
  target: Number.parseInt(fields[1], 16)
})).sort((left, right) => left.source - right.source);
for (let index = 1; index < mirroring.length; index += 1) {
  if (mirroring[index - 1].source >= mirroring[index].source) {
    throw new Error("Bidi mirroring entries are duplicated or unsorted");
  }
}

const combiningClassRanges = [];
for (const entry of combiningClassRows) {
  const previous = combiningClassRanges.at(-1);
  if (previous && previous.end + 1 === entry.start && previous.value === entry.value) previous.end = entry.end;
  else combiningClassRanges.push({ ...entry });
}
const combiningCodePointCount = combiningClassRanges.reduce(
  (count, { start, end }) => count + end - start + 1,
  0
);

const lines = [
  "// @generated by scripts/build-native-bidi-data.mjs; do not edit by hand.",
  `pub const UNICODE_VERSION: &str = ${JSON.stringify(manifest.unicodeVersion)};`,
  "pub const SOURCE_MANIFEST_SHA256: &str =",
  `    ${JSON.stringify(sha256(manifestBytes))};`,
  `pub const BIDI_CLASS_SOURCE_PATH: &str = ${JSON.stringify(BIDI_CLASS_PATH)};`,
  "pub const BIDI_CLASS_SOURCE_SHA256: &str =",
  `    ${JSON.stringify(bidiClassSource.entry.sha256)};`,
  `pub const BIDI_BRACKETS_SOURCE_PATH: &str = ${JSON.stringify(BIDI_BRACKETS_PATH)};`,
  "pub const BIDI_BRACKETS_SOURCE_SHA256: &str =",
  `    ${JSON.stringify(bidiBracketsSource.entry.sha256)};`,
  `pub const BIDI_MIRRORING_SOURCE_PATH: &str = ${JSON.stringify(BIDI_MIRRORING_PATH)};`,
  "pub const BIDI_MIRRORING_SOURCE_SHA256: &str =",
  `    ${JSON.stringify(bidiMirroringSource.entry.sha256)};`,
  `pub const UNICODE_DATA_SOURCE_PATH: &str = ${JSON.stringify(UNICODE_DATA_PATH)};`,
  "pub const UNICODE_DATA_SOURCE_SHA256: &str =",
  `    ${JSON.stringify(unicodeDataSource.entry.sha256)};`,
  `pub const BIDI_CLASS_RANGE_COUNT: usize = ${bidiClassRanges.length};`,
  `pub const BIDI_BRACKET_ENTRY_COUNT: usize = ${brackets.length};`,
  `pub const COMBINING_CLASS_RANGE_COUNT: usize = ${combiningClassRanges.length};`,
  `pub const COMBINING_CLASS_CODE_POINT_COUNT: usize = ${combiningCodePointCount};`,
  `pub const BIDI_MIRRORING_ENTRY_COUNT: usize = ${mirroring.length};`,
  "#[rustfmt::skip]",
  "pub const BIDI_CLASS_RANGES: &[(u32, u32, u8)] = &[",
  ...bidiClassRanges.map(({ start, end, value }) =>
    `    (0x${start.toString(16)}, 0x${end.toString(16)}, ${CLASS_CODES.indexOf(value)}),`
  ),
  "];",
  "#[rustfmt::skip]",
  "pub const BIDI_BRACKETS: &[(u32, u32, bool)] = &[",
  ...brackets.map(({ codePoint, opening, isOpen }) =>
    `    (0x${codePoint.toString(16)}, 0x${opening.toString(16)}, ${isOpen}),`
  ),
  "];",
  "#[rustfmt::skip]",
  "pub const COMBINING_CLASS_RANGES: &[(u32, u32, u8)] = &[",
  ...combiningClassRanges.map(({ start, end, value }) =>
    `    (0x${start.toString(16)}, 0x${end.toString(16)}, ${value}),`
  ),
  "];",
  "#[rustfmt::skip]",
  "pub const BIDI_MIRRORING: &[(u32, u32)] = &[",
  ...mirroring.map(({ source, target }) =>
    `    (0x${source.toString(16)}, 0x${target.toString(16)}),`
  ),
  "];",
  ""
];
const rendered = Buffer.from(lines.join("\n"));

if (mode === "--write") {
  writeFileSync(OUTPUT_PATH, rendered);
  process.stdout.write(
    `native Unicode 17 UBA tables updated (${bidiClassRanges.length} class ranges, ${brackets.length} brackets, ${combiningClassRanges.length} combining ranges, ${mirroring.length} mirrors)\n`
  );
} else {
  let committed;
  try {
    committed = readFileSync(OUTPUT_PATH);
  } catch {
    process.stderr.write("native Unicode 17 UBA tables are missing; run with --write\n");
    process.exit(1);
  }
  if (!committed.equals(rendered)) {
    process.stderr.write("native Unicode 17 UBA tables do not reproduce from the pinned Unicode sources\n");
    process.exit(1);
  }
  process.stdout.write(
    `native Unicode 17 UBA tables match (${bidiClassRanges.length} class ranges, ${brackets.length} brackets, ${combiningClassRanges.length} combining ranges, ${mirroring.length} mirrors)\n`
  );
}
