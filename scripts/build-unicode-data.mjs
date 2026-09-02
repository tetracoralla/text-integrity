// Build-time compaction of the pinned Unicode 17 UCD/UTS #39 text files into
// one deterministic binary interval-table blob. The repository keeps the full
// text corpora as the source of record for CI; the runtime package ships only
// the generated blob. Given identical vendor inputs this script is byte-for-byte
// reproducible: no timestamps, fixed section order, insertion-ordered string
// pool.
//
// Usage:
//   node scripts/build-unicode-data.mjs           regenerate the blob in place
//   node scripts/build-unicode-data.mjs --check   verify the committed blob reproduces exactly

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { UNICODE_SECURITY_MANIFEST_SHA256 } from "../src/core/unicode-security-data.js";
import { parseNormalizationData } from "./unicode-normalization-data.mjs";

const ROOT = new URL("../", import.meta.url);
const DATA_ROOT = new URL("../vendor/unicode/17.0.0/", import.meta.url);
const COMPACT_DIR = new URL("compact/", DATA_ROOT);
const COMPACT_DATA_PATH = new URL("data.bin", COMPACT_DIR);
const COMPACT_MANIFEST_PATH = new URL("MANIFEST.json", COMPACT_DIR);
const FORMAT_VERSION = 4;
const CHECK_ONLY = process.argv.includes("--check");

const EXPECTED_UNICODE_VERSION = "17.0.0";
const EXPECTED_UTS39_REVISION = 32;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function looseKey(value) {
  return value.toLowerCase().replace(/[\s_-]/gu, "");
}

function parseRange(value) {
  const [first, last = first] = value.trim().split("..");
  const start = Number.parseInt(first, 16);
  const end = Number.parseInt(last, 16);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end > 0x10ffff) {
    throw new Error(`invalid code-point range: ${value.trim()}`);
  }
  return [start, end];
}

function dataRows(text) {
  const rows = [];
  for (const line of text.split(/\r?\n/u)) {
    const content = line.split("#", 1)[0].trim();
    if (content === "") continue;
    const fields = content.split(";").map((field) => field.trim());
    if (fields.length >= 2) rows.push(fields);
  }
  return rows;
}

function parseAliases(text, property) {
  const aliases = new Map();
  for (const fields of dataRows(text)) {
    if (looseKey(fields[0]) !== looseKey(property) || fields.length < 3) continue;
    const canonical = fields[1];
    for (const value of fields.slice(1)) {
      if (value !== "") aliases.set(looseKey(value), canonical);
    }
  }
  return aliases;
}

function parseAssignments(text, transform = (value) => value) {
  const ranges = [];
  for (const [range, value] of dataRows(text)) {
    const [start, end] = parseRange(range);
    ranges.push({ start, end, value: transform(value) });
  }
  ranges.sort((left, right) => left.start - right.start || left.end - right.end);
  return ranges;
}

function parsePropertyRanges(text, property) {
  return parseAssignments(text)
    .filter((entry) => entry.value === property)
    .map(({ start, end }) => ({ start, end, value: true }));
}

function parseQualifiedAssignments(text, property) {
  const ranges = [];
  for (const fields of dataRows(text)) {
    if (fields[1] !== property || fields.length < 3) continue;
    const [start, end] = parseRange(fields[0]);
    ranges.push({ start, end, value: fields[2] });
  }
  ranges.sort((left, right) => left.start - right.start || left.end - right.end);
  return ranges;
}

function parseMissingAssignments(text, aliases) {
  const ranges = [];
  for (const line of text.split(/\r?\n/u)) {
    const match = line.match(/^#\s*@missing:\s*([0-9A-F.]+)\s*;\s*(?:Bidi_Class\s*;\s*)?([^#\s;]+)/iu);
    if (!match) continue;
    const [start, end] = parseRange(match[1]);
    const value = aliases.get(looseKey(match[2])) ?? match[2];
    ranges.push({ start, end, value });
  }
  return ranges;
}

function parseConfusables(text) {
  const mappings = [];
  for (const fields of dataRows(text)) {
    if (fields.length < 3 || fields[2] !== "MA") throw new Error("unsupported confusables row");
    const source = fields[0].split(/\s+/u);
    if (source.length !== 1) throw new Error("multi-code-point confusable source");
    const sourceCodePoint = Number.parseInt(source[0], 16);
    const target = fields[1].split(/\s+/u).filter(Boolean)
      .map((value) => String.fromCodePoint(Number.parseInt(value, 16))).join("");
    mappings.push({ key: sourceCodePoint, value: target });
  }
  mappings.sort((left, right) => left.key - right.key);
  return mappings;
}

function parseNfkcCasefold(text) {
  const ranges = [];
  for (const fields of dataRows(text)) {
    if (fields[1] !== "NFKC_CF") continue;
    const [start, end] = parseRange(fields[0]);
    const mapping = (fields[2] ?? "").split(/\s+/u).filter(Boolean)
      .map((value) => String.fromCodePoint(Number.parseInt(value, 16))).join("");
    ranges.push({ start, end, value: mapping });
  }
  ranges.sort((left, right) => left.start - right.start || left.end - right.end);
  return ranges;
}

function parseUnicodeData(text) {
  const combiningClasses = [];
  const decimalValues = [];
  const widthMappings = [];
  const lowercaseMappings = new Map();
  for (const line of text.split(/\r?\n/u)) {
    if (line === "") continue;
    const fields = line.split(";");
    if (fields.length < 15) throw new Error("malformed UnicodeData row");
    const codePoint = Number.parseInt(fields[0], 16);
    const combiningClass = Number.parseInt(fields[3], 10);
    if (combiningClass !== 0) combiningClasses.push({ start: codePoint, end: codePoint, value: combiningClass });
    if (fields[6] !== "") decimalValues.push({ start: codePoint, end: codePoint, value: Number.parseInt(fields[6], 10) });
    if (fields[13] !== "") {
      lowercaseMappings.set(codePoint, String.fromCodePoint(Number.parseInt(fields[13], 16)));
    }
    const decomposition = fields[5];
    if (decomposition.startsWith("<")) {
      const match = decomposition.match(/^<(?:wide|narrow)>\s+(.+)$/u);
      if (match) {
        widthMappings.push({
          key: codePoint,
          value: match[1].split(/\s+/u).map((value) => String.fromCodePoint(Number.parseInt(value, 16))).join("")
        });
      }
    }
  }
  combiningClasses.sort((left, right) => left.start - right.start);
  decimalValues.sort((left, right) => left.start - right.start);
  widthMappings.sort((left, right) => left.key - right.key);
  return { combiningClasses, decimalValues, widthMappings, lowercaseMappings };
}

function parseDefaultLowercaseMappings(unicodeData, specialCasingText) {
  const mappings = new Map(unicodeData.lowercaseMappings);
  for (const fields of dataRows(specialCasingText)) {
    if (fields.length < 5) throw new Error("malformed SpecialCasing row");
    if (fields[4] !== "") continue;
    const codePoint = Number.parseInt(fields[0], 16);
    const value = fields[1].split(/\s+/u).filter(Boolean)
      .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("");
    mappings.set(codePoint, value);
  }
  return [...mappings.entries()]
    .filter(([codePoint, value]) => value !== String.fromCodePoint(codePoint))
    .map(([key, value]) => ({ key, value }))
    .sort((left, right) => left.key - right.key);
}

function parseBidiMirroring(text) {
  const mappings = [];
  for (const fields of dataRows(text)) {
    mappings.push({ key: Number.parseInt(fields[0], 16), value: Number.parseInt(fields[1], 16) });
  }
  mappings.sort((left, right) => left.key - right.key);
  return mappings;
}

function scriptsWithIdentifierType(scriptRanges, typeRanges, type) {
  const scripts = new Set();
  let typeIndex = 0;
  for (const script of scriptRanges) {
    while (typeIndex < typeRanges.length && typeRanges[typeIndex].end < script.start) typeIndex += 1;
    for (let index = typeIndex; index < typeRanges.length && typeRanges[index].start <= script.end; index += 1) {
      if (typeRanges[index].value.includes(type)) scripts.add(script.value);
    }
  }
  return [...scripts];
}

function verifyVendorBundle() {
  const manifestBytes = readFileSync(new URL("MANIFEST.json", DATA_ROOT));
  const actualManifestSha256 = sha256(manifestBytes);
  if (actualManifestSha256 !== UNICODE_SECURITY_MANIFEST_SHA256) {
    throw new Error(`vendor manifest sha256 mismatch: expected ${UNICODE_SECURITY_MANIFEST_SHA256}, saw ${actualManifestSha256}`);
  }
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (manifest.unicodeVersion !== EXPECTED_UNICODE_VERSION || manifest.uts39Revision !== EXPECTED_UTS39_REVISION) {
    throw new Error("vendor manifest has an unexpected version");
  }
  const files = new Map();
  for (const entry of manifest.files) {
    const bytes = readFileSync(new URL(entry.path, DATA_ROOT));
    const actualSha256 = sha256(bytes);
    if (bytes.length !== entry.bytes || actualSha256 !== entry.sha256) {
      throw new Error(`vendor file failed verification: ${entry.path}`);
    }
    files.set(entry.path, bytes);
  }
  return { manifest, files };
}

// ---------------------------------------------------------------------------
// Binary layout (all integers little-endian u32):
//   [magic][headerByteLength][header JSON, NUL-padded to 4]
//   [stringOffsetCount][string byte offsets...][UTF-8 string bytes, 0-padded]
//   [section u32 arrays in fixed order]
// Section value encoding: bool => 1; integer => the integer; string/multi-
// string/byte-string => index into the string pool. Multi-values are pooled as
// "+"-joined tokens (script names and identifier-type tokens are [A-Za-z0-9_]+).
// ---------------------------------------------------------------------------

const MAGIC = 0x31495554;
// Sections are u32 arrays; entry width is 3 units for range tables
// (start, end, value), 2 for code-point-keyed maps, 1 for plain lists.
const SECTION_ENTRY_UNITS = Object.freeze({
  recommendedScripts: 1,
  bidiMirroring: 2,
  confusables: 2,
  widthMappings: 2,
  lowercaseMappings: 2,
  canonicalDecompositions: 2,
  compatibilityDecompositions: 2,
  compositionMappings: 3
});
const SECTION_ORDER = Object.freeze([
  "identifierAllowed",
  "identifierTypes",
  "confusables",
  "defaultIgnorable",
  "cased",
  "caseIgnorable",
  "graphemeBreaks",
  "extendedPictographic",
  "indicConjunctBreak",
  "xidStart",
  "xidContinue",
  "bidiControl",
  "formatCharacter",
  "scripts",
  "recommendedScripts",
  "scriptExtensions",
  "bidiClasses",
  "bidiMissing",
  "bidiMirroring",
  "nfkcCasefoldMappings",
  "combiningClasses",
  "canonicalDecompositions",
  "compatibilityDecompositions",
  "compositionMappings",
  "decimalValues",
  "widthMappings",
  "lowercaseMappings",
  "joinControl",
  "noncharacter",
  "unassigned",
  "generalCategories",
  "joiningTypes",
  "oldHangulJamo"
]);

function buildBlob() {
  const { manifest, files } = verifyVendorBundle();
  const source = (path) => files.get(path).toString("utf8");
  const aliasesText = source("ucd/PropertyValueAliases.txt");
  const scriptAliases = parseAliases(aliasesText, "sc");
  const bidiAliases = parseAliases(aliasesText, "bc");
  const canonicalScript = (value) => scriptAliases.get(looseKey(value)) ?? value;
  const canonicalBidi = (value) => bidiAliases.get(looseKey(value)) ?? value;
  const bidiText = source("ucd/extracted/DerivedBidiClass.txt");
  const identifierTypes = parseAssignments(source("security/IdentifierType.txt"), (value) => value.split(/\s+/u));
  const scripts = parseAssignments(source("ucd/Scripts.txt"), canonicalScript);
  const unicodeData = parseUnicodeData(source("ucd/UnicodeData.txt"));
  const derivedCoreProperties = source("ucd/DerivedCoreProperties.txt");
  const normalizationData = parseNormalizationData(
    source("ucd/UnicodeData.txt"),
    source("ucd/DerivedNormalizationProps.txt")
  );
  const categories = source("ucd/extracted/DerivedGeneralCategory.txt");
  const properties = source("ucd/PropList.txt");

  const pool = new Map();
  const poolIndex = (value) => {
    if (!pool.has(value)) pool.set(value, pool.size);
    return pool.get(value);
  };

  // Ranges with string, multi-string ("+"), boolean, or integer values.
  const ranges = (entries, encodeValue) => entries.flatMap(({ start, end, value }) => [start, end, encodeValue(value)]);
  const boolRanges = (entries) => entries.flatMap(({ start, end }) => [start, end, 1]);
  // Code-point keyed maps with string or integer values.
  const pairs = (entries, encodeValue) => entries.flatMap(({ key, value }) => [key, encodeValue(value)]);
  const triples = (entries) => entries.flatMap(({ first, second, value }) => [first, second, value]);

  const sections = new Map();
  sections.set("identifierAllowed", ranges(parseAssignments(source("security/IdentifierStatus.txt")), poolIndex));
  sections.set("identifierTypes", ranges(identifierTypes, (value) => poolIndex(value.join("+"))));
  sections.set("confusables", pairs(parseConfusables(source("security/confusables.txt")), poolIndex));
  sections.set("defaultIgnorable", boolRanges(parsePropertyRanges(derivedCoreProperties, "Default_Ignorable_Code_Point")));
  sections.set("cased", boolRanges(parsePropertyRanges(derivedCoreProperties, "Cased")));
  sections.set("caseIgnorable", boolRanges(parsePropertyRanges(derivedCoreProperties, "Case_Ignorable")));
  sections.set("graphemeBreaks", ranges(
    parseAssignments(source("ucd/auxiliary/GraphemeBreakProperty.txt")),
    poolIndex
  ));
  sections.set("extendedPictographic", boolRanges(
    parsePropertyRanges(source("ucd/emoji/emoji-data.txt"), "Extended_Pictographic")
  ));
  sections.set("indicConjunctBreak", ranges(
    parseQualifiedAssignments(derivedCoreProperties, "InCB"),
    poolIndex
  ));
  sections.set("xidStart", boolRanges(parsePropertyRanges(derivedCoreProperties, "XID_Start")));
  sections.set("xidContinue", boolRanges(parsePropertyRanges(derivedCoreProperties, "XID_Continue")));
  sections.set("bidiControl", boolRanges(parsePropertyRanges(properties, "Bidi_Control")));
  sections.set("formatCharacter", boolRanges(parsePropertyRanges(categories, "Cf")));
  sections.set("scripts", ranges(scripts, poolIndex));
  sections.set(
    "recommendedScripts",
    scriptsWithIdentifierType(scripts, identifierTypes, "Recommended").map((script) => poolIndex(script))
  );
  sections.set("scriptExtensions", ranges(parseAssignments(source("ucd/ScriptExtensions.txt"), (value) => value.split(/\s+/u).map(canonicalScript)), (value) => poolIndex(value.join("+"))));
  sections.set("bidiClasses", ranges(parseAssignments(bidiText, canonicalBidi), poolIndex));
  sections.set("bidiMissing", ranges(parseMissingAssignments(bidiText, bidiAliases), poolIndex));
  sections.set("bidiMirroring", pairs(parseBidiMirroring(source("ucd/BidiMirroring.txt")), (value) => value));
  sections.set("nfkcCasefoldMappings", ranges(parseNfkcCasefold(source("ucd/DerivedNormalizationProps.txt")), poolIndex));
  sections.set("combiningClasses", ranges(unicodeData.combiningClasses, (value) => value));
  sections.set("canonicalDecompositions", pairs(normalizationData.canonicalDecompositions, poolIndex));
  sections.set("compatibilityDecompositions", pairs(normalizationData.compatibilityDecompositions, poolIndex));
  sections.set("compositionMappings", triples(normalizationData.compositionMappings));
  sections.set("decimalValues", ranges(unicodeData.decimalValues, (value) => value));
  sections.set("widthMappings", pairs(unicodeData.widthMappings, poolIndex));
  sections.set("lowercaseMappings", pairs(
    parseDefaultLowercaseMappings(unicodeData, source("ucd/SpecialCasing.txt")),
    poolIndex
  ));
  sections.set("joinControl", boolRanges(parsePropertyRanges(properties, "Join_Control")));
  sections.set("noncharacter", boolRanges(parsePropertyRanges(properties, "Noncharacter_Code_Point")));
  sections.set("unassigned", boolRanges(parsePropertyRanges(categories, "Cn")));
  sections.set("generalCategories", ranges(parseAssignments(categories), poolIndex));
  sections.set("joiningTypes", ranges(parseAssignments(source("ucd/extracted/DerivedJoiningType.txt")), poolIndex));
  sections.set("oldHangulJamo", boolRanges(parseAssignments(source("ucd/HangulSyllableType.txt"))
    .filter((entry) => ["L", "V", "T"].includes(entry.value))
    .map(({ start, end }) => ({ start, end, value: true }))));

  const poolStrings = [...pool.keys()];
  const stringOffsets = [0];
  let stringBytesLength = 0;
  for (const value of poolStrings) {
    stringBytesLength += Buffer.byteLength(value, "utf8");
    stringOffsets.push(stringBytesLength);
  }
  const stringBytes = Buffer.alloc(stringBytesLength);
  let writeOffset = 0;
  for (const value of poolStrings) {
    stringBytes.write(value, writeOffset, "utf8");
    writeOffset += Buffer.byteLength(value, "utf8");
  }

  const stringRegionUnits = poolStrings.length + 1 + Math.ceil(stringBytes.length / 4);
  const sectionDescriptors = {};
  let unitCursor = stringRegionUnits;
  for (const name of SECTION_ORDER) {
    const units = sections.get(name);
    const entryUnits = SECTION_ENTRY_UNITS[name] ?? 3;
    sectionDescriptors[name] = { unitOffset: unitCursor, count: Math.floor(units.length / entryUnits) };
    unitCursor += units.length;
  }

  const header = {
    format: FORMAT_VERSION,
    unicodeVersion: manifest.unicodeVersion,
    uts39Revision: manifest.uts39Revision,
    sourceRoot: manifest.sourceRoot,
    sourceManifestSha256: UNICODE_SECURITY_MANIFEST_SHA256,
    license: "Unicode License V3",
    stringCount: poolStrings.length,
    sections: sectionDescriptors
  };
  const headerJson = Buffer.from(JSON.stringify(header), "utf8");
  const headerPadding = (4 - ((8 + headerJson.length) % 4)) % 4;
  const paddedHeaderLength = headerJson.length + headerPadding;

  const totalBytes = 8 + paddedHeaderLength + unitCursor * 4;
  const blob = Buffer.alloc(totalBytes);
  blob.writeUInt32LE(MAGIC, 0);
  blob.writeUInt32LE(paddedHeaderLength, 4);
  headerJson.copy(blob, 8);
  for (let index = 0; index < headerPadding; index += 1) blob[8 + headerJson.length + index] = 0x20;

  let cursor = 8 + paddedHeaderLength;
  for (const offset of stringOffsets) {
    blob.writeUInt32LE(offset, cursor);
    cursor += 4;
  }
  stringBytes.copy(blob, cursor);
  cursor += stringBytes.length;
  cursor += (4 - (stringBytes.length % 4)) % 4;
  for (const name of SECTION_ORDER) {
    for (const value of sections.get(name)) {
      blob.writeUInt32LE(value, cursor);
      cursor += 4;
    }
  }
  if (cursor !== totalBytes) throw new Error(`serialization size mismatch: ${cursor} !== ${totalBytes}`);
  return { blob, header };
}

function compactManifestFor(blob) {
  return {
    formatVersion: FORMAT_VERSION,
    unicodeVersion: EXPECTED_UNICODE_VERSION,
    uts39Revision: EXPECTED_UTS39_REVISION,
    sourceManifestSha256: UNICODE_SECURITY_MANIFEST_SHA256,
    files: [
      { path: "data.bin", bytes: blob.length, sha256: sha256(blob) }
    ],
    generator: "scripts/build-unicode-data.mjs"
  };
}

const { blob } = buildBlob();
const manifestJson = `${JSON.stringify(compactManifestFor(blob), null, 2)}\n`;

if (CHECK_ONLY) {
  const committedBlob = readFileSync(COMPACT_DATA_PATH);
  const committedManifest = readFileSync(COMPACT_MANIFEST_PATH, "utf8");
  if (Buffer.compare(committedBlob, blob) !== 0) {
    process.stderr.write("compact data check failed: committed data.bin does not reproduce from vendor sources\n");
    process.exit(1);
  }
  if (committedManifest !== manifestJson) {
    process.stderr.write("compact data check failed: committed compact MANIFEST.json is stale\n");
    process.exit(1);
  }
  process.stdout.write(`compact data check passed: data.bin reproduces byte-for-byte (${blob.length} bytes)\n`);
} else {
  mkdirSync(COMPACT_DIR, { recursive: true });
  writeFileSync(COMPACT_DATA_PATH, blob);
  writeFileSync(COMPACT_MANIFEST_PATH, manifestJson);
  process.stdout.write(`wrote vendor/unicode/17.0.0/compact/data.bin (${blob.length} bytes)\n`);
  process.stdout.write(`compact manifest sha256: ${sha256(Buffer.from(manifestJson, "utf8"))}\n`);
}
