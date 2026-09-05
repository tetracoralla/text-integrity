// Generate the Rust verifier's remaining Unicode 17 security-observation
// tables directly from the pinned source bundle.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const MANIFEST_PATH = new URL("../vendor/unicode/17.0.0/MANIFEST.json", import.meta.url);
const DATA_ROOT = new URL("../vendor/unicode/17.0.0/", import.meta.url);
const OUTPUT_PATH = new URL("../native/src/security_data.rs", import.meta.url);
const SOURCE_PATHS = Object.freeze({
  identifierStatus: "security/IdentifierStatus.txt",
  identifierType: "security/IdentifierType.txt",
  derivedCore: "ucd/DerivedCoreProperties.txt",
  propList: "ucd/PropList.txt",
  generalCategory: "ucd/extracted/DerivedGeneralCategory.txt",
  unicodeData: "ucd/UnicodeData.txt",
  scripts: "ucd/Scripts.txt",
  propertyValueAliases: "ucd/PropertyValueAliases.txt"
});
const mode = process.argv[2] ?? "--check";

if (!new Set(["--check", "--write"]).has(mode)) {
  process.stderr.write("usage: node scripts/build-native-security-data.mjs [--check|--write]\n");
  process.exit(2);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function rows(text) {
  return text.split(/\r?\n/u).flatMap((sourceLine) => {
    const content = sourceLine.split("#", 1)[0].trim();
    return content === "" ? [] : [content.split(";").map((field) => field.trim())];
  });
}

function parseRange(value) {
  const [first, last = first] = value.split("..");
  const start = Number.parseInt(first, 16);
  const end = Number.parseInt(last, 16);
  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start || end > 0x10ffff) {
    throw new Error(`invalid code-point range: ${value}`);
  }
  return { start, end };
}

function assignments(bytes, transform = (value) => value) {
  return rows(bytes.toString("utf8")).map((fields) => ({
    ...parseRange(fields[0]),
    value: transform(fields[1])
  })).sort((left, right) => left.start - right.start || left.end - right.end);
}

function propertyRanges(bytes, property) {
  return assignments(bytes)
    .filter((entry) => entry.value === property)
    .map(({ start, end }) => ({ start, end }));
}

function assertRanges(name, ranges) {
  for (let index = 1; index < ranges.length; index += 1) {
    if (ranges[index - 1].end >= ranges[index].start) {
      throw new Error(`${name} ranges overlap or are unsorted`);
    }
  }
}

const manifestBytes = readFileSync(MANIFEST_PATH);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
if (manifest.unicodeVersion !== "17.0.0" || manifest.uts39Revision !== 32) {
  throw new Error("expected Unicode 17.0.0 and UTS #39 revision 32");
}

const sources = {};
for (const [name, relativePath] of Object.entries(SOURCE_PATHS)) {
  const bytes = readFileSync(new URL(relativePath, DATA_ROOT));
  const entry = manifest.files.find((item) => item.path === relativePath);
  if (!entry || entry.bytes !== bytes.length || entry.sha256 !== sha256(bytes)) {
    throw new Error(`${relativePath} does not match the pinned Unicode manifest`);
  }
  sources[name] = { bytes, entry };
}

const identifierAllowed = assignments(sources.identifierStatus.bytes)
  .filter((entry) => entry.value === "Allowed");
const identifierTypes = assignments(
  sources.identifierType.bytes,
  (value) => value.split(/\s+/u).filter(Boolean).join("+")
);
const scriptAliases = new Map();
for (const fields of rows(sources.propertyValueAliases.bytes.toString("utf8"))) {
  if (fields[0] !== "sc") continue;
  const canonical = fields[1];
  for (const alias of fields.slice(1).filter(Boolean)) scriptAliases.set(alias, canonical);
}
const scripts = assignments(sources.scripts.bytes, (value) => {
  const canonical = scriptAliases.get(value);
  if (!canonical) throw new Error(`unknown Script alias: ${value}`);
  return canonical;
});
const recommendedScripts = new Set();
let identifierTypeIndex = 0;
for (const script of scripts) {
  while (identifierTypeIndex < identifierTypes.length
    && identifierTypes[identifierTypeIndex].end < script.start) identifierTypeIndex += 1;
  for (let index = identifierTypeIndex;
    index < identifierTypes.length && identifierTypes[index].start <= script.end;
    index += 1) {
    if (identifierTypes[index].value.split("+").includes("Recommended")) {
      recommendedScripts.add(script.value);
    }
  }
}
const defaultIgnorable = propertyRanges(sources.derivedCore.bytes, "Default_Ignorable_Code_Point");
const xidStart = propertyRanges(sources.derivedCore.bytes, "XID_Start");
const xidContinue = propertyRanges(sources.derivedCore.bytes, "XID_Continue");
const bidiControl = propertyRanges(sources.propList.bytes, "Bidi_Control");
const formatCharacter = propertyRanges(sources.generalCategory.bytes, "Cf");
const decimalValues = [];
for (const line of sources.unicodeData.bytes.toString("utf8").split(/\r?\n/u)) {
  if (line === "") continue;
  const fields = line.split(";");
  if (fields.length < 15) throw new Error("malformed UnicodeData row");
  if (fields[6] !== "") {
    const codePoint = Number.parseInt(fields[0], 16);
    decimalValues.push({ start: codePoint, end: codePoint, value: Number.parseInt(fields[6], 10) });
  }
}

for (const [name, ranges] of Object.entries({
  identifierAllowed,
  identifierTypes,
  defaultIgnorable,
  xidStart,
  xidContinue,
  bidiControl,
  formatCharacter,
  decimalValues
})) assertRanges(name, ranges);

const sourceConstants = Object.entries(SOURCE_PATHS).flatMap(([name, relativePath]) => {
  const prefix = name.replace(/([a-z])([A-Z])/gu, "$1_$2").toUpperCase();
  return [
    `pub const ${prefix}_SOURCE_PATH: &str = ${JSON.stringify(relativePath)};`,
    `pub const ${prefix}_SOURCE_SHA256: &str =`,
    `    ${JSON.stringify(sources[name].entry.sha256)};`
  ];
});
const stringRanges = (name, ranges) => [
  `pub const ${name}_COUNT: usize = ${ranges.length};`,
  "#[rustfmt::skip]",
  `pub const ${name}: &[(u32, u32, &str)] = &[`,
  ...ranges.map(({ start, end, value }) =>
    `    (0x${start.toString(16)}, 0x${end.toString(16)}, ${JSON.stringify(value)}),`),
  "];"
];
const boolRanges = (name, ranges) => [
  `pub const ${name}_COUNT: usize = ${ranges.length};`,
  "#[rustfmt::skip]",
  `pub const ${name}: &[(u32, u32)] = &[`,
  ...ranges.map(({ start, end }) => `    (0x${start.toString(16)}, 0x${end.toString(16)}),`),
  "];"
];

const lines = [
  "// @generated by scripts/build-native-security-data.mjs; do not edit by hand.",
  "#![allow(dead_code)]",
  `pub const UNICODE_VERSION: &str = ${JSON.stringify(manifest.unicodeVersion)};`,
  "pub const UTS39_REVISION: u32 = 32;",
  `pub const SOURCE_ROOT: &str = ${JSON.stringify(manifest.sourceRoot)};`,
  "pub const SOURCE_MANIFEST_SHA256: &str =",
  `    ${JSON.stringify(sha256(manifestBytes))};`,
  ...sourceConstants,
  ...stringRanges("IDENTIFIER_ALLOWED_RANGES", identifierAllowed),
  ...stringRanges("IDENTIFIER_TYPE_RANGES", identifierTypes),
  `pub const RECOMMENDED_SCRIPT_COUNT: usize = ${recommendedScripts.size};`,
  "#[rustfmt::skip]",
  "pub const RECOMMENDED_SCRIPTS: &[&str] = &[",
  ...[...recommendedScripts].map((value) => `    ${JSON.stringify(value)},`),
  "];",
  ...boolRanges("DEFAULT_IGNORABLE_RANGES", defaultIgnorable),
  ...boolRanges("XID_START_RANGES", xidStart),
  ...boolRanges("XID_CONTINUE_RANGES", xidContinue),
  ...boolRanges("BIDI_CONTROL_RANGES", bidiControl),
  ...boolRanges("FORMAT_CHARACTER_RANGES", formatCharacter),
  `pub const DECIMAL_VALUE_RANGE_COUNT: usize = ${decimalValues.length};`,
  "#[rustfmt::skip]",
  "pub const DECIMAL_VALUE_RANGES: &[(u32, u32, u8)] = &[",
  ...decimalValues.map(({ start, end, value }) =>
    `    (0x${start.toString(16)}, 0x${end.toString(16)}, ${value}),`),
  "];",
  ""
];
const rendered = Buffer.from(lines.join("\n"));

if (mode === "--write") {
  writeFileSync(OUTPUT_PATH, rendered);
  process.stdout.write(
    `native security tables updated (${identifierAllowed.length} allowed, ${identifierTypes.length} type, ${recommendedScripts.size} recommended scripts, ${decimalValues.length} decimal ranges)\n`
  );
} else {
  let committed;
  try {
    committed = readFileSync(OUTPUT_PATH);
  } catch {
    process.stderr.write("native security tables are missing; run with --write\n");
    process.exit(1);
  }
  if (!committed.equals(rendered)) {
    process.stderr.write("native security tables do not reproduce from the pinned Unicode sources\n");
    process.exit(1);
  }
  process.stdout.write(
    `native security tables match (${identifierAllowed.length} allowed, ${identifierTypes.length} type, ${recommendedScripts.size} recommended scripts, ${decimalValues.length} decimal ranges)\n`
  );
}
