// Generate the independent Rust verifier's Unicode 17 PRECIS tables directly
// from the pinned UCD sources. The Node runtime consumes the separately
// compacted data.bin image; keeping this source-only route avoids sharing its
// runtime tables with the differential implementation.

import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const DATA_ROOT = new URL("../vendor/unicode/17.0.0/", import.meta.url);
const MANIFEST_PATH = new URL("MANIFEST.json", DATA_ROOT);
const OUTPUT_PATH = new URL("../native/src/precis_data.rs", import.meta.url);
const SOURCE_PATHS = Object.freeze({
  derivedCore: "ucd/DerivedCoreProperties.txt",
  propList: "ucd/PropList.txt",
  generalCategory: "ucd/extracted/DerivedGeneralCategory.txt",
  unicodeData: "ucd/UnicodeData.txt",
  specialCasing: "ucd/SpecialCasing.txt",
  joiningType: "ucd/extracted/DerivedJoiningType.txt",
  hangulSyllableType: "ucd/HangulSyllableType.txt"
});
const mode = process.argv[2] ?? "--check";

if (!new Set(["--check", "--write"]).has(mode)) {
  process.stderr.write("usage: node scripts/build-native-precis-data.mjs [--check|--write]\n");
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
  if (!Number.isInteger(start) || !Number.isInteger(end)
    || start < 0 || end < start || end > 0x10ffff) {
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

function rustString(value) {
  return [...value].map((character) => `\\u{${character.codePointAt(0).toString(16)}}`).join("");
}

const manifestBytes = readFileSync(MANIFEST_PATH);
const manifest = JSON.parse(manifestBytes.toString("utf8"));
if (manifest.unicodeVersion !== "17.0.0") {
  throw new Error(`expected Unicode 17.0.0, received ${manifest.unicodeVersion}`);
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

const categoryCodes = new Map([
  "Cc", "Cf", "Cn", "Co", "Cs", "Ll", "Lm", "Lo", "Lt", "Lu",
  "Mc", "Me", "Mn", "Nd", "Nl", "No", "Pc", "Pd", "Pe", "Pf",
  "Pi", "Po", "Ps", "Sc", "Sk", "Sm", "So", "Zl", "Zp", "Zs"
].map((value, index) => [value, index]));
const generalCategories = assignments(sources.generalCategory.bytes, (value) => {
  const code = categoryCodes.get(value);
  if (code === undefined) throw new Error(`unknown General_Category value: ${value}`);
  return code;
});
const joiningTypeCodes = new Map(["C", "D", "L", "R", "T"].map((value, index) => [value, index]));
const joiningTypes = assignments(sources.joiningType.bytes, (value) => {
  const code = joiningTypeCodes.get(value);
  if (code === undefined) throw new Error(`unknown Joining_Type value: ${value}`);
  return code;
});
const defaultIgnorable = propertyRanges(sources.derivedCore.bytes, "Default_Ignorable_Code_Point");
const cased = propertyRanges(sources.derivedCore.bytes, "Cased");
const caseIgnorable = propertyRanges(sources.derivedCore.bytes, "Case_Ignorable");
const joinControl = propertyRanges(sources.propList.bytes, "Join_Control");
const noncharacter = propertyRanges(sources.propList.bytes, "Noncharacter_Code_Point");
const unassigned = assignments(sources.generalCategory.bytes)
  .filter((entry) => entry.value === "Cn")
  .map(({ start, end }) => ({ start, end }));
const oldHangulJamo = assignments(sources.hangulSyllableType.bytes)
  .filter((entry) => ["L", "V", "T"].includes(entry.value))
  .map(({ start, end }) => ({ start, end }));

const widthMappings = [];
const lowercaseMappings = new Map();
for (const line of sources.unicodeData.bytes.toString("utf8").split(/\r?\n/u)) {
  if (line === "") continue;
  const fields = line.split(";");
  if (fields.length < 15) throw new Error("malformed UnicodeData row");
  const codePoint = Number.parseInt(fields[0], 16);
  if (fields[13] !== "") {
    lowercaseMappings.set(codePoint, String.fromCodePoint(Number.parseInt(fields[13], 16)));
  }
  const match = fields[5].match(/^<(?:wide|narrow)>\s+(.+)$/u);
  if (match) {
    widthMappings.push({
      key: codePoint,
      value: match[1].split(/\s+/u).map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("")
    });
  }
}
for (const fields of rows(sources.specialCasing.bytes.toString("utf8"))) {
  if (fields.length < 5) throw new Error("malformed SpecialCasing row");
  if (fields[4] !== "") continue;
  lowercaseMappings.set(
    Number.parseInt(fields[0], 16),
    fields[1].split(/\s+/u).filter(Boolean)
      .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("")
  );
}
const lowercase = [...lowercaseMappings.entries()]
  .filter(([codePoint, value]) => value !== String.fromCodePoint(codePoint))
  .map(([key, value]) => ({ key, value }))
  .sort((left, right) => left.key - right.key);
widthMappings.sort((left, right) => left.key - right.key);

for (const [name, ranges] of Object.entries({
  generalCategories,
  joiningTypes,
  defaultIgnorable,
  cased,
  caseIgnorable,
  joinControl,
  noncharacter,
  unassigned,
  oldHangulJamo
})) assertRanges(name, ranges);

const sourceConstants = Object.entries(SOURCE_PATHS).flatMap(([name, relativePath]) => {
  const prefix = name.replace(/([a-z])([A-Z])/gu, "$1_$2").toUpperCase();
  return [
    `pub const ${prefix}_SOURCE_PATH: &str = ${JSON.stringify(relativePath)};`,
    `pub const ${prefix}_SOURCE_SHA256: &str =`,
    `    ${JSON.stringify(sources[name].entry.sha256)};`
  ];
});
const boolRanges = (name, ranges) => [
  `pub const ${name}_COUNT: usize = ${ranges.length};`,
  "#[rustfmt::skip]",
  `pub const ${name}: &[(u32, u32)] = &[`,
  ...ranges.map(({ start, end }) => `    (0x${start.toString(16)}, 0x${end.toString(16)}),`),
  "];"
];
const u8Ranges = (name, ranges) => [
  `pub const ${name}_COUNT: usize = ${ranges.length};`,
  "#[rustfmt::skip]",
  `pub const ${name}: &[(u32, u32, u8)] = &[`,
  ...ranges.map(({ start, end, value }) =>
    `    (0x${start.toString(16)}, 0x${end.toString(16)}, ${value}),`),
  "];"
];
const stringMappings = (name, mappings) => [
  `pub const ${name}_COUNT: usize = ${mappings.length};`,
  "#[rustfmt::skip]",
  `pub const ${name}: &[(u32, &str)] = &[`,
  ...mappings.map(({ key, value }) =>
    `    (0x${key.toString(16)}, "${rustString(value)}"),`),
  "];"
];

const lines = [
  "// @generated by scripts/build-native-precis-data.mjs; do not edit by hand.",
  "#![allow(dead_code)]",
  `pub const UNICODE_VERSION: &str = ${JSON.stringify(manifest.unicodeVersion)};`,
  "pub const SOURCE_MANIFEST_SHA256: &str =",
  `    ${JSON.stringify(sha256(manifestBytes))};`,
  ...sourceConstants,
  "#[rustfmt::skip]",
  `pub const GENERAL_CATEGORY_NAMES: &[&str] = &[${[...categoryCodes.keys()].map(JSON.stringify).join(", ")}];`,
  "#[rustfmt::skip]",
  `pub const JOINING_TYPE_NAMES: &[&str] = &[${[...joiningTypeCodes.keys()].map(JSON.stringify).join(", ")}];`,
  ...u8Ranges("GENERAL_CATEGORY_RANGES", generalCategories),
  ...u8Ranges("JOINING_TYPE_RANGES", joiningTypes),
  ...boolRanges("DEFAULT_IGNORABLE_RANGES", defaultIgnorable),
  ...boolRanges("CASED_RANGES", cased),
  ...boolRanges("CASE_IGNORABLE_RANGES", caseIgnorable),
  ...boolRanges("JOIN_CONTROL_RANGES", joinControl),
  ...boolRanges("NONCHARACTER_RANGES", noncharacter),
  ...boolRanges("UNASSIGNED_RANGES", unassigned),
  ...boolRanges("OLD_HANGUL_JAMO_RANGES", oldHangulJamo),
  ...stringMappings("WIDTH_MAPPINGS", widthMappings),
  ...stringMappings("LOWERCASE_MAPPINGS", lowercase),
  ""
];
const rendered = Buffer.from(lines.join("\n"));

if (mode === "--write") {
  writeFileSync(OUTPUT_PATH, rendered);
  process.stdout.write(
    `native PRECIS tables updated (${generalCategories.length} category ranges, ${joiningTypes.length} joining ranges, ${widthMappings.length} width mappings, ${lowercase.length} lowercase mappings)\n`
  );
} else {
  let committed;
  try {
    committed = readFileSync(OUTPUT_PATH);
  } catch {
    process.stderr.write("native PRECIS tables are missing; run with --write\n");
    process.exit(1);
  }
  if (!committed.equals(rendered)) {
    process.stderr.write("native PRECIS tables do not reproduce from the pinned Unicode sources\n");
    process.exit(1);
  }
  process.stdout.write(
    `native PRECIS tables match (${generalCategories.length} category ranges, ${joiningTypes.length} joining ranges, ${widthMappings.length} width mappings, ${lowercase.length} lowercase mappings)\n`
  );
}
