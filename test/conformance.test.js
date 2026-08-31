import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { gunzipSync } from "node:zlib";
import { readFileSync } from "node:fs";
import tr46 from "tr46";
import { bidiConformanceEngine } from "../src/core/bidi.js";

const ROOT = new URL("../", import.meta.url);
const DATA_ROOT = new URL("../vendor/unicode/17.0.0/", import.meta.url);
const manifestBytes = readFileSync(new URL("CONFORMANCE_MANIFEST.json", DATA_ROOT));
const manifest = JSON.parse(manifestBytes);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function corpus(name) {
  const entry = manifest.files.find((item) => item.path.endsWith(`/${name}.txt.gz`));
  assert.ok(entry, `missing ${name}`);
  const compressed = readFileSync(new URL(entry.path, DATA_ROOT));
  assert.equal(compressed.length, entry.bytes);
  assert.equal(sha256(compressed), entry.sha256);
  const raw = gunzipSync(compressed);
  assert.equal(raw.length, entry.uncompressedBytes);
  assert.equal(sha256(raw), entry.uncompressedSha256);
  return raw.toString("utf8");
}

function fromHexList(value) {
  const trimmed = value.trim();
  return trimmed === "" ? "" : trimmed.split(/\s+/u).map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("");
}

test("all pinned conformance corpora match their immutable manifest", () => {
  assert.equal(manifest.unicodeVersion, "17.0.0");
  assert.equal(sha256(manifestBytes), "61c3f102afd997d929634ea5170e094a2d9808394113d6d749f8f448b1a5497d");
  for (const entry of manifest.files) corpus(entry.path.split("/").at(-1).replace(".txt.gz", ""));
});

test("runtime normalization passes every Unicode 17 NormalizationTest case", () => {
  let count = 0;
  for (const sourceLine of corpus("NormalizationTest").split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "" || line.startsWith("@")) continue;
    const [c1, c2, c3, c4, c5] = line.split(";").slice(0, 5).map(fromHexList);
    for (const value of [c1, c2, c3]) {
      assert.equal(value.normalize("NFC"), c2);
      assert.equal(value.normalize("NFD"), c3);
    }
    assert.equal(c4.normalize("NFC"), c4);
    assert.equal(c5.normalize("NFC"), c4);
    assert.equal(c4.normalize("NFD"), c5);
    assert.equal(c5.normalize("NFD"), c5);
    for (const value of [c1, c2, c3, c4, c5]) {
      assert.equal(value.normalize("NFKC"), c4);
      assert.equal(value.normalize("NFKD"), c5);
    }
    count += 1;
  }
  assert.equal(count > 19000, true);
});

test("runtime grapheme segmentation passes every Unicode 17 GraphemeBreakTest case", () => {
  const segmenter = new Intl.Segmenter("und", { granularity: "grapheme" });
  let count = 0;
  for (const sourceLine of corpus("GraphemeBreakTest").split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "") continue;
    const tokens = line.split(/\s+/u);
    const expected = [];
    let current = "";
    for (const token of tokens) {
      if (token === "÷") {
        if (current !== "") expected.push(current);
        current = "";
      } else if (token !== "×") {
        current += String.fromCodePoint(Number.parseInt(token, 16));
      }
    }
    if (current !== "") expected.push(current);
    const text = expected.join("");
    assert.deepEqual([...segmenter.segment(text)].map((item) => item.segment), expected);
    count += 1;
  }
  assert.equal(count > 700, true);
});

function decodeIdna(value, fallback) {
  const trimmed = value.trim();
  if (trimmed === "") return fallback;
  if (trimmed === '""') return "";
  return trimmed
    .replace(/\\u([0-9A-Fa-f]{4})/gu, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x\{([0-9A-Fa-f]+)\}/gu, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)));
}

function statuses(value, fallback) {
  const trimmed = value.trim();
  if (trimmed === "") return fallback;
  if (trimmed === "[]") return [];
  return trimmed.slice(1, -1).split(",").map((item) => item.trim());
}

function hasEnabledError(values, { verifyDNSLength }) {
  return values.some((status) => status !== "U1" && (verifyDNSLength || !status.startsWith("A4_")));
}

test("tr46@6 passes every well-formed Unicode 17 IdnaTestV2 case with enabled checks", () => {
  let count = 0;
  for (const sourceLine of corpus("IdnaTestV2").split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "") continue;
    const fields = line.split(";");
    const source = decodeIdna(fields[0], "");
    if (!source.isWellFormed()) continue;
    const unicode = decodeIdna(fields[1], source);
    const unicodeStatuses = statuses(fields[2], []);
    const asciiN = decodeIdna(fields[3], unicode);
    const asciiNStatuses = statuses(fields[4], unicodeStatuses);
    const asciiT = decodeIdna(fields[5], asciiN);
    const asciiTStatuses = statuses(fields[6], asciiNStatuses);
    const common = {
      checkBidi: true, checkHyphens: true, checkJoiners: true,
      ignoreInvalidPunycode: false, useSTD3ASCIIRules: false
    };
    const actualUnicode = tr46.toUnicode(source, { ...common, transitionalProcessing: false });
    assert.equal(actualUnicode.domain, unicode);
    const supplementalX42 = actualUnicode.domain === ""
      || actualUnicode.domain.split(".").slice(0, -1).some((label) => label === "");
    assert.equal(actualUnicode.error || supplementalX42, hasEnabledError(unicodeStatuses, { verifyDNSLength: false }));
    const actualN = tr46.toASCII(source, { ...common, transitionalProcessing: false, verifyDNSLength: true });
    assert.equal(actualN, hasEnabledError(asciiNStatuses, { verifyDNSLength: true }) ? null : asciiN);
    const actualT = tr46.toASCII(source, { ...common, transitionalProcessing: true, verifyDNSLength: true });
    assert.equal(actualT, hasEnabledError(asciiTStatuses, { verifyDNSLength: true }) ? null : asciiT);
    count += 1;
  }
  assert.equal(count > 6000, true);
});

const TYPE_CHARACTER = Object.freeze({
  L: "A", R: "א", EN: "0", ES: "+", ET: "#", AN: "٠", CS: ",", B: "\u2029", S: "\t", WS: " ",
  ON: "!", BN: "\u00AD", NSM: "\u036F", AL: "ە", LRO: "\u202D", RLO: "\u202E", LRE: "\u202A",
  RLE: "\u202B", PDF: "\u202C", LRI: "\u2066", RLI: "\u2067", FSI: "\u2068", PDI: "\u2069"
});

function bidiCheck(engine, text, direction, expectedParagraph, expectedLevels, expectedOrder) {
  const result = engine.getEmbeddingLevels(text, direction);
  assert.equal(result.paragraphs[0]?.level ?? 0, expectedParagraph);
  for (const [index, level] of expectedLevels.entries()) {
    if (level !== "x") assert.equal(result.levels[index], level);
  }
  const actualOrder = engine.getReorderedIndices(text, result).filter((index) => expectedLevels[index] !== "x");
  assert.deepEqual(actualOrder, expectedOrder);
}

test("vendored Unicode 17 UBA passes every BidiTest and BidiCharacterTest case", { timeout: 180000 }, () => {
  const engine = bidiConformanceEngine();
  let levels = [];
  let order = [];
  let count = 0;
  for (const sourceLine of corpus("BidiTest").split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "") continue;
    if (line.startsWith("@Levels:")) {
      levels = line.slice(8).trim().split(/\s+/u).filter(Boolean).map((item) => item === "x" ? "x" : Number(item));
      continue;
    }
    if (line.startsWith("@Reorder:")) {
      order = line.slice(9).trim().split(/\s+/u).filter(Boolean).map(Number);
      continue;
    }
    const [typesValue, modesValue] = line.split(";").map((item) => item.trim());
    const text = typesValue.split(/\s+/u).map((type) => TYPE_CHARACTER[type]).join("");
    const modes = Number(modesValue);
    for (const [bit, direction, paragraph] of [[1, "auto", null], [2, "ltr", 0], [4, "rtl", 1]]) {
      if ((modes & bit) === 0) continue;
      const expectedParagraph = paragraph ?? engine.getEmbeddingLevels(text, "auto").paragraphs[0]?.level ?? 0;
      bidiCheck(engine, text, direction, expectedParagraph, levels, order);
      count += 1;
    }
  }
  assert.equal(count, 770241);

  let characterCount = 0;
  for (const sourceLine of corpus("BidiCharacterTest").split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "") continue;
    const [characters, paragraphMode, paragraphLevel, levelValue, orderValue] = line.split(";").map((item) => item.trim());
    const text = fromHexList(characters);
    const expectedLevels = levelValue.split(/\s+/u).map((item) => item === "x" ? "x" : Number(item));
    const expectedOrder = orderValue === "" ? [] : orderValue.split(/\s+/u).map(Number);
    bidiCheck(engine, text, ["ltr", "rtl", "auto"][Number(paragraphMode)], Number(paragraphLevel), expectedLevels, expectedOrder);
    characterCount += 1;
  }
  assert.equal(characterCount, 91707);
});
