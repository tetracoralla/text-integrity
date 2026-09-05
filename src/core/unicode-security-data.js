import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { TextIntegrityError } from "./errors.js";
import { assertPinnedUnicodeRuntime } from "./runtime.js";

const DATA_ROOT = new URL("../../vendor/unicode/17.0.0/", import.meta.url);
const COMPACT_MANIFEST_URL = new URL("compact/MANIFEST.json", DATA_ROOT);
const COMPACT_DATA_URL = new URL("compact/data.bin", DATA_ROOT);
const EXPECTED_MANIFEST_SHA256 = "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf";
const EXPECTED_COMPACT_MANIFEST_SHA256 = "3c8a54c3d74be6b11ac6458c882d86d0564da031640f90b6a6354fef0dd001c0";
const EXPECTED_UNICODE_VERSION = "17.0.0";
const EXPECTED_UTS39_REVISION = 32;
const COMPACT_FORMAT_VERSION = 4;
const COMPACT_MAGIC = 0x31495554;
const PAIR_SECTIONS = new Set([
  "bidiMirroring",
  "confusables",
  "widthMappings",
  "lowercaseMappings",
  "canonicalDecompositions",
  "compatibilityDecompositions"
]);
const LIST_SECTIONS = new Set(["recommendedScripts"]);

let cachedData;

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function dataError(message, details) {
  return new TextIntegrityError("UNICODE_DATA_INTEGRITY", message, details);
}

function rangeLookup(table, codePoint) {
  let low = 0;
  let high = table.count - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const base = middle * 3;
    if (codePoint < table.data[base]) high = middle - 1;
    else if (codePoint > table.data[base + 1]) low = middle + 1;
    else return table.data[base + 2];
  }
  return undefined;
}

function pairLookup(table, key) {
  let low = 0;
  let high = table.count - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const base = middle * 2;
    if (key < table.data[base]) high = middle - 1;
    else if (key > table.data[base]) low = middle + 1;
    else return table.data[base + 1];
  }
  return undefined;
}

function triplePairLookup(table, first, second) {
  let low = 0;
  let high = table.count - 1;
  while (low <= high) {
    const middle = (low + high) >> 1;
    const base = middle * 3;
    const currentFirst = table.data[base];
    const currentSecond = table.data[base + 1];
    if (first < currentFirst || (first === currentFirst && second < currentSecond)) high = middle - 1;
    else if (first > currentFirst || (first === currentFirst && second > currentSecond)) low = middle + 1;
    else return table.data[base + 2];
  }
  return undefined;
}

function mapInterface(lookup) {
  return {
    has(codePoint) {
      return lookup(codePoint) !== undefined;
    },
    get(codePoint) {
      return lookup(codePoint);
    }
  };
}

function readCompactBundle() {
  let manifestBytes;
  let blob;
  try {
    manifestBytes = readFileSync(COMPACT_MANIFEST_URL);
    blob = readFileSync(COMPACT_DATA_URL);
  } catch {
    throw dataError("The compact Unicode data bundle is unavailable.");
  }
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw dataError("The compact Unicode data manifest is not valid JSON.");
  }
  if (sha256(manifestBytes) !== EXPECTED_COMPACT_MANIFEST_SHA256) {
    throw dataError("The compact Unicode data manifest failed SHA-256 verification.", {
      expectedSha256: EXPECTED_COMPACT_MANIFEST_SHA256,
      actualSha256: sha256(manifestBytes)
    });
  }
  if (manifest.sourceManifestSha256 !== EXPECTED_MANIFEST_SHA256) {
    throw dataError("The compact Unicode data manifest does not chain to the pinned source manifest.");
  }
  const entry = manifest.files?.[0];
  if (entry?.path !== "data.bin" || entry.bytes !== blob.length || sha256(blob) !== entry.sha256) {
    throw dataError("The compact Unicode data blob failed size or SHA-256 verification.", {
      expectedBytes: entry?.bytes,
      actualBytes: blob.length,
      expectedSha256: entry?.sha256,
      actualSha256: sha256(blob)
    });
  }
  return { manifest, blob };
}

function parseCompactBlob(manifest, blob) {
  if (blob.byteOffset % 4 !== 0) blob = Buffer.from(blob);
  if (blob.length < 12 || blob.readUInt32LE(0) !== COMPACT_MAGIC) {
    throw dataError("The compact Unicode data blob has an unknown format.");
  }
  const headerLength = blob.readUInt32LE(4);
  let header;
  try {
    header = JSON.parse(blob.subarray(8, 8 + headerLength).toString("utf8"));
  } catch {
    throw dataError("The compact Unicode data blob header is not valid JSON.");
  }
  if (header.format !== COMPACT_FORMAT_VERSION
    || header.unicodeVersion !== EXPECTED_UNICODE_VERSION
    || header.uts39Revision !== EXPECTED_UTS39_REVISION
    || header.sourceManifestSha256 !== EXPECTED_MANIFEST_SHA256) {
    throw dataError("The compact Unicode data blob header has an unexpected version.");
  }

  const regionByteOffset = blob.byteOffset + 8 + headerLength;
  const region = new Uint32Array(blob.buffer, regionByteOffset, Math.floor((blob.length - 8 - headerLength) / 4));

  const { stringCount, sections } = header;
  const stringBytesStart = regionByteOffset + (stringCount + 1) * 4;
  const stringBytesEnd = stringBytesStart + region[stringCount];
  const stringBytes = blob.subarray(stringBytesStart, stringBytesEnd);
  const strings = new Array(stringCount);
  for (let index = 0; index < stringCount; index += 1) {
    strings[index] = stringBytes.subarray(region[index], region[index + 1]).toString("utf8");
  }

  const sectionView = (name) => {
    const descriptor = sections[name];
    if (!descriptor) throw dataError("A compact Unicode data section is absent.", { section: name });
    const entryUnits = LIST_SECTIONS.has(name) ? 1 : PAIR_SECTIONS.has(name) ? 2 : 3;
    const units = descriptor.count * entryUnits;
    return {
      data: region.subarray(descriptor.unitOffset, descriptor.unitOffset + units),
      count: descriptor.count
    };
  };

  const stringRange = (view) => {
    const table = { data: view.data, count: view.count };
    return { kind: "ranges", lookup: (codePoint) => { const ref = rangeLookup(table, codePoint); return ref === undefined ? undefined : strings[ref]; } };
  };
  const multiRange = (view) => {
    const table = { data: view.data, count: view.count };
    const cache = new Map();
    const decode = (ref) => {
      let value = cache.get(ref);
      if (value === undefined) {
        value = strings[ref].split("+");
        cache.set(ref, value);
      }
      return value;
    };
    return { kind: "ranges", lookup: (codePoint) => { const ref = rangeLookup(table, codePoint); return ref === undefined ? undefined : decode(ref); } };
  };
  const boolRange = (view) => {
    const table = { data: view.data, count: view.count };
    return { kind: "ranges", lookup: (codePoint) => rangeLookup(table, codePoint) === undefined ? undefined : true };
  };
  const intRange = (view) => {
    const table = { data: view.data, count: view.count };
    return { kind: "ranges", lookup: (codePoint) => rangeLookup(table, codePoint) };
  };
  const stringPair = (view) => {
    const table = { data: view.data, count: view.count };
    return { kind: "pairs", lookup: (key) => { const ref = pairLookup(table, key); return ref === undefined ? undefined : strings[ref]; } };
  };
  const intPair = (view) => {
    const table = { data: view.data, count: view.count };
    return { kind: "pairs", lookup: (key) => pairLookup(table, key) };
  };
  const stringRangeMap = (view) => {
    const table = { data: view.data, count: view.count };
    return { kind: "ranges", lookup: (codePoint) => { const ref = rangeLookup(table, codePoint); return ref === undefined ? undefined : strings[ref]; } };
  };
  const compositionMap = (view) => {
    const table = { data: view.data, count: view.count };
    return { get: (first, second) => triplePairLookup(table, first, second) };
  };

  const recommendedView = sectionView("recommendedScripts");
  const recommendedScripts = new Set();
  for (let index = 0; index < recommendedView.count; index += 1) recommendedScripts.add(strings[recommendedView.data[index]]);

  const bidiMissingView = sectionView("bidiMissing");
  const bidiMissing = [];
  for (let index = 0; index < bidiMissingView.count; index += 1) {
    const base = index * 3;
    bidiMissing.push({
      start: bidiMissingView.data[base],
      end: bidiMissingView.data[base + 1],
      value: strings[bidiMissingView.data[base + 2]]
    });
  }

  return {
    identity: Object.freeze({
      unicodeVersion: header.unicodeVersion,
      uts39Revision: header.uts39Revision,
      sourceManifestSha256: EXPECTED_MANIFEST_SHA256,
      compactFormatVersion: COMPACT_FORMAT_VERSION,
      compactManifestSha256: sha256(readFileSync(COMPACT_MANIFEST_URL)),
      compactDataSha256: manifest.files[0].sha256
    }),
    metadata: Object.freeze({
      unicodeVersion: header.unicodeVersion,
      uts39Revision: header.uts39Revision,
      sourceRoot: header.sourceRoot,
      license: header.license,
      manifestSha256: EXPECTED_MANIFEST_SHA256,
      offline: true
    }),
    identifierAllowed: stringRange(sectionView("identifierAllowed")),
    identifierTypes: multiRange(sectionView("identifierTypes")),
    confusables: mapInterface(stringPair(sectionView("confusables")).lookup),
    defaultIgnorable: boolRange(sectionView("defaultIgnorable")),
    cased: boolRange(sectionView("cased")),
    caseIgnorable: boolRange(sectionView("caseIgnorable")),
    graphemeBreaks: stringRange(sectionView("graphemeBreaks")),
    extendedPictographic: boolRange(sectionView("extendedPictographic")),
    indicConjunctBreak: stringRange(sectionView("indicConjunctBreak")),
    xidStart: boolRange(sectionView("xidStart")),
    xidContinue: boolRange(sectionView("xidContinue")),
    bidiControl: boolRange(sectionView("bidiControl")),
    formatCharacter: boolRange(sectionView("formatCharacter")),
    scripts: stringRange(sectionView("scripts")),
    recommendedScripts,
    scriptExtensions: multiRange(sectionView("scriptExtensions")),
    bidiClasses: stringRange(sectionView("bidiClasses")),
    bidiMissing,
    bidiMirroring: mapInterface(intPair(sectionView("bidiMirroring")).lookup),
    nfkcCasefoldMappings: mapInterface(stringRangeMap(sectionView("nfkcCasefoldMappings")).lookup),
    combiningClasses: intRange(sectionView("combiningClasses")),
    canonicalDecompositions: mapInterface(stringPair(sectionView("canonicalDecompositions")).lookup),
    compatibilityDecompositions: mapInterface(stringPair(sectionView("compatibilityDecompositions")).lookup),
    compositionMappings: compositionMap(sectionView("compositionMappings")),
    decimalValues: intRange(sectionView("decimalValues")),
    widthMappings: mapInterface(stringPair(sectionView("widthMappings")).lookup),
    lowercaseMappings: mapInterface(stringPair(sectionView("lowercaseMappings")).lookup),
    joinControl: boolRange(sectionView("joinControl")),
    noncharacter: boolRange(sectionView("noncharacter")),
    unassigned: boolRange(sectionView("unassigned")),
    generalCategories: stringRange(sectionView("generalCategories")),
    joiningTypes: stringRange(sectionView("joiningTypes")),
    oldHangulJamo: boolRange(sectionView("oldHangulJamo")),
    compactManifestSha256: sha256(readFileSync(COMPACT_MANIFEST_URL))
  };
}

function buildData() {
  const { manifest, blob } = readCompactBundle();
  const data = parseCompactBlob(manifest, blob);
  if (data.metadata.unicodeVersion !== manifest.unicodeVersion) {
    throw dataError("The compact bundle and its manifest disagree on the Unicode version.");
  }
  return data;
}

export function unicodeSecurityData() {
  assertPinnedUnicodeRuntime("Unicode 17 text profiles");
  cachedData ??= buildData();
  return cachedData;
}

export function unicodeProtocolData() {
  assertPinnedUnicodeRuntime("Unicode 17 protocol-string profiles");
  return unicodeSecurityData();
}

export function unicodeNormalizationData() {
  assertPinnedUnicodeRuntime("Unicode 17 normalization");
  cachedData ??= buildData();
  return cachedData;
}

export function unicodeDataIdentity() {
  assertPinnedUnicodeRuntime("Unicode 17 data identity");
  cachedData ??= buildData();
  return cachedData.identity;
}

export function dataLookup(table, codePoint) {
  return table.lookup(codePoint);
}

export const UNICODE_SECURITY_VERSION = EXPECTED_UNICODE_VERSION;
export const UTS39_REVISION = EXPECTED_UTS39_REVISION;
export const UNICODE_SECURITY_MANIFEST_SHA256 = EXPECTED_MANIFEST_SHA256;
