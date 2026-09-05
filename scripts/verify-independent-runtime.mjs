import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { gunzipSync } from "node:zlib";
import { errorPayload } from "../src/core/errors.js";
import { analyzeNamespaceIntegrity } from "../src/core/namespace-integrity.js";
import { executeOperation } from "../src/core/operations.js";
import { reorderForDisplay } from "../src/core/bidi.js";
import { compareConfusables, nfkcCasefold, uts39PostReorderSkeleton } from "../src/core/security.js";
import { unicodeDataIdentity, unicodeSecurityData } from "../src/core/unicode-security-data.js";
import {
  canonicalDigest,
  canonicalJson,
  materializeTaggedArguments,
  semanticProjection
} from "../src/reference/behavior.js";
import {
  createReferenceWasmRunner,
  REFERENCE_WASM_RAW_ABI
} from "../src/reference/wasm.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const MANIFEST = path.join(ROOT, "native", "Cargo.toml");
const RUST_TOOLCHAIN = "1.89.0";
const NATIVE_BINARY = path.join(
  ROOT,
  "native",
  "target",
  "release",
  process.platform === "win32" ? "text-integrity-reference.exe" : "text-integrity-reference"
);
const WASM_BINARY = path.join(
  ROOT,
  "native",
  "target",
  "wasm32-unknown-unknown",
  "release",
  "text_integrity_reference.wasm"
);
const batchFrameMeasurements = {
  configuredBatchSize: 0,
  batchCount: 0,
  maximumRequestCount: 0,
  maximumDifferenceAlignmentCells: null,
  maximumSourceDiagnosticUnits: null,
  maximumUts46PunycodeScanUnits: null,
  maximumInput: null,
  maximumNativeOutput: null,
  maximumWasmOutput: null
};

function observeBatchWork(field, units, requests) {
  const current = batchFrameMeasurements[field];
  if (current !== null && current.units >= units) return;
  batchFrameMeasurements[field] = {
    units,
    requestCount: requests.length,
    firstCaseId: requests[0]?.id ?? null,
    lastCaseId: requests.at(-1)?.id ?? null
  };
}

function observeBatchFrame(field, bytes, requests) {
  const current = batchFrameMeasurements[field];
  if (current !== null && current.bytes >= bytes) return;
  batchFrameMeasurements[field] = {
    bytes,
    requestCount: requests.length,
    firstCaseId: requests[0]?.id ?? null,
    lastCaseId: requests.at(-1)?.id ?? null
  };
}

function runCargo(args) {
  const child = spawnSync("cargo", args, {
    cwd: ROOT,
    env: { ...process.env, RUSTUP_TOOLCHAIN: RUST_TOOLCHAIN },
    encoding: "utf8",
    maxBuffer: 16 << 20
  });
  if (child.status !== 0) {
    throw new Error(`${child.stdout}${child.stderr}`.trim() || `cargo ${args.join(" ")} failed`);
  }
}

function nextRandom(state) {
  state.value = (Math.imul(state.value, 1664525) + 1013904223) >>> 0;
  return state.value;
}

function taggedScalar(value) {
  return { $text: { kind: "unicode_scalar_string", value } };
}

function taggedUnits(units) {
  return { $text: { kind: "utf16_code_units", units } };
}

const DIFFERENCE_COLLATION = Object.freeze({
  locale: "en",
  options: Object.freeze({
    usage: "sort",
    sensitivity: "variant",
    ignorePunctuation: false,
    numeric: false,
    caseFirst: "false",
    localeMatcher: "lookup",
    collation: "default"
  })
});

const DIFFERENCE_SPINE_PROJECTION = Object.freeze({
  kind: "deterministic_spine",
  consumerOperation: "explain_difference",
  includedStages: Object.freeze([
    "exact_representation",
    "normalization",
    "nfkc_casefold",
    "coordinate_mapping",
    "alignment",
    "unicode_signals",
    "line_endings",
    "identifier_confusable"
  ]),
  excludedStages: Object.freeze(["collation"]),
  excludedFields: Object.freeze([
    "collation",
    "runtime",
    "identifierConfusableComparison.engine"
  ]),
  completeConsumerParity: false
});

function differenceSpineArguments(left, right = left, {
  direction = "LTR",
  detailLimit = 0,
  witnessMode = "none"
} = {}) {
  return {
    left,
    right,
    locale: DIFFERENCE_COLLATION.locale,
    options: DIFFERENCE_COLLATION.options,
    confusableDirection: direction,
    detailLimit,
    witnessMode
  };
}

function buildBaseOperationShapeRequests() {
  const requests = [];
  const counts = { inspect: 0, normalize: 0, index: 0, transcode: 0 };
  const add = (operation, id, arguments_) => {
    requests.push({
      id: `${operation}:request-shape:${id}`,
      operation,
      arguments: arguments_
    });
    counts[operation] += 1;
  };
  const without = (value, key) => Object.fromEntries(
    Object.entries(value).filter(([name]) => name !== key)
  );
  const inspectBase = { text: taggedScalar("A"), detailLimit: 1 };
  const normalizeBase = { text: taggedScalar("A"), form: "NFC", witnessMode: "none" };
  const indexBase = { text: taggedScalar("A"), detailLimit: 1, maxChunkUtf8Bytes: 4 };
  const textTranscodeBase = {
    sourceKind: "text",
    text: taggedScalar("A"),
    targetEncoding: "utf-8",
    allowLossy: false,
    byteRepresentation: "hex",
    witnessMode: "none"
  };
  const byteTranscodeBase = {
    sourceKind: "bytes",
    bytes: [65],
    sourceEncoding: "utf-8",
    targetEncoding: "utf-8",
    allowLossy: false,
    byteRepresentation: "hex",
    witnessMode: "none"
  };

  for (const [id, arguments_] of [
    ["arguments-not-object-null", null],
    ["arguments-not-object-array", []],
    ["unknown-fields-sorted", { ...inspectBase, z: true, a: true }],
    ["unknown-precedes-missing", { detailLimit: 1, extra: true }],
    ["missing-text", without(inspectBase, "text")],
    ["text-wrong-type", { ...inspectBase, text: 1 }],
    ["detail-wrong-type", { ...inspectBase, detailLimit: "1" }],
    ["detail-fraction", { ...inspectBase, detailLimit: 1.5 }],
    ["detail-negative", { ...inspectBase, detailLimit: -1 }],
    ["detail-over-limit", { ...inspectBase, detailLimit: 129 }],
    ["text-budget-precedes-detail", {
      text: taggedScalar("a".repeat(4097)), detailLimit: "bad"
    }]
  ]) add("inspect", id, arguments_);

  for (const [id, arguments_] of [
    ["arguments-not-object-null", null],
    ["arguments-not-object-array", []],
    ["unknown-fields-sorted", { ...normalizeBase, z: true, a: true }],
    ["unknown-precedes-missing", { form: "NFC", extra: true }],
    ["missing-text", without(normalizeBase, "text")],
    ["missing-form", without(normalizeBase, "form")],
    ["text-wrong-type", { ...normalizeBase, text: 1 }],
    ["text-budget", { ...normalizeBase, text: taggedScalar("a".repeat(4097)) }],
    ["invalid-unicode", { ...normalizeBase, text: taggedUnits([0xd800]) }],
    ["invalid-unicode-precedes-form", {
      ...normalizeBase, text: taggedUnits([0xd800]), form: "bad"
    }],
    ["form-bad-value", { ...normalizeBase, form: "NFX" }],
    ["form-wrong-type", { ...normalizeBase, form: null }],
    ["witness-bad-value", { ...normalizeBase, witnessMode: "full" }],
    ["witness-wrong-type", { ...normalizeBase, witnessMode: 1 }],
    ["form-precedes-witness", { ...normalizeBase, form: "bad", witnessMode: "bad" }],
    ["text-budget-precedes-form", {
      ...normalizeBase, text: taggedScalar("a".repeat(4097)), form: "bad"
    }]
  ]) add("normalize", id, arguments_);

  for (const [id, arguments_] of [
    ["arguments-not-object-null", null],
    ["arguments-not-object-array", []],
    ["unknown-fields-sorted", { ...indexBase, z: true, a: true }],
    ["unknown-precedes-missing", { detailLimit: 1, extra: true }],
    ["missing-text", without(indexBase, "text")],
    ["text-wrong-type", { ...indexBase, text: 1 }],
    ["text-budget", { ...indexBase, text: taggedScalar("a".repeat(4097)) }],
    ["invalid-unicode", { ...indexBase, text: taggedUnits([0xd800]) }],
    ["detail-wrong-type", { ...indexBase, detailLimit: "1" }],
    ["detail-fraction", { ...indexBase, detailLimit: 1.5 }],
    ["detail-negative", { ...indexBase, detailLimit: -1 }],
    ["detail-over-limit", { ...indexBase, detailLimit: 129 }],
    ["chunk-wrong-type", { ...indexBase, maxChunkUtf8Bytes: "1" }],
    ["chunk-zero", { ...indexBase, maxChunkUtf8Bytes: 0 }],
    ["chunk-over-limit", { ...indexBase, maxChunkUtf8Bytes: 4097 }],
    ["invalid-unicode-precedes-detail", {
      ...indexBase, text: taggedUnits([0xd800]), detailLimit: "bad"
    }],
    ["detail-precedes-chunk", {
      ...indexBase, detailLimit: "bad", maxChunkUtf8Bytes: "bad"
    }],
    ["text-budget-precedes-detail", {
      ...indexBase, text: taggedScalar("a".repeat(4097)), detailLimit: "bad"
    }]
  ]) add("index", id, arguments_);

  for (const [id, arguments_] of [
    ["arguments-not-object-null", null],
    ["arguments-not-object-array", []],
    ["missing-source-kind", {}],
    ["source-kind-null", { ...textTranscodeBase, sourceKind: null }],
    ["source-kind-bad-value", { ...textTranscodeBase, sourceKind: "file" }],
    ["source-kind-precedes-unknown", { ...textTranscodeBase, sourceKind: "bad", extra: true }],
    ["target-encoding-missing", without(textTranscodeBase, "targetEncoding")],
    ["target-encoding-null", { ...textTranscodeBase, targetEncoding: null }],
    ["target-encoding-array", { ...textTranscodeBase, targetEncoding: [] }],
    ["target-encoding-boolean", { ...textTranscodeBase, targetEncoding: true }],
    ["target-encoding-number", { ...textTranscodeBase, targetEncoding: 1 }],
    ["target-encoding-object", { ...textTranscodeBase, targetEncoding: {} }],
    ["target-encoding-bad-value", { ...textTranscodeBase, targetEncoding: "latin1" }],
    ["target-encoding-precedes-unknown", {
      ...textTranscodeBase, targetEncoding: "bad", extra: true
    }],
    ["allow-lossy-missing", without(textTranscodeBase, "allowLossy")],
    ["allow-lossy-wrong-type", { ...textTranscodeBase, allowLossy: 0 }],
    ["allow-lossy-precedes-unknown", { ...textTranscodeBase, allowLossy: 0, extra: true }],
    ["byte-representation-missing", without(textTranscodeBase, "byteRepresentation")],
    ["byte-representation-wrong-type", { ...textTranscodeBase, byteRepresentation: 1 }],
    ["byte-representation-bad-value", { ...textTranscodeBase, byteRepresentation: "octal" }],
    ["byte-representation-precedes-unknown", {
      ...textTranscodeBase, byteRepresentation: "bad", extra: true
    }],
    ["witness-wrong-type", { ...textTranscodeBase, witnessMode: 1 }],
    ["witness-bad-value", { ...textTranscodeBase, witnessMode: "full" }],
    ["witness-precedes-unknown", { ...textTranscodeBase, witnessMode: "bad", extra: true }],
    ["text-unknown-fields-sorted", { ...textTranscodeBase, z: true, a: true }],
    ["text-missing", without(textTranscodeBase, "text")],
    ["text-wrong-type", { ...textTranscodeBase, text: 1 }],
    ["text-incompatible-fields", {
      ...textTranscodeBase, bytes: [65], sourceEncoding: "utf-8"
    }],
    ["text-budget", { ...textTranscodeBase, text: taggedScalar("a".repeat(4097)) }],
    ["text-invalid-unicode", { ...textTranscodeBase, text: taggedUnits([0xd800]) }],
    ["text-budget-precedes-unicode", {
      ...textTranscodeBase, text: taggedUnits(Array(1366).fill(0xd800))
    }],
    ["bytes-unknown-fields-sorted", { ...byteTranscodeBase, z: true, a: true }],
    ["bytes-missing-payload-and-encoding", without(without(byteTranscodeBase, "bytes"), "sourceEncoding")],
    ["source-encoding-missing", without(byteTranscodeBase, "sourceEncoding")],
    ["source-encoding-null", { ...byteTranscodeBase, sourceEncoding: null }],
    ["source-encoding-bad-value", { ...byteTranscodeBase, sourceEncoding: "latin1" }],
    ["bytes-null", { ...byteTranscodeBase, bytes: null }],
    ["bytes-object", { ...byteTranscodeBase, bytes: {} }],
    ["byte-negative", { ...byteTranscodeBase, bytes: [-1] }],
    ["byte-fraction", { ...byteTranscodeBase, bytes: [1.5] }],
    ["byte-over-range", { ...byteTranscodeBase, bytes: [256] }],
    ["byte-wrong-type", { ...byteTranscodeBase, bytes: ["1"] }],
    ["bytes-over-limit", { ...byteTranscodeBase, bytes: Array(4097).fill(65) }],
    ["bytes-limit-precedes-element", {
      ...byteTranscodeBase, bytes: [-1, ...Array(4096).fill(65)]
    }],
    ["bytes-incompatible-field", { ...byteTranscodeBase, text: taggedScalar("A") }]
  ]) add("transcode", id, arguments_);

  return {
    requests,
    coverage: Object.fromEntries(Object.entries(counts).map(([operation, negativeRequestShapeCaseCount]) => [
      operation,
      { negativeRequestShapeCaseCount }
    ]))
  };
}

function decodeIdna(value, fallback) {
  const source = value.trim();
  if (source === "") return fallback;
  if (source === '""') return "";
  return source
    .replace(/\\u([0-9A-Fa-f]{4})/gu, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)))
    .replace(/\\x\{([0-9A-Fa-f]+)\}/gu, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)));
}

function independentProjection(operation, result) {
  const projection = semanticProjection(result);
  if ([
    "reference_bidi_skeleton",
    "reference_confusable_comparison",
    "reference_nfkc_casefold",
    "reference_uts39_post_reorder_skeleton"
  ].includes(operation)
    && projection.status === "ok") {
    const scoped = structuredClone(projection);
    delete scoped.engine;
    if (operation === "reference_bidi_skeleton") {
      delete scoped.standards.uba.algorithm;
      delete scoped.standards.uba.hardcodedDataFeature;
      delete scoped.standards.uba.dataSource;
      delete scoped.resolvedLevels;
      delete scoped.visualOrder;
      delete scoped.entries;
      delete scoped.reordered;
    }
    return scoped;
  }
  return projection;
}

function rawSha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function buildUts46OptionRequests() {
  const probes = [
    ["ascii-case", "Example.COM"],
    ["transitional-sharp-s", "faß.de"],
    ["transitional-capital-sharp-s", "ẞ.de"],
    ["transitional-final-sigma", "βόλος.example"],
    ["mapped-dot", "a\u3002b"],
    ["std3", "a_b"],
    ["hyphen-leading", "-a"],
    ["hyphen-third-fourth", "ab--cd"],
    ["bidi-valid", "אב.example"],
    ["bidi-invalid", "אa.example"],
    ["joiner-invalid-zwnj", "a\u200Cb"],
    ["joiner-invalid-zwj", "a\u200Db"],
    ["joiner-valid-virama", "क्‍ष.example"],
    ["leading-mark", "\u0301a"],
    ["punycode-valid", "xn--fa-hia.de"],
    ["punycode-invalid", "xn--a"],
    ["dns-label-long", `${"a".repeat(64)}.example`],
    ["empty", ""],
    ["trailing-root", "example.com."]
  ];
  const commonFields = [
    "checkBidi",
    "checkHyphens",
    "checkJoiners",
    "ignoreInvalidPunycode",
    "transitionalProcessing",
    "useSTD3ASCIIRules"
  ];
  const witnessModes = ["none", "summary", "full_required"];
  const requests = [];
  const addCombinations = (action, fields) => {
    const combinationCount = 2 ** fields.length;
    for (const [probeIndex, [probe, text]] of probes.entries()) {
      for (let mask = 0; mask < combinationCount; mask += 1) {
        const options = Object.fromEntries(fields.map((field, bit) => [field, (mask & (1 << bit)) !== 0]));
        requests.push({
          id: `uts46-options:${action}:${probe}:${mask}`,
          operation: "protocol_profile",
          arguments: {
            profile: "uts46_domain",
            action,
            text: taggedScalar(text),
            options,
            witnessMode: witnessModes[(probeIndex + mask) % witnessModes.length]
          }
        });
      }
    }
    return combinationCount;
  };
  const toAsciiOptionCombinationCount = addCombinations("to_ascii", [...commonFields, "verifyDNSLength"]);
  const toUnicodeOptionCombinationCount = addCombinations("to_unicode", commonFields);
  return {
    requests,
    coverage: {
      probeCount: probes.length,
      toAsciiOptionCombinationCount,
      toUnicodeOptionCombinationCount,
      allLegalOptionCombinationsIncluded: true,
      totalCaseCount: requests.length
    }
  };
}

function buildProtocolShapeRequests() {
  const without = (value, key) => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  const uts46Options = {
    checkBidi: true,
    checkHyphens: true,
    checkJoiners: true,
    ignoreInvalidPunycode: false,
    transitionalProcessing: false,
    useSTD3ASCIIRules: true,
    verifyDNSLength: true
  };
  const uts46Base = {
    profile: "uts46_domain",
    action: "to_ascii",
    text: taggedScalar("example.com"),
    options: uts46Options,
    witnessMode: "summary"
  };
  const precisBase = {
    profile: "precis_username_case_mapped",
    action: "enforce",
    text: taggedScalar("User"),
    witnessMode: "summary"
  };
  const requests = [
    ["arguments-not-object", null],
    ["missing-profile", without(uts46Base, "profile")],
    ["bad-profile", { ...uts46Base, profile: "bad" }],
    ["profile-wrong-type", { ...uts46Base, profile: 1 }]
  ];
  const uts46Start = requests.length;
  requests.push(
    ["uts46-unknown-field", { ...uts46Base, extra: true }],
    ["uts46-missing-action", without(uts46Base, "action")],
    ["uts46-missing-text", without(uts46Base, "text")],
    ["uts46-missing-options", without(uts46Base, "options")],
    ["uts46-bad-action", { ...uts46Base, action: "bad" }],
    ["uts46-bad-witness", { ...uts46Base, witnessMode: "bad" }],
    ["uts46-text-wrong-type", { ...uts46Base, text: 1 }],
    ["uts46-invalid-unicode", { ...uts46Base, text: taggedUnits([0xd800]) }],
    ["uts46-text-byte-limit", { ...uts46Base, text: taggedScalar("a".repeat(4097)) }],
    ["uts46-options-wrong-type", { ...uts46Base, options: [] }],
    ["uts46-option-unknown-field", { ...uts46Base, options: { ...uts46Options, extra: true } }]
  );
  for (const field of Object.keys(uts46Options)) {
    requests.push([
      `uts46-option-missing-${field}`,
      { ...uts46Base, options: without(uts46Options, field) }
    ]);
    requests.push([
      `uts46-option-wrong-type-${field}`,
      { ...uts46Base, options: { ...uts46Options, [field]: "true" } }
    ]);
  }
  requests.push([
    "uts46-to-unicode-dns-option",
    {
      ...uts46Base,
      action: "to_unicode",
      options: { ...without(uts46Options, "verifyDNSLength"), verifyDNSLength: true }
    }
  ]);
  const uts46CaseCount = requests.length - uts46Start;
  const precisStart = requests.length;
  requests.push(
    ["precis-unknown-field", { ...precisBase, extra: true }],
    ["precis-missing-action", without(precisBase, "action")],
    ["precis-missing-text", without(precisBase, "text")],
    ["precis-bad-action", { ...precisBase, action: "bad" }],
    ["precis-bad-witness", { ...precisBase, witnessMode: "bad" }],
    ["precis-text-wrong-type", { ...precisBase, text: 1 }],
    ["precis-invalid-unicode", { ...precisBase, text: taggedUnits([0xd800]) }],
    ["precis-text-byte-limit", { ...precisBase, text: taggedScalar("a".repeat(4097)) }],
    ["precis-compare-missing-comparison", { ...precisBase, action: "compare" }],
    ["precis-enforce-has-comparison", { ...precisBase, comparison: taggedScalar("User") }],
    ["precis-comparison-wrong-type", { ...precisBase, action: "compare", comparison: 1 }],
    ["precis-comparison-invalid-unicode", {
      ...precisBase, action: "compare", comparison: taggedUnits([0xd800])
    }],
    ["precis-comparison-byte-limit", {
      ...precisBase, action: "compare", comparison: taggedScalar("a".repeat(4097))
    }],
    ["precis-combined-byte-limit", {
      ...precisBase,
      action: "compare",
      text: taggedScalar("a".repeat(4096)),
      comparison: taggedScalar("b".repeat(4096))
    }]
  );
  const precisCaseCount = requests.length - precisStart;
  return {
    requests: requests.map(([id, arguments_]) => ({
      id: `protocol-shape:${id}`,
      operation: "protocol_profile",
      arguments: arguments_
    })),
    coverage: {
      sharedCaseCount: uts46Start,
      uts46CaseCount,
      precisCaseCount,
      totalCaseCount: requests.length
    }
  };
}

function buildPrecisRequests() {
  const dataRoot = path.join(ROOT, "vendor", "unicode", "17.0.0");
  const manifestBytes = readFileSync(path.join(dataRoot, "MANIFEST.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const sourcePaths = {
    derivedCore: "ucd/DerivedCoreProperties.txt",
    propList: "ucd/PropList.txt",
    generalCategory: "ucd/extracted/DerivedGeneralCategory.txt",
    unicodeData: "ucd/UnicodeData.txt",
    specialCasing: "ucd/SpecialCasing.txt",
    joiningType: "ucd/extracted/DerivedJoiningType.txt",
    hangulSyllableType: "ucd/HangulSyllableType.txt",
    scripts: "ucd/Scripts.txt",
    scriptExtensions: "ucd/ScriptExtensions.txt",
    bidiClass: "ucd/extracted/DerivedBidiClass.txt"
  };
  const sources = {};
  for (const [name, relativePath] of Object.entries(sourcePaths)) {
    const bytes = readFileSync(path.join(dataRoot, relativePath));
    const entry = manifest.files.find((item) => item.path === relativePath);
    if (manifest.unicodeVersion !== "17.0.0" || !entry
      || entry.bytes !== bytes.length || entry.sha256 !== rawSha256(bytes)) {
      throw new Error(`${relativePath} does not match the pinned Unicode manifest`);
    }
    sources[name] = { bytes, entry };
  }

  const parseRows = (bytes) => bytes.toString("utf8").split(/\r?\n/u).flatMap((sourceLine) => {
    const content = sourceLine.split("#", 1)[0].trim();
    return content === "" ? [] : [content.split(";").map((field) => field.trim())];
  });
  const addBoundaries = (set, rows, predicate = () => true) => {
    for (const fields of rows) {
      if (!predicate(fields)) continue;
      const [first, last = first] = fields[0].split("..");
      set.add(Number.parseInt(first, 16));
      set.add(Number.parseInt(last, 16));
    }
  };
  const validScalars = (values) => [...values]
    .filter((codePoint) => Number.isInteger(codePoint)
      && codePoint >= 0 && codePoint <= 0x10ffff
      && !(codePoint >= 0xd800 && codePoint <= 0xdfff))
    .sort((left, right) => left - right);
  const label = (codePoint) => codePoint.toString(16).toUpperCase().padStart(4, "0");
  const profiles = [
    "precis_username_case_mapped",
    "precis_username_case_preserved",
    "precis_opaque_string"
  ];
  const requests = [];

  const propertyBoundaries = new Set([
    0x00df, 0x03c2, 0x06fd, 0x06fe, 0x0f0b, 0x3007,
    0x00b7, 0x0375, 0x05f3, 0x05f4, 0x30fb,
    0x0640, 0x07fa, 0x302e, 0x302f, 0x3031, 0x3035, 0x303b,
    0x0660, 0x0669, 0x06f0, 0x06f9, 0x20, 0x21, 0x7e, 0x7f
  ]);
  addBoundaries(
    propertyBoundaries,
    parseRows(sources.derivedCore.bytes),
    (fields) => ["Default_Ignorable_Code_Point", "Cased", "Case_Ignorable"].includes(fields[1])
  );
  addBoundaries(
    propertyBoundaries,
    parseRows(sources.propList.bytes),
    (fields) => ["Join_Control", "Noncharacter_Code_Point"].includes(fields[1])
  );
  for (const name of [
    "generalCategory", "joiningType", "hangulSyllableType", "scripts", "scriptExtensions", "bidiClass"
  ]) addBoundaries(propertyBoundaries, parseRows(sources[name].bytes));
  const propertyScalars = validScalars(propertyBoundaries);
  for (const codePoint of propertyScalars) {
    for (const profile of profiles) {
      requests.push({
        id: `precis:property-boundary:U+${label(codePoint)}:${profile}`,
        operation: "protocol_profile",
        arguments: {
          profile,
          action: "enforce",
          text: taggedScalar(String.fromCodePoint(codePoint)),
          witnessMode: "none"
        }
      });
    }
  }

  const widthMappings = [];
  const lowercaseMappings = new Map();
  for (const sourceLine of sources.unicodeData.bytes.toString("utf8").split(/\r?\n/u)) {
    if (sourceLine === "") continue;
    const fields = sourceLine.split(";");
    const codePoint = Number.parseInt(fields[0], 16);
    if (fields[13] !== "") {
      lowercaseMappings.set(codePoint, String.fromCodePoint(Number.parseInt(fields[13], 16)));
    }
    if (/^<(?:wide|narrow)>\s+/u.test(fields[5])) widthMappings.push(codePoint);
  }
  for (const fields of parseRows(sources.specialCasing.bytes)) {
    if (fields[4] !== "") continue;
    lowercaseMappings.set(
      Number.parseInt(fields[0], 16),
      fields[1].split(/\s+/u).filter(Boolean)
        .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("")
    );
  }
  const changingLowercaseMappings = [...lowercaseMappings.entries()]
    .filter(([codePoint, value]) => value !== String.fromCodePoint(codePoint))
    .sort(([left], [right]) => left - right);
  for (const codePoint of widthMappings) {
    requests.push({
      id: `precis:width-mapping:U+${label(codePoint)}`,
      operation: "protocol_profile",
      arguments: {
        profile: "precis_username_case_preserved",
        action: "enforce",
        text: taggedScalar(String.fromCodePoint(codePoint)),
        witnessMode: "summary"
      }
    });
  }
  for (const [codePoint] of changingLowercaseMappings) {
    requests.push({
      id: `precis:lowercase-mapping:U+${label(codePoint)}`,
      operation: "protocol_profile",
      arguments: {
        profile: "precis_username_case_mapped",
        action: "enforce",
        text: taggedScalar(String.fromCodePoint(codePoint)),
        witnessMode: "summary"
      }
    });
  }

  const conformanceManifest = JSON.parse(readFileSync(path.join(dataRoot, "CONFORMANCE_MANIFEST.json")));
  const normalizationEntry = conformanceManifest.files.find(
    (entry) => entry.path.endsWith("/NormalizationTest.txt.gz")
  );
  const normalizationBytes = readFileSync(path.join(dataRoot, normalizationEntry.path));
  if (normalizationBytes.length !== normalizationEntry.bytes
    || rawSha256(normalizationBytes) !== normalizationEntry.sha256) {
    throw new Error("NormalizationTest.txt.gz does not match the pinned conformance manifest");
  }
  const normalizationCorpus = gunzipSync(normalizationBytes).toString("utf8");
  let normalizationConformanceSourceCaseCount = 0;
  for (const sourceLine of normalizationCorpus.split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "" || content.startsWith("@")) continue;
    const value = content.split(";", 1)[0].trim().split(/\s+/u)
      .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("");
    requests.push({
      id: `precis:normalization-conformance:${normalizationConformanceSourceCaseCount}`,
      operation: "protocol_profile",
      arguments: {
        profile: "precis_opaque_string",
        action: "enforce",
        text: taggedScalar(value),
        witnessMode: "none"
      }
    });
    normalizationConformanceSourceCaseCount += 1;
  }
  if (normalizationConformanceSourceCaseCount !== 20034) {
    throw new Error(
      `expected 20034 NormalizationTest sources for PRECIS, received ${normalizationConformanceSourceCaseCount}`
    );
  }

  const contextSequences = [
    ["middle-dot-valid", "l\u00B7l"], ["middle-dot-invalid", "a\u00B7a"],
    ["greek-valid", "\u0375\u03B1"], ["greek-invalid", "\u0375a"],
    ["hebrew-valid", "\u05D0\u05F3"], ["hebrew-invalid", "a\u05F3"],
    ["katakana-valid", "\u30AB\u30FB"], ["katakana-invalid", "a\u30FB"],
    ["arabic-indic-valid", "\u0661"], ["extended-arabic-indic-valid", "\u06F1"],
    ["arabic-digit-mix-invalid", "\u0661\u06F1"],
    ["zwnj-virama-valid", "\u0915\u094D\u200C"], ["zwnj-invalid", "a\u200C"],
    ["zwj-virama-valid", "\u0915\u094D\u200D"], ["zwj-invalid", "a\u200D"],
    ["zwnj-joining-valid", "\u0628\u200C\u062A"]
  ];
  for (const [id, value] of contextSequences) {
    for (const profile of profiles) {
      requests.push({
        id: `precis:context:${id}:${profile}`,
        operation: "protocol_profile",
        arguments: {
          profile,
          action: "enforce",
          text: taggedScalar(value),
          witnessMode: "full_required"
        }
      });
    }
  }

  const bidiSequences = [
    ["rtl-letter", "\u05D0"], ["rtl-european-digit", "\u05D01"],
    ["rtl-arabic-digit", "\u0627\u0661"], ["rtl-trailing-nsm", "\u05D0\u0301"],
    ["mixed-digits", "\u06271\u0661"], ["leading-digit", "1\u05D0"],
    ["ltr-in-rtl", "\u05D0A"], ["invalid-end", "\u05D0-"], ["ltr-prefix", "A\u05D0"]
  ];
  const usernameProfiles = profiles.slice(0, 2);
  for (const [id, value] of bidiSequences) {
    for (const profile of usernameProfiles) {
      requests.push({
        id: `precis:bidi:${id}:${profile}`,
        operation: "protocol_profile",
        arguments: {
          profile,
          action: "enforce",
          text: taggedScalar(value),
          witnessMode: "full_required"
        }
      });
    }
  }

  const sequenceRequests = [
    ["mapped-width-case", "precis_username_case_mapped", "enforce", "Ｕser", undefined, "full_required"],
    ["mapped-final-sigma", "precis_username_case_mapped", "enforce", "A\u0301\u03A3", undefined, "full_required"],
    ["mapped-nonfinal-sigma", "precis_username_case_mapped", "enforce", "A\u03A3\u0301A", undefined, "full_required"],
    ["preserved", "precis_username_case_preserved", "enforce", "User", undefined, "summary"],
    ["opaque-space", "precis_opaque_string", "enforce", "A\u00A0B", undefined, "full_required"],
    ["opaque-case", "precis_opaque_string", "compare", "Password", "password", "summary"],
    ["mapped-compare", "precis_username_case_mapped", "compare", "User", "user", "full_required"],
    ["preserved-compare", "precis_username_case_preserved", "compare", "User", "User", "summary"],
    ["empty-mapped", "precis_username_case_mapped", "enforce", "", undefined, "none"],
    ["empty-preserved", "precis_username_case_preserved", "enforce", "", undefined, "none"],
    ["empty-opaque", "precis_opaque_string", "enforce", "", undefined, "none"],
    ["identifier-space", "precis_username_case_mapped", "enforce", "a b", undefined, "none"],
    ["noncharacter", "precis_username_case_mapped", "enforce", "\uFDD0", undefined, "none"],
    ["unassigned", "precis_username_case_mapped", "enforce", "\u0378", undefined, "none"],
    ["has-compat-identifier", "precis_username_case_mapped", "enforce", "\u212A", undefined, "none"],
    ["has-compat-freeform", "precis_opaque_string", "enforce", "\u00B9", undefined, "none"],
    ["maximum-summary", "precis_username_case_mapped", "compare", "A".repeat(4096), "A".repeat(4096), "summary"]
  ];
  for (const [id, profile, action, text, comparison, witnessMode] of sequenceRequests) {
    requests.push({
      id: `precis:sequence:${id}`,
      operation: "protocol_profile",
      arguments: {
        profile,
        action,
        text: taggedScalar(text),
        ...(comparison === undefined ? {} : { comparison: taggedScalar(comparison) }),
        witnessMode
      }
    });
  }
  requests.push({
    id: "precis:negative:unpaired-text",
    operation: "protocol_profile",
    arguments: {
      profile: "precis_username_case_mapped",
      action: "enforce",
      text: taggedUnits([0xd800]),
      witnessMode: "none"
    }
  }, {
    id: "precis:negative:unpaired-comparison",
    operation: "protocol_profile",
    arguments: {
      profile: "precis_username_case_mapped",
      action: "compare",
      text: taggedScalar("user"),
      comparison: taggedUnits([0xd800]),
      witnessMode: "none"
    }
  });

  return {
    requests,
    coverage: {
      sourceManifestSha256: rawSha256(manifestBytes),
      sourceFiles: Object.fromEntries(Object.entries(sources).map(([name, source]) => [name, {
        path: sourcePaths[name], sha256: source.entry.sha256
      }])),
      profiles,
      actions: ["enforce", "compare"],
      witnessModes: ["none", "summary", "full_required"],
      propertyBoundaryCodePointCount: propertyScalars.length,
      propertyBoundaryProfileCaseCount: propertyScalars.length * profiles.length,
      widthMappingCaseCount: widthMappings.length,
      lowercaseMappingCaseCount: changingLowercaseMappings.length,
      normalizationConformanceSourceCaseCount,
      contextSequenceCaseCount: contextSequences.length * profiles.length,
      bidiSequenceCaseCount: bidiSequences.length * usernameProfiles.length,
      composedSequenceCaseCount: sequenceRequests.length,
      negativeEncodingCaseCount: 2,
      totalCaseCount: requests.length
    }
  };
}

function buildNfkcCasefoldRequests() {
  const manifestBytes = readFileSync(path.join(ROOT, "vendor", "unicode", "17.0.0", "MANIFEST.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const sourcePath = "ucd/DerivedNormalizationProps.txt";
  const sourceBytes = readFileSync(path.join(ROOT, "vendor", "unicode", "17.0.0", sourcePath));
  const sourceEntry = manifest.files.find((entry) => entry.path === sourcePath);
  if (manifest.unicodeVersion !== "17.0.0"
    || !sourceEntry
    || sourceEntry.bytes !== sourceBytes.length
    || sourceEntry.sha256 !== rawSha256(sourceBytes)) {
    throw new Error("the NFKC_CF comparison source does not match the pinned Unicode manifest");
  }

  const ranges = [];
  for (const sourceLine of sourceBytes.toString("utf8").split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const fields = content.split(";").map((field) => field.trim());
    if (fields[1] !== "NFKC_CF") continue;
    const [first, last = first] = fields[0].split("..");
    ranges.push({ start: Number.parseInt(first, 16), end: Number.parseInt(last, 16) });
  }

  const mappingFor = (codePoint) => {
    let low = 0;
    let high = ranges.length;
    while (low < high) {
      const middle = low + ((high - low) >>> 1);
      if (codePoint < ranges[middle].start) high = middle;
      else if (codePoint > ranges[middle].end) low = middle + 1;
      else return true;
    }
    return false;
  };
  const label = (codePoint) => codePoint.toString(16).toUpperCase().padStart(4, "0");
  const requests = [];
  let mappedCodePointCaseCount = 0;
  for (const { start, end } of ranges) {
    for (let codePoint = start; codePoint <= end; codePoint += 1) {
      requests.push({
        id: `nfkc-casefold:mapped:U+${label(codePoint)}`,
        operation: "reference_nfkc_casefold",
        arguments: { text: taggedScalar(String.fromCodePoint(codePoint)) }
      });
      mappedCodePointCaseCount += 1;
    }
  }

  const boundaryCodePoints = new Set();
  for (const { start, end } of ranges) {
    for (const codePoint of [start - 1, end + 1]) {
      if (codePoint < 0 || codePoint > 0x10ffff
        || (codePoint >= 0xd800 && codePoint <= 0xdfff)
        || mappingFor(codePoint)) continue;
      boundaryCodePoints.add(codePoint);
    }
  }
  for (const codePoint of [...boundaryCodePoints].sort((left, right) => left - right)) {
    requests.push({
      id: `nfkc-casefold:identity-boundary:U+${label(codePoint)}`,
      operation: "reference_nfkc_casefold",
      arguments: { text: taggedScalar(String.fromCodePoint(codePoint)) }
    });
  }

  const sequences = [
    "",
    "ASCII",
    "Straße",
    "A\u030A",
    "\u212B",
    "\u00AD",
    "\u034F",
    "\uFB03",
    "\u1E9B\u0323",
    "①A\u0315\u0300",
    "\u1100\u1161\u11A8",
    "\uAC01",
    "\uFDFA",
    "\u{1D15E}",
    "\u0130",
    "\u03A3\u0345\u0300"
  ];
  for (const [index, value] of sequences.entries()) {
    requests.push({
      id: `nfkc-casefold:sequence:${index}`,
      operation: "reference_nfkc_casefold",
      arguments: { text: taggedScalar(value) }
    });
  }

  return {
    requests,
    coverage: {
      sourceManifestSha256: rawSha256(manifestBytes),
      sourceFilePath: sourcePath,
      sourceFileSha256: sourceEntry.sha256,
      mappingRowCount: ranges.length,
      mappedCodePointCaseCount,
      identityBoundaryCaseCount: boundaryCodePoints.size,
      sequenceCaseCount: sequences.length,
      totalCaseCount: requests.length
    }
  };
}

function buildUts39PostReorderSkeletonRequests() {
  const dataRoot = path.join(ROOT, "vendor", "unicode", "17.0.0");
  const manifestBytes = readFileSync(path.join(dataRoot, "MANIFEST.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const confusablesPath = "security/confusables.txt";
  const derivedCorePath = "ucd/DerivedCoreProperties.txt";
  const confusablesBytes = readFileSync(path.join(dataRoot, confusablesPath));
  const derivedCoreBytes = readFileSync(path.join(dataRoot, derivedCorePath));
  const confusablesEntry = manifest.files.find((entry) => entry.path === confusablesPath);
  const derivedCoreEntry = manifest.files.find((entry) => entry.path === derivedCorePath);
  if (manifest.unicodeVersion !== "17.0.0" || manifest.uts39Revision !== 32
    || !confusablesEntry || !derivedCoreEntry
    || confusablesEntry.bytes !== confusablesBytes.length
    || confusablesEntry.sha256 !== rawSha256(confusablesBytes)
    || derivedCoreEntry.bytes !== derivedCoreBytes.length
    || derivedCoreEntry.sha256 !== rawSha256(derivedCoreBytes)) {
    throw new Error("the UTS #39 skeleton comparison sources do not match the pinned Unicode manifest");
  }

  const mappingSources = [];
  for (const sourceLine of confusablesBytes.toString("utf8").split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const fields = content.split(";").map((field) => field.trim());
    const source = fields[0].split(/\s+/u).filter(Boolean);
    if (fields[2] !== "MA" || source.length !== 1) {
      throw new Error("the UTS #39 skeleton comparison found an unsupported confusables row");
    }
    mappingSources.push(Number.parseInt(source[0], 16));
  }
  mappingSources.sort((left, right) => left - right);
  if (new Set(mappingSources).size !== mappingSources.length) {
    throw new Error("the UTS #39 skeleton comparison found duplicate mapping sources");
  }

  const defaultIgnorableRanges = [];
  for (const sourceLine of derivedCoreBytes.toString("utf8").split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const fields = content.split(";").map((field) => field.trim());
    if (fields[1] !== "Default_Ignorable_Code_Point") continue;
    const [first, last = first] = fields[0].split("..");
    defaultIgnorableRanges.push({
      start: Number.parseInt(first, 16),
      end: Number.parseInt(last, 16)
    });
  }
  defaultIgnorableRanges.sort((left, right) => left.start - right.start || left.end - right.end);
  const isDefaultIgnorable = (codePoint) => {
    let low = 0;
    let high = defaultIgnorableRanges.length;
    while (low < high) {
      const middle = low + ((high - low) >>> 1);
      const range = defaultIgnorableRanges[middle];
      if (codePoint < range.start) high = middle;
      else if (codePoint > range.end) low = middle + 1;
      else return true;
    }
    return false;
  };
  const mappingSourceSet = new Set(mappingSources);
  const label = (codePoint) => codePoint.toString(16).toUpperCase().padStart(4, "0");
  const requests = mappingSources.map((codePoint) => ({
    id: `uts39-post-reorder-skeleton:mapped-source:U+${label(codePoint)}`,
    operation: "reference_uts39_post_reorder_skeleton",
    arguments: { text: taggedScalar(String.fromCodePoint(codePoint)) }
  }));

  let defaultIgnorableCaseCount = 0;
  for (const { start, end } of defaultIgnorableRanges) {
    for (let codePoint = start; codePoint <= end; codePoint += 1) {
      requests.push({
        id: `uts39-post-reorder-skeleton:default-ignorable:U+${label(codePoint)}`,
        operation: "reference_uts39_post_reorder_skeleton",
        arguments: { text: taggedScalar(String.fromCodePoint(codePoint)) }
      });
      defaultIgnorableCaseCount += 1;
    }
  }

  const boundaryCodePoints = new Set();
  for (const codePoint of mappingSources) {
    for (const boundary of [codePoint - 1, codePoint + 1]) {
      if (boundary < 0 || boundary > 0x10ffff
        || (boundary >= 0xd800 && boundary <= 0xdfff)
        || mappingSourceSet.has(boundary) || isDefaultIgnorable(boundary)) continue;
      boundaryCodePoints.add(boundary);
    }
  }
  for (const { start, end } of defaultIgnorableRanges) {
    for (const boundary of [start - 1, end + 1]) {
      if (boundary < 0 || boundary > 0x10ffff
        || (boundary >= 0xd800 && boundary <= 0xdfff)
        || mappingSourceSet.has(boundary) || isDefaultIgnorable(boundary)) continue;
      boundaryCodePoints.add(boundary);
    }
  }
  for (const codePoint of [...boundaryCodePoints].sort((left, right) => left - right)) {
    requests.push({
      id: `uts39-post-reorder-skeleton:identity-boundary:U+${label(codePoint)}`,
      operation: "reference_uts39_post_reorder_skeleton",
      arguments: { text: taggedScalar(String.fromCodePoint(codePoint)) }
    });
  }

  const sequences = [
    "",
    "ASCII",
    "paypal",
    "pаypal",
    "☝",
    "☝️",
    "\u00AD",
    "a\u00ADb",
    "\u3164",
    "\u3165",
    "é",
    "e\u0301",
    "A\u0315\u0300",
    "\u05AD",
    "\u06E8",
    "\u0341",
    "\u212B",
    "👨‍👩‍👧‍👦",
    "\uFE0F",
    "\u200D",
    "A1<שׂ",
    "Αשֺ>1",
    "\uFDFA",
    "\u{1D400}"
  ];
  for (const [index, value] of sequences.entries()) {
    requests.push({
      id: `uts39-post-reorder-skeleton:sequence:${index}`,
      operation: "reference_uts39_post_reorder_skeleton",
      arguments: { text: taggedScalar(value) }
    });
  }

  const conformanceManifest = JSON.parse(readFileSync(path.join(dataRoot, "CONFORMANCE_MANIFEST.json")));
  const normalizationEntry = conformanceManifest.files.find(
    (entry) => entry.path.endsWith("/NormalizationTest.txt.gz")
  );
  const normalizationCorpus = gunzipSync(readFileSync(path.join(dataRoot, normalizationEntry.path))).toString("utf8");
  let normalizationConformanceSourceCaseCount = 0;
  for (const sourceLine of normalizationCorpus.split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "" || content.startsWith("@")) continue;
    const value = content.split(";", 1)[0].trim().split(/\s+/u)
      .map((item) => String.fromCodePoint(Number.parseInt(item, 16)))
      .join("");
    requests.push({
      id: `uts39-post-reorder-skeleton:normalization-conformance:${normalizationConformanceSourceCaseCount}`,
      operation: "reference_uts39_post_reorder_skeleton",
      arguments: { text: taggedScalar(value) }
    });
    normalizationConformanceSourceCaseCount += 1;
  }
  if (normalizationConformanceSourceCaseCount !== 20034) {
    throw new Error(
      `expected 20034 NormalizationTest sources for the UTS #39 skeleton composition, received ${normalizationConformanceSourceCaseCount}`
    );
  }

  return {
    requests,
    coverage: {
      sourceManifestSha256: rawSha256(manifestBytes),
      confusablesSourcePath: confusablesPath,
      confusablesSourceSha256: confusablesEntry.sha256,
      derivedCoreSourcePath: derivedCorePath,
      derivedCoreSourceSha256: derivedCoreEntry.sha256,
      confusableMappingRowCount: mappingSources.length,
      mappedSourceCaseCount: mappingSources.length,
      defaultIgnorableRangeCount: defaultIgnorableRanges.length,
      defaultIgnorableCodePointCount: defaultIgnorableCaseCount,
      defaultIgnorableCaseCount,
      identityBoundaryCaseCount: boundaryCodePoints.size,
      sequenceCaseCount: sequences.length,
      normalizationConformanceSourceCaseCount,
      totalCaseCount: requests.length
    }
  };
}

function buildBidiSkeletonRequests() {
  const dataRoot = path.join(ROOT, "vendor", "unicode", "17.0.0");
  const manifestBytes = readFileSync(path.join(dataRoot, "MANIFEST.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const sourcePaths = {
    bidiClass: "ucd/extracted/DerivedBidiClass.txt",
    bidiBrackets: "ucd/BidiBrackets.txt",
    bidiMirroring: "ucd/BidiMirroring.txt",
    unicodeData: "ucd/UnicodeData.txt"
  };
  const sources = {};
  for (const [name, relativePath] of Object.entries(sourcePaths)) {
    const bytes = readFileSync(path.join(dataRoot, relativePath));
    const entry = manifest.files.find((item) => item.path === relativePath);
    if (manifest.unicodeVersion !== "17.0.0" || !entry
      || entry.bytes !== bytes.length || entry.sha256 !== rawSha256(bytes)) {
      throw new Error(`${relativePath} does not match the pinned Unicode manifest`);
    }
    sources[name] = { bytes, entry };
  }

  const requests = [];
  const directions = ["LTR", "RTL", "first_strong"];
  const scalarBoundarySet = new Set();
  for (const sourceLine of sources.bidiClass.bytes.toString("utf8").split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const [rangeValue] = content.split(";");
    const [first, last = first] = rangeValue.trim().split("..");
    scalarBoundarySet.add(Number.parseInt(first, 16));
    scalarBoundarySet.add(Number.parseInt(last, 16));
  }
  const scalarBoundaries = [...scalarBoundarySet]
    .filter((codePoint) => !(codePoint >= 0xd800 && codePoint <= 0xdfff))
    .sort((left, right) => left - right);
  for (const codePoint of scalarBoundaries) {
    for (const direction of directions) {
      requests.push({
        id: `bidi-skeleton:class-boundary:U+${codePoint.toString(16).toUpperCase()}:${direction}`,
        operation: "reference_bidi_skeleton",
        arguments: { text: taggedScalar(String.fromCodePoint(codePoint)), direction }
      });
    }
  }

  let bracketEntryCount = 0;
  for (const sourceLine of sources.bidiBrackets.bytes.toString("utf8").split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const codePoint = Number.parseInt(content.split(";", 1)[0], 16);
    for (const direction of directions) {
      requests.push({
        id: `bidi-skeleton:bracket:U+${codePoint.toString(16).toUpperCase()}:${direction}`,
        operation: "reference_bidi_skeleton",
        arguments: { text: taggedScalar(`A${String.fromCodePoint(codePoint)}א`), direction }
      });
    }
    bracketEntryCount += 1;
  }

  let mirroringEntryCount = 0;
  for (const sourceLine of sources.bidiMirroring.bytes.toString("utf8").split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const codePoint = Number.parseInt(content.split(";", 1)[0], 16);
    requests.push({
      id: `bidi-skeleton:mirror:U+${codePoint.toString(16).toUpperCase()}`,
      operation: "reference_bidi_skeleton",
      arguments: { text: taggedScalar(`א${String.fromCodePoint(codePoint)}`), direction: "RTL" }
    });
    mirroringEntryCount += 1;
  }

  let combiningCodePointCount = 0;
  for (const sourceLine of sources.unicodeData.bytes.toString("utf8").split(/\r?\n/u)) {
    if (sourceLine === "") continue;
    const fields = sourceLine.split(";");
    if (Number.parseInt(fields[3], 10) === 0) continue;
    const codePoint = Number.parseInt(fields[0], 16);
    requests.push({
      id: `bidi-skeleton:l3-combining:U+${codePoint.toString(16).toUpperCase()}`,
      operation: "reference_bidi_skeleton",
      arguments: { text: taggedScalar(`A${String.fromCodePoint(codePoint)}א`), direction: "RTL" }
    });
    combiningCodePointCount += 1;
  }

  const conformanceManifestBytes = readFileSync(path.join(dataRoot, "CONFORMANCE_MANIFEST.json"));
  const conformanceManifest = JSON.parse(conformanceManifestBytes.toString("utf8"));
  const bidiCharacterEntry = conformanceManifest.files.find(
    (entry) => entry.path.endsWith("/BidiCharacterTest.txt.gz")
  );
  const bidiTestEntry = conformanceManifest.files.find(
    (entry) => entry.path.endsWith("/BidiTest.txt.gz")
  );
  for (const entry of [bidiCharacterEntry, bidiTestEntry]) {
    const bytes = readFileSync(path.join(dataRoot, entry.path));
    if (bytes.length !== entry.bytes || rawSha256(bytes) !== entry.sha256) {
      throw new Error(`${entry.path} does not match the pinned conformance manifest`);
    }
  }

  const bidiCharacterCorpus = gunzipSync(
    readFileSync(path.join(dataRoot, bidiCharacterEntry.path))
  ).toString("utf8");
  let bidiCharacterFullCaseCount = 0;
  let bidiCharacterSampleCount = 0;
  for (const sourceLine of bidiCharacterCorpus.split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const fields = content.split(";").map((field) => field.trim());
    if (bidiCharacterFullCaseCount % 128 === 0) {
      const value = fields[0].split(/\s+/u).filter(Boolean)
        .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("");
      requests.push({
        id: `bidi-skeleton:BidiCharacterTest:${bidiCharacterFullCaseCount}`,
        operation: "reference_bidi_skeleton",
        arguments: {
          text: taggedScalar(value),
          direction: ["LTR", "RTL", "first_strong"][Number(fields[1])]
        }
      });
      bidiCharacterSampleCount += 1;
    }
    bidiCharacterFullCaseCount += 1;
  }
  if (bidiCharacterFullCaseCount !== 91707) {
    throw new Error(`expected 91707 BidiCharacterTest cases, received ${bidiCharacterFullCaseCount}`);
  }

  const typeCharacter = Object.freeze({
    L: "A", R: "א", EN: "0", ES: "+", ET: "#", AN: "٠", CS: ",", B: "\u2029",
    S: "\t", WS: " ", ON: "!", BN: "\u00AD", NSM: "\u036F", AL: "ە",
    LRO: "\u202D", RLO: "\u202E", LRE: "\u202A", RLE: "\u202B", PDF: "\u202C",
    LRI: "\u2066", RLI: "\u2067", FSI: "\u2068", PDI: "\u2069"
  });
  const bidiTestCorpus = gunzipSync(readFileSync(path.join(dataRoot, bidiTestEntry.path))).toString("utf8");
  let bidiTestRowCount = 0;
  let bidiTestParagraphModeCaseCount = 0;
  let bidiTestSampleCount = 0;
  for (const sourceLine of bidiTestCorpus.split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "" || content.startsWith("@")) continue;
    const [typesValue, modesValue] = content.split(";").map((field) => field.trim());
    const modes = Number(modesValue);
    const enabled = [[1, "first_strong"], [2, "LTR"], [4, "RTL"]]
      .filter(([bit]) => (modes & bit) !== 0);
    bidiTestParagraphModeCaseCount += enabled.length;
    if (bidiTestRowCount % 256 === 0) {
      const value = typesValue.split(/\s+/u).map((type) => typeCharacter[type]).join("");
      for (const [, direction] of enabled) {
        requests.push({
          id: `bidi-skeleton:BidiTest:${bidiTestRowCount}:${direction}`,
          operation: "reference_bidi_skeleton",
          arguments: { text: taggedScalar(value), direction }
        });
        bidiTestSampleCount += 1;
      }
    }
    bidiTestRowCount += 1;
  }
  if (bidiTestParagraphModeCaseCount !== 770241) {
    throw new Error(
      `expected 770241 BidiTest paragraph-mode cases, received ${bidiTestParagraphModeCaseCount}`
    );
  }

  const sequences = [
    "", "ASCII", "אבגabc", "A\u2029B", "\u2029", "A1<שׂ", "Αשֺ>1",
    "A\u2067א(1)\u2069Z", "א\u2066A[1]\u2069ב", "\u202A\t", "\u2329א\u232A",
    "👨‍👩‍👧‍👦א", "\u{10D40}A", "\u{1E6C0}א"
  ];
  for (const [index, value] of sequences.entries()) {
    for (const direction of directions) {
      requests.push({
        id: `bidi-skeleton:sequence:${index}:${direction}`,
        operation: "reference_bidi_skeleton",
        arguments: { text: taggedScalar(value), direction }
      });
    }
  }

  return {
    requests,
    coverage: {
      sourceManifestSha256: rawSha256(manifestBytes),
      bidiClassSourcePath: sourcePaths.bidiClass,
      bidiClassSourceSha256: sources.bidiClass.entry.sha256,
      scalarBoundaryCodePointCount: scalarBoundaries.length,
      scalarBoundaryDirectionCaseCount: scalarBoundaries.length * directions.length,
      bidiBracketsSourcePath: sourcePaths.bidiBrackets,
      bidiBracketsSourceSha256: sources.bidiBrackets.entry.sha256,
      bracketEntryCount,
      bracketDirectionCaseCount: bracketEntryCount * directions.length,
      bidiMirroringSourcePath: sourcePaths.bidiMirroring,
      bidiMirroringSourceSha256: sources.bidiMirroring.entry.sha256,
      mirroringEntryCount,
      unicodeDataSourcePath: sourcePaths.unicodeData,
      unicodeDataSourceSha256: sources.unicodeData.entry.sha256,
      combiningCodePointCount,
      conformanceManifestSha256: rawSha256(conformanceManifestBytes),
      bidiTestCompressedSha256: bidiTestEntry.sha256,
      bidiTestParagraphModeCaseCount,
      bidiTestSampleCount,
      bidiCharacterTestCompressedSha256: bidiCharacterEntry.sha256,
      bidiCharacterTestCaseCount: bidiCharacterFullCaseCount,
      bidiCharacterTestSampleCount: bidiCharacterSampleCount,
      sequenceCaseCount: sequences.length * directions.length,
      totalCaseCount: requests.length
    }
  };
}

function buildConfusableComparisonRequests() {
  const dataRoot = path.join(ROOT, "vendor", "unicode", "17.0.0");
  const manifestBytes = readFileSync(path.join(dataRoot, "MANIFEST.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const sourcePaths = {
    scripts: "ucd/Scripts.txt",
    scriptExtensions: "ucd/ScriptExtensions.txt",
    propertyValueAliases: "ucd/PropertyValueAliases.txt",
    confusables: "security/confusables.txt"
  };
  const sources = {};
  for (const [name, relativePath] of Object.entries(sourcePaths)) {
    const bytes = readFileSync(path.join(dataRoot, relativePath));
    const entry = manifest.files.find((item) => item.path === relativePath);
    if (manifest.unicodeVersion !== "17.0.0" || manifest.uts39Revision !== 32
      || !entry || entry.bytes !== bytes.length || entry.sha256 !== rawSha256(bytes)) {
      throw new Error(`${relativePath} does not match the pinned Unicode manifest`);
    }
    sources[name] = { bytes, entry };
  }

  const directions = ["LTR", "RTL", "FS"];
  const requests = [];
  const boundarySet = new Set();
  for (const name of ["scripts", "scriptExtensions"]) {
    for (const sourceLine of sources[name].bytes.toString("utf8").split(/\r?\n/u)) {
      const content = sourceLine.split("#", 1)[0].trim();
      if (content === "") continue;
      const [first, last = first] = content.split(";", 1)[0].trim().split("..");
      boundarySet.add(Number.parseInt(first, 16));
      boundarySet.add(Number.parseInt(last, 16));
    }
  }
  const boundaries = [...boundarySet]
    .filter((codePoint) => !(codePoint >= 0xd800 && codePoint <= 0xdfff))
    .sort((left, right) => left - right);
  for (const [index, codePoint] of boundaries.entries()) {
    const value = String.fromCodePoint(codePoint);
    requests.push({
      id: `confusable-comparison:script-boundary:U+${codePoint.toString(16).toUpperCase()}`,
      operation: "reference_confusable_comparison",
      arguments: {
        text: taggedScalar(value),
        comparison: taggedScalar(value),
        direction: directions[index % directions.length]
      }
    });
  }

  let confusableMappingCount = 0;
  for (const sourceLine of sources.confusables.bytes.toString("utf8").split(/\r?\n/u)) {
    const content = sourceLine.split("#", 1)[0].trim();
    if (content === "") continue;
    const fields = content.split(";").map((field) => field.trim());
    const source = fields[0].split(/\s+/u).filter(Boolean);
    if (fields[2] !== "MA" || source.length !== 1) throw new Error("unsupported confusables row");
    const left = String.fromCodePoint(Number.parseInt(source[0], 16));
    const right = fields[1].split(/\s+/u).filter(Boolean)
      .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("");
    requests.push({
      id: `confusable-comparison:mapping:${confusableMappingCount}`,
      operation: "reference_confusable_comparison",
      arguments: {
        text: taggedScalar(left),
        comparison: taggedScalar(right),
        direction: directions[confusableMappingCount % directions.length]
      }
    });
    confusableMappingCount += 1;
  }

  const pairs = [
    ["", ""], [" ", "!"], ["paypal", "pаypal"], ["same", "same"],
    ["A", "B"], ["一", "ひ"], ["ひ", "カ"], ["한", "一"], ["ㄅ", "一"],
    ["Aא", "Aא"], ["☝", "☝️"], ["A1<שׂ", "Αשֺ>1"],
    ["A\u2029B", "B\u2029A"], ["\u2329א\u232A", "\u3008א\u3009"]
  ];
  for (const [index, [left, right]] of pairs.entries()) {
    for (const direction of directions) {
      requests.push({
        id: `confusable-comparison:sequence:${index}:${direction}`,
        operation: "reference_confusable_comparison",
        arguments: { text: taggedScalar(left), comparison: taggedScalar(right), direction }
      });
    }
  }

  return {
    requests,
    coverage: {
      sourceManifestSha256: rawSha256(manifestBytes),
      scriptsSourcePath: sourcePaths.scripts,
      scriptsSourceSha256: sources.scripts.entry.sha256,
      scriptExtensionsSourcePath: sourcePaths.scriptExtensions,
      scriptExtensionsSourceSha256: sources.scriptExtensions.entry.sha256,
      propertyValueAliasesSourcePath: sourcePaths.propertyValueAliases,
      propertyValueAliasesSourceSha256: sources.propertyValueAliases.entry.sha256,
      scriptBoundaryCaseCount: boundaries.length,
      confusablesSourcePath: sourcePaths.confusables,
      confusablesSourceSha256: sources.confusables.entry.sha256,
      confusableMappingCaseCount: confusableMappingCount,
      sequenceCaseCount: pairs.length * directions.length,
      totalCaseCount: requests.length
    }
  };
}

function buildSecurityRequests() {
  const dataRoot = path.join(ROOT, "vendor", "unicode", "17.0.0");
  const manifestBytes = readFileSync(path.join(dataRoot, "MANIFEST.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const sourcePaths = {
    identifierStatus: "security/IdentifierStatus.txt",
    identifierType: "security/IdentifierType.txt",
    derivedCore: "ucd/DerivedCoreProperties.txt",
    propList: "ucd/PropList.txt",
    generalCategory: "ucd/extracted/DerivedGeneralCategory.txt",
    unicodeData: "ucd/UnicodeData.txt",
    scripts: "ucd/Scripts.txt",
    scriptExtensions: "ucd/ScriptExtensions.txt",
    bidiClass: "ucd/extracted/DerivedBidiClass.txt",
    nfkcCasefold: "ucd/DerivedNormalizationProps.txt",
    confusables: "security/confusables.txt"
  };
  const sources = {};
  for (const [name, relativePath] of Object.entries(sourcePaths)) {
    const bytes = readFileSync(path.join(dataRoot, relativePath));
    const entry = manifest.files.find((item) => item.path === relativePath);
    if (manifest.unicodeVersion !== "17.0.0" || manifest.uts39Revision !== 32
      || !entry || entry.bytes !== bytes.length || entry.sha256 !== rawSha256(bytes)) {
      throw new Error(`${relativePath} does not match the pinned Unicode manifest`);
    }
    sources[name] = { bytes, entry };
  }

  const parseRows = (bytes) => bytes.toString("utf8").split(/\r?\n/u).flatMap((sourceLine) => {
    const content = sourceLine.split("#", 1)[0].trim();
    return content === "" ? [] : [content.split(";").map((field) => field.trim())];
  });
  const addRangeBoundaries = (set, rows, predicate = () => true) => {
    for (const fields of rows) {
      if (!predicate(fields)) continue;
      const [first, last = first] = fields[0].split("..");
      set.add(Number.parseInt(first, 16));
      set.add(Number.parseInt(last, 16));
    }
  };
  const validScalars = (set) => [...set]
    .filter((codePoint) => Number.isInteger(codePoint)
      && codePoint >= 0 && codePoint <= 0x10ffff
      && !(codePoint >= 0xd800 && codePoint <= 0xdfff))
    .sort((left, right) => left - right);

  const propertyBoundaries = new Set();
  addRangeBoundaries(propertyBoundaries, parseRows(sources.identifierStatus.bytes));
  addRangeBoundaries(propertyBoundaries, parseRows(sources.identifierType.bytes));
  addRangeBoundaries(
    propertyBoundaries,
    parseRows(sources.derivedCore.bytes),
    (fields) => ["Default_Ignorable_Code_Point", "XID_Start", "XID_Continue"].includes(fields[1])
  );
  addRangeBoundaries(
    propertyBoundaries,
    parseRows(sources.propList.bytes),
    (fields) => fields[1] === "Bidi_Control"
  );
  addRangeBoundaries(
    propertyBoundaries,
    parseRows(sources.generalCategory.bytes),
    (fields) => fields[1] === "Cf"
  );
  addRangeBoundaries(propertyBoundaries, parseRows(sources.scripts.bytes));
  addRangeBoundaries(propertyBoundaries, parseRows(sources.scriptExtensions.bytes));
  addRangeBoundaries(propertyBoundaries, parseRows(sources.bidiClass.bytes));
  for (const line of sources.unicodeData.bytes.toString("utf8").split(/\r?\n/u)) {
    if (line === "") continue;
    const fields = line.split(";");
    if (fields[6] !== "") propertyBoundaries.add(Number.parseInt(fields[0], 16));
  }
  const boundaryScalars = validScalars(propertyBoundaries);
  const requests = boundaryScalars.map((codePoint) => ({
    id: `security:property-boundary:U+${codePoint.toString(16).toUpperCase()}`,
    operation: "security",
    arguments: {
      text: taggedScalar(String.fromCodePoint(codePoint)),
      mode: "identifier",
      profile: "uts39_general_security",
      detailLimit: 1
    }
  }));

  const freeTextBoundaries = new Set();
  addRangeBoundaries(
    freeTextBoundaries,
    parseRows(sources.derivedCore.bytes),
    (fields) => fields[1] === "Default_Ignorable_Code_Point"
  );
  addRangeBoundaries(
    freeTextBoundaries,
    parseRows(sources.propList.bytes),
    (fields) => fields[1] === "Bidi_Control"
  );
  addRangeBoundaries(
    freeTextBoundaries,
    parseRows(sources.generalCategory.bytes),
    (fields) => fields[1] === "Cf"
  );
  const freeTextScalars = validScalars(freeTextBoundaries);
  for (const codePoint of freeTextScalars) {
    requests.push({
      id: `security:free-text-boundary:U+${codePoint.toString(16).toUpperCase()}`,
      operation: "security",
      arguments: {
        text: taggedScalar(String.fromCodePoint(codePoint)),
        mode: "free_text",
        detailLimit: 1
      }
    });
  }

  const xidBoundaries = new Set();
  addRangeBoundaries(xidBoundaries, parseRows(sources.identifierStatus.bytes));
  addRangeBoundaries(
    xidBoundaries,
    parseRows(sources.derivedCore.bytes),
    (fields) => ["XID_Start", "XID_Continue"].includes(fields[1])
  );
  const xidScalars = validScalars(xidBoundaries);
  for (const codePoint of xidScalars) {
    requests.push({
      id: `security:xid-boundary:U+${codePoint.toString(16).toUpperCase()}`,
      operation: "security",
      arguments: {
        text: taggedScalar(String.fromCodePoint(codePoint)),
        mode: "identifier",
        profile: "uax31_xid",
        detailLimit: 0
      }
    });
  }

  let nfkcCasefoldCaseCount = 0;
  for (const fields of parseRows(sources.nfkcCasefold.bytes)) {
    if (fields[1] !== "NFKC_CF") continue;
    const [first, last = first] = fields[0].split("..");
    for (let codePoint = Number.parseInt(first, 16); codePoint <= Number.parseInt(last, 16); codePoint += 1) {
      if (codePoint >= 0xd800 && codePoint <= 0xdfff) continue;
      requests.push({
        id: `security:nfkc-casefold:U+${codePoint.toString(16).toUpperCase()}`,
        operation: "security",
        arguments: {
          text: taggedScalar(String.fromCodePoint(codePoint)),
          mode: "identifier",
          profile: "uax31_nfkc_casefold",
          detailLimit: 0
        }
      });
      nfkcCasefoldCaseCount += 1;
    }
  }

  const directions = ["LTR", "RTL", "FS"];
  let confusableEnvelopeCaseCount = 0;
  for (const fields of parseRows(sources.confusables.bytes)) {
    const source = fields[0].split(/\s+/u).filter(Boolean);
    if (fields[2] !== "MA" || source.length !== 1) throw new Error("unsupported confusables row");
    const left = String.fromCodePoint(Number.parseInt(source[0], 16));
    const right = fields[1].split(/\s+/u).filter(Boolean)
      .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("");
    requests.push({
      id: `security:confusable-envelope:${confusableEnvelopeCaseCount}`,
      operation: "security",
      arguments: {
        text: taggedScalar(left),
        mode: "identifier",
        profile: "uts39_general_security",
        comparison: taggedScalar(right),
        confusableDirection: directions[confusableEnvelopeCaseCount % directions.length],
        detailLimit: 0
      }
    });
    confusableEnvelopeCaseCount += 1;
  }

  const sequences = [
    ["", "free_text", null],
    ["", "identifier", "uax31_xid"],
    ["abc", "identifier", "uts39_general_security"],
    ["é", "identifier", "uts39_general_security"],
    ["a一", "identifier", "uts39_general_security"],
    ["aا", "identifier", "uts39_general_security"],
    ["aа", "identifier", "uts39_general_security"],
    ["😀", "identifier", "uts39_general_security"],
    ["1١", "identifier", "uts39_general_security"],
    ["_a", "identifier", "uax31_xid"],
    ["A\u030a", "identifier", "uax31_nfkc_casefold"],
    ["a\u202e\u200db", "free_text", null],
    ["Aא😀一١", "identifier", "uts39_general_security"]
  ];
  for (const [index, [text, mode, profile]] of sequences.entries()) {
    requests.push({
      id: `security:sequence:${index}`,
      operation: "security",
      arguments: {
        text: taggedScalar(text),
        mode,
        ...(profile === null ? {} : { profile }),
        detailLimit: index === sequences.length - 1 ? 2 : 128
      }
    });
  }

  const negativeRequests = [
    {
      id: "security:negative:unknown-field",
      arguments: { text: taggedScalar("A"), mode: "free_text", extra: true }
    },
    {
      id: "security:negative:free-text-profile",
      arguments: { text: taggedScalar("A"), mode: "free_text", profile: "uax31_xid" }
    },
    {
      id: "security:negative:missing-profile",
      arguments: { text: taggedScalar("A"), mode: "identifier" }
    },
    {
      id: "security:negative:direction-only",
      arguments: {
        text: taggedScalar("A"), mode: "identifier", profile: "uax31_xid",
        confusableDirection: "LTR"
      }
    },
    {
      id: "security:negative:comparison-only",
      arguments: {
        text: taggedScalar("A"), mode: "identifier", profile: "uax31_xid",
        comparison: taggedScalar("A")
      }
    },
    {
      id: "security:negative:detail-over-limit",
      arguments: { text: taggedScalar("A"), mode: "free_text", detailLimit: 129 }
    },
    {
      id: "security:negative:detail-wrong-type",
      arguments: { text: taggedScalar("A"), mode: "free_text", detailLimit: "1" }
    },
    {
      id: "security:negative:bad-mode",
      arguments: { text: taggedScalar("A"), mode: "bad" }
    },
    {
      id: "security:negative:bad-profile",
      arguments: { text: taggedScalar("A"), mode: "identifier", profile: "bad" }
    },
    {
      id: "security:negative:bad-direction",
      arguments: {
        text: taggedScalar("A"), mode: "identifier", profile: "uax31_xid",
        comparison: taggedScalar("A"), confusableDirection: "bad"
      }
    },
    {
      id: "security:negative:invalid-text-unicode",
      arguments: { text: taggedUnits([0xd800]), mode: "free_text" }
    },
    {
      id: "security:negative:invalid-comparison-unicode",
      arguments: {
        text: taggedScalar("A"), mode: "identifier", profile: "uax31_xid",
        comparison: taggedUnits([0xd800]), confusableDirection: "LTR"
      }
    },
    {
      id: "security:negative:text-byte-limit",
      arguments: { text: taggedScalar("a".repeat(4097)), mode: "free_text" }
    },
    {
      id: "security:negative:combined-byte-limit",
      arguments: {
        text: taggedScalar("a".repeat(2049)), mode: "identifier", profile: "uax31_xid",
        comparison: taggedScalar("b".repeat(2049)), confusableDirection: "LTR"
      }
    }
  ];
  requests.push(...negativeRequests.map((entry) => ({ ...entry, operation: "security" })));

  return {
    requests,
    coverage: {
      sourceManifestSha256: rawSha256(manifestBytes),
      sourceFiles: Object.fromEntries(Object.entries(sourcePaths).map(([name, relativePath]) => [name, {
        path: relativePath,
        sha256: sources[name].entry.sha256
      }])),
      propertyBoundaryCaseCount: boundaryScalars.length,
      freeTextBoundaryCaseCount: freeTextScalars.length,
      xidProfileCaseCount: xidScalars.length,
      nfkcCasefoldProfileCaseCount: nfkcCasefoldCaseCount,
      confusableEnvelopeCaseCount,
      sequenceCaseCount: sequences.length,
      negativeCaseCount: negativeRequests.length,
      totalCaseCount: requests.length
    }
  };
}

function buildSourceDiagnosticsRequests() {
  const dataRoot = path.join(ROOT, "vendor", "unicode", "17.0.0");
  const manifestBytes = readFileSync(path.join(dataRoot, "MANIFEST.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const sourcePaths = {
    derivedCore: "ucd/DerivedCoreProperties.txt",
    propList: "ucd/PropList.txt",
    generalCategory: "ucd/extracted/DerivedGeneralCategory.txt",
    confusables: "security/confusables.txt"
  };
  const sources = {};
  for (const [name, relativePath] of Object.entries(sourcePaths)) {
    const bytes = readFileSync(path.join(dataRoot, relativePath));
    const entry = manifest.files.find((item) => item.path === relativePath);
    if (manifest.unicodeVersion !== "17.0.0" || manifest.uts39Revision !== 32
      || !entry || entry.bytes !== bytes.length || entry.sha256 !== rawSha256(bytes)) {
      throw new Error(`${relativePath} does not match the pinned Unicode manifest`);
    }
    sources[name] = { bytes, entry };
  }
  const parseRows = (bytes) => bytes.toString("utf8").split(/\r?\n/u).flatMap((sourceLine) => {
    const content = sourceLine.split("#", 1)[0].trim();
    return content === "" ? [] : [content.split(";").map((field) => field.trim())];
  });
  const scalarLength = (value) => value.length;
  const token = (value) => ({ kind: "token", startUtf16: 0, endUtf16: scalarLength(value) });
  const request = (id, source, spans, confusableDirection = "LTR", detailLimit = 128) => ({
    id: `source-diagnostics:${id}`,
    operation: "security",
    arguments: {
      source: taggedScalar(source), mode: "source", spans, confusableDirection, detailLimit
    }
  });
  const requests = [];

  const signalBoundaries = new Set();
  for (const fields of parseRows(sources.derivedCore.bytes)) {
    if (fields[1] !== "Default_Ignorable_Code_Point") continue;
    const [first, last = first] = fields[0].split("..");
    signalBoundaries.add(Number.parseInt(first, 16));
    signalBoundaries.add(Number.parseInt(last, 16));
  }
  for (const fields of parseRows(sources.propList.bytes)) {
    if (fields[1] !== "Bidi_Control") continue;
    const [first, last = first] = fields[0].split("..");
    signalBoundaries.add(Number.parseInt(first, 16));
    signalBoundaries.add(Number.parseInt(last, 16));
  }
  for (const fields of parseRows(sources.generalCategory.bytes)) {
    if (fields[1] !== "Cf") continue;
    const [first, last = first] = fields[0].split("..");
    signalBoundaries.add(Number.parseInt(first, 16));
    signalBoundaries.add(Number.parseInt(last, 16));
  }
  const signalScalars = [...signalBoundaries]
    .filter((codePoint) => !(codePoint >= 0xd800 && codePoint <= 0xdfff))
    .sort((left, right) => left - right);
  for (const [index, codePoint] of signalScalars.entries()) {
    const source = String.fromCodePoint(codePoint);
    requests.push(request(
      `signal-boundary:U+${codePoint.toString(16).toUpperCase()}`,
      source,
      [token(source)],
      ["LTR", "RTL", "FS"][index % 3],
      index % 2
    ));
  }

  const coordinateSource = "A😀e\u0301\r\nB\nC\rD\u0085E\u2028F\u2029G\u202E";
  const coordinateSpans = [];
  let utf16 = 0;
  for (const character of coordinateSource) {
    coordinateSpans.push({ kind: "token", startUtf16: utf16, endUtf16: utf16 + character.length });
    utf16 += character.length;
  }
  requests.push(request("coordinate-and-line-endings", coordinateSource, coordinateSpans, "FS", 128));
  requests.push(request("empty", "", [], "LTR", 0));
  requests.push(request("normal-endings-before-abnormal-truncation", "\n\n\n\r\u0085\u2028\u2029", [], "LTR", 1));
  requests.push(request("detail-zero", "\u202E\r", [], "RTL", 0));
  requests.push(request(
    "different-scopes",
    "A Ａ",
    [
      { kind: "identifier", startUtf16: 0, endUtf16: 1, scope: "left" },
      { kind: "identifier", startUtf16: 2, endUtf16: 3, scope: "right" }
    ],
    "LTR",
    128
  ));
  requests.push(request(
    "same-text-is-not-a-pair",
    "A A",
    [
      { kind: "identifier", startUtf16: 0, endUtf16: 1, scope: "file" },
      { kind: "identifier", startUtf16: 2, endUtf16: 3, scope: "file" }
    ],
    "LTR",
    128
  ));
  const repeatedSource = Array.from({ length: 16 }, (_, index) => index % 2 === 0 ? "A" : "Ａ").join(" ");
  const repeatedSpans = [];
  for (let index = 0; index < 16; index += 1) {
    repeatedSpans.push({
      kind: "identifier", startUtf16: index * 2, endUtf16: index * 2 + 1, scope: "file"
    });
  }
  requests.push(request("pair-count-and-truncation", repeatedSource, repeatedSpans, "LTR", 3));

  let confusableEnvelopeCaseCount = 0;
  for (const fields of parseRows(sources.confusables.bytes)) {
    const leftUnits = fields[0].split(/\s+/u).filter(Boolean);
    if (fields[2] !== "MA" || leftUnits.length !== 1) throw new Error("unsupported confusables row");
    const left = String.fromCodePoint(Number.parseInt(leftUnits[0], 16));
    const right = fields[1].split(/\s+/u).filter(Boolean)
      .map((item) => String.fromCodePoint(Number.parseInt(item, 16))).join("");
    const source = `${left} ${right}`;
    requests.push(request(
      `confusable-envelope:${confusableEnvelopeCaseCount}`,
      source,
      [
        { kind: "identifier", startUtf16: 0, endUtf16: left.length, scope: "scope" },
        {
          kind: "identifier",
          startUtf16: left.length + 1,
          endUtf16: left.length + 1 + right.length,
          scope: "scope"
        }
      ],
      ["LTR", "RTL", "FS"][confusableEnvelopeCaseCount % 3],
      confusableEnvelopeCaseCount % 2
    ));
    confusableEnvelopeCaseCount += 1;
  }

  const base = {
    source: taggedScalar("A"), mode: "source", spans: [], confusableDirection: "LTR"
  };
  const negativeRequests = [
    ["unknown-field", { ...base, extra: true }],
    ["missing-source", { mode: "source", spans: [], confusableDirection: "LTR" }],
    ["missing-spans", { source: taggedScalar("A"), mode: "source", confusableDirection: "LTR" }],
    ["missing-direction", { source: taggedScalar("A"), mode: "source", spans: [] }],
    ["bad-direction", { ...base, confusableDirection: "bad" }],
    ["detail-over-limit", { ...base, detailLimit: 129 }],
    ["detail-wrong-type", { ...base, detailLimit: "1" }],
    ["spans-wrong-type", { ...base, spans: {} }],
    ["spans-over-limit", { ...base, spans: Array.from({ length: 129 }, () => ({
      kind: "token", startUtf16: 0, endUtf16: 1
    })) }],
    ["span-not-object", { ...base, spans: [null] }],
    ["span-bad-kind", { ...base, spans: [{ kind: "bad", startUtf16: 0, endUtf16: 1 }] }],
    ["span-unknown-field", { ...base, spans: [{
      kind: "token", startUtf16: 0, endUtf16: 1, scope: "file"
    }] }],
    ["span-missing-end", { ...base, spans: [{ kind: "token", startUtf16: 0 }] }],
    ["identifier-missing-scope", { ...base, spans: [{
      kind: "identifier", startUtf16: 0, endUtf16: 1
    }] }],
    ["start-wrong-type", { ...base, spans: [{
      kind: "token", startUtf16: "0", endUtf16: 1
    }] }],
    ["end-wrong-type", { ...base, spans: [{
      kind: "token", startUtf16: 0, endUtf16: 1.5
    }] }],
    ["start-negative", { ...base, spans: [{ kind: "token", startUtf16: -1, endUtf16: 1 }] }],
    ["end-over-source", { ...base, spans: [{ kind: "token", startUtf16: 0, endUtf16: 2 }] }],
    ["empty-span", { ...base, spans: [{ kind: "token", startUtf16: 0, endUtf16: 0 }] }],
    ["reversed-span", { ...base, spans: [{ kind: "token", startUtf16: 1, endUtf16: 0 }] }],
    ["surrogate-interior-start", {
      source: taggedScalar("😀"), mode: "source",
      spans: [{ kind: "token", startUtf16: 1, endUtf16: 2 }], confusableDirection: "LTR"
    }],
    ["surrogate-interior-end", {
      source: taggedScalar("😀"), mode: "source",
      spans: [{ kind: "token", startUtf16: 0, endUtf16: 1 }], confusableDirection: "LTR"
    }],
    ["scope-wrong-type", { ...base, spans: [{
      kind: "identifier", startUtf16: 0, endUtf16: 1, scope: 1
    }] }],
    ["scope-empty", { ...base, spans: [{
      kind: "identifier", startUtf16: 0, endUtf16: 1, scope: ""
    }] }],
    ["scope-over-limit", { ...base, spans: [{
      kind: "identifier", startUtf16: 0, endUtf16: 1, scope: "s".repeat(65)
    }] }],
    ["scope-astral-over-limit", { ...base, spans: [{
      kind: "identifier", startUtf16: 0, endUtf16: 1, scope: "😀".repeat(33)
    }] }],
    ["invalid-source-unicode", {
      source: taggedUnits([0xd800]), mode: "source", spans: [], confusableDirection: "LTR"
    }],
    ["source-byte-limit", {
      source: taggedScalar("a".repeat(4097)), mode: "source", spans: [], confusableDirection: "LTR"
    }],
    ["complete-result-budget", {
      source: taggedScalar("a".repeat(4096)), mode: "source",
      spans: Array.from({ length: 128 }, () => ({
        kind: "identifier", startUtf16: 0, endUtf16: 4096, scope: "file"
      })),
      confusableDirection: "LTR", detailLimit: 0
    }]
  ];
  requests.push(...negativeRequests.map(([id, requestArguments]) => ({
    id: `source-diagnostics:negative:${id}`, operation: "security", arguments: requestArguments
  })));

  return {
    requests,
    coverage: {
      sourceManifestSha256: rawSha256(manifestBytes),
      sourceFiles: Object.fromEntries(Object.entries(sourcePaths).map(([name, relativePath]) => [name, {
        path: relativePath, sha256: sources[name].entry.sha256
      }])),
      signalBoundaryCaseCount: signalScalars.length,
      confusableEnvelopeCaseCount,
      sequenceCaseCount: requests.length - signalScalars.length
        - confusableEnvelopeCaseCount - negativeRequests.length,
      negativeCaseCount: negativeRequests.length,
      totalCaseCount: requests.length
    }
  };
}

function buildNamespaceRequests(corpus) {
  const requests = corpus.cases
    .filter((entry) => entry.operation === "namespace_integrity"
      && !entry.arguments.relations.some((relation) => relation?.kind === "declared_collation"))
    .map((entry) => ({
      id: `corpus:${entry.id}`,
      operation: "namespace_integrity",
      arguments: entry.arguments
    }));
  const canonicalCaseCount = requests.length;
  const simpleItems = [
    { id: "exact-a", text: taggedScalar("same"), scope: "alpha" },
    { id: "exact-b", text: taggedScalar("same"), scope: "alpha" },
    { id: "nfc-a", text: taggedScalar("é"), scope: "alpha" },
    { id: "nfc-b", text: taggedScalar("e\u0301"), scope: "alpha" },
    { id: "nfkc-a", text: taggedScalar("①"), scope: "alpha" },
    { id: "nfkc-b", text: taggedScalar("1"), scope: "alpha" },
    { id: "fold-a", text: taggedScalar("Straße"), scope: "alpha" },
    { id: "fold-b", text: taggedScalar("strasse"), scope: "alpha" },
    { id: "confusable-a", text: taggedScalar("pаypal"), scope: "alpha" },
    { id: "confusable-b", text: taggedScalar("paypal"), scope: "alpha" },
    { id: "isolated", text: taggedScalar("only"), scope: "beta" }
  ];
  for (const direction of ["LTR", "RTL", "FS"]) {
    requests.push({
      id: `namespace:simple-relations:${direction}`,
      operation: "namespace_integrity",
      arguments: {
        items: simpleItems,
        relations: ["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable"],
        confusableDirection: direction
      }
    });
  }
  const simpleDirectionCaseCount = 3;

  requests.push({
    id: "namespace:utf16-order",
    operation: "namespace_integrity",
    arguments: {
      items: [
        { id: "\ue000", text: taggedScalar("first"), scope: "\ue000" },
        { id: "\ue001", text: taggedScalar("first"), scope: "\ue000" },
        { id: "𐀀", text: taggedScalar("second"), scope: "𐀀" },
        { id: "𐀁", text: taggedScalar("second"), scope: "𐀀" }
      ],
      relations: ["exact"]
    }
  });
  const utf16OrderingCaseCount = 1;

  const commonOptionNames = [
    "checkBidi", "checkHyphens", "checkJoiners", "ignoreInvalidPunycode",
    "transitionalProcessing", "useSTD3ASCIIRules"
  ];
  let uts46ConfigurationCaseCount = 0;
  for (const [action, optionNames] of [
    ["to_ascii", [...commonOptionNames, "verifyDNSLength"]],
    ["to_unicode", commonOptionNames]
  ]) {
    for (let mask = 0; mask < 2 ** optionNames.length; mask += 1) {
      requests.push({
        id: `namespace:uts46:${action}:${mask}`,
        operation: "namespace_integrity",
        arguments: {
          items: [
            { id: "unicode", text: taggedScalar("faß.de"), scope: "domains" },
            { id: "ascii", text: taggedScalar("xn--fa-hia.de"), scope: "domains" },
            { id: "isolated", text: taggedScalar("example.com"), scope: "domains" }
          ],
          relations: [{
            kind: "protocol",
            profile: "uts46_domain",
            action,
            options: Object.fromEntries(optionNames.map((name, bit) => [name, (mask & (1 << bit)) !== 0]))
          }]
        }
      });
      uts46ConfigurationCaseCount += 1;
    }
  }

  const precisCases = [
    ["precis_username_case_mapped", "Ｕser", "user"],
    ["precis_username_case_preserved", "Ｕser", "User"],
    ["precis_opaque_string", "Ａ B", "A B"]
  ];
  for (const [profile, left, right] of precisCases) {
    requests.push({
      id: `namespace:precis:${profile}`,
      operation: "namespace_integrity",
      arguments: {
        items: [
          { id: "mapped", text: taggedScalar(left), scope: "names" },
          { id: "reference", text: taggedScalar(right), scope: "names" }
        ],
        relations: [{ kind: "protocol", profile, action: "enforce" }]
      }
    });
  }
  const precisProfileCaseCount = precisCases.length;

  const strictUts46 = {
    checkBidi: true,
    checkHyphens: true,
    checkJoiners: true,
    ignoreInvalidPunycode: false,
    transitionalProcessing: false,
    useSTD3ASCIIRules: true,
    verifyDNSLength: true
  };
  requests.push({
    id: "namespace:composed-protocol-relations",
    operation: "namespace_integrity",
    arguments: {
      items: [
        { id: "width", text: taggedScalar("Ｕser"), scope: "names" },
        { id: "ascii", text: taggedScalar("User"), scope: "names" }
      ],
      relations: [
        { kind: "protocol", profile: "uts46_domain", action: "to_ascii", options: strictUts46 },
        { kind: "protocol", profile: "uts46_domain", action: "to_ascii", options: { ...strictUts46, checkBidi: false } },
        { kind: "protocol", profile: "precis_username_case_mapped", action: "enforce" },
        { kind: "protocol", profile: "precis_username_case_preserved", action: "enforce" },
        { kind: "protocol", profile: "precis_opaque_string", action: "enforce" }
      ]
    }
  });
  const composedProtocolRelationCaseCount = 1;

  const base = {
    items: [{ id: "one", text: taggedScalar("text"), scope: "scope" }],
    relations: ["exact"]
  };
  const protocol = {
    kind: "protocol", profile: "uts46_domain", action: "to_ascii", options: strictUts46
  };
  const without = (value, key) => Object.fromEntries(Object.entries(value).filter(([name]) => name !== key));
  const negativeCases = [
    ["arguments-not-object", null],
    ["unknown-argument", { ...base, extra: true }],
    ["missing-items", without(base, "items")],
    ["missing-relations", without(base, "relations")],
    ["items-not-array", { ...base, items: null }],
    ["relations-not-array", { ...base, relations: null }],
    ["items-over-limit", { ...base, items: Array.from({ length: 513 }, (_, index) => ({
      id: `item-${index}`, text: taggedScalar(""), scope: "scope"
    })) }],
    ["relations-over-limit", { ...base, relations: ["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable", "exact"] }],
    ["empty-relations", { ...base, relations: [] }],
    ["bad-simple-relation", { ...base, relations: ["semantic"] }],
    ["relation-not-object", { ...base, relations: [null] }],
    ["relation-missing-kind", { ...base, relations: [{}] }],
    ["relation-bad-kind", { ...base, relations: [{ kind: "semantic" }] }],
    ["duplicate-simple", { ...base, relations: ["exact", "exact"] }],
    ["duplicate-protocol", { ...base, relations: [protocol, protocol] }],
    ["missing-direction", { ...base, relations: ["uts39_confusable"] }],
    ["forbidden-direction", { ...base, confusableDirection: "LTR" }],
    ["bad-direction", { ...base, relations: ["uts39_confusable"], confusableDirection: "AUTO" }],
    ["item-not-object", { ...base, items: [null] }],
    ["item-unknown-field", { ...base, items: [{ ...base.items[0], extra: true }] }],
    ["item-missing-id", { ...base, items: [without(base.items[0], "id")] }],
    ["item-id-not-string", { ...base, items: [{ ...base.items[0], id: 1 }] }],
    ["item-id-empty", { ...base, items: [{ ...base.items[0], id: "" }] }],
    ["item-id-utf16-over-limit", { ...base, items: [{ ...base.items[0], id: "😀".repeat(65) }] }],
    ["item-scope-empty", { ...base, items: [{ ...base.items[0], scope: "" }] }],
    ["item-scope-utf16-over-limit", { ...base, items: [{ ...base.items[0], scope: "😀".repeat(33) }] }],
    ["item-text-not-string", { ...base, items: [{ ...base.items[0], text: 1 }] }],
    ["item-text-invalid-unicode", { ...base, items: [{ ...base.items[0], text: taggedUnits([0xd800]) }] }],
    ["item-text-byte-limit", { ...base, items: [{ ...base.items[0], text: taggedScalar("a".repeat(4097)) }] }],
    ["duplicate-item-id", { ...base, items: [base.items[0], { ...base.items[0], text: taggedScalar("other") }] }],
    ["cumulative-text-limit", { ...base, items: Array.from({ length: 17 }, (_, index) => ({
      id: `large-${index}`, text: taggedScalar("a".repeat(4096)), scope: "scope"
    })) }],
    ["uts46-unknown-field", { ...base, relations: [{ ...protocol, extra: true }] }],
    ["uts46-missing-action", { ...base, relations: [without(protocol, "action")] }],
    ["uts46-bad-action", { ...base, relations: [{ ...protocol, action: "enforce" }] }],
    ["uts46-missing-option", { ...base, relations: [{ ...protocol, options: without(strictUts46, "checkBidi") }] }],
    ["uts46-option-not-boolean", { ...base, relations: [{ ...protocol, options: { ...strictUts46, checkBidi: "yes" } }] }],
    ["precis-unknown-field", { ...base, relations: [{ kind: "protocol", profile: "precis_opaque_string", action: "enforce", options: {} }] }],
    ["precis-bad-action", { ...base, relations: [{ kind: "protocol", profile: "precis_opaque_string", action: "prepare" }] }],
    ["protocol-execution-error", {
      items: [{ id: "bad", text: taggedScalar("-bad"), scope: "domains" }], relations: [protocol]
    }]
  ];
  requests.push(...negativeCases.map(([id, requestArguments]) => ({
    id: `namespace:negative:${id}`, operation: "namespace_integrity", arguments: requestArguments
  })));

  return {
    requests,
    coverage: {
      canonicalCaseCount,
      simpleDirectionCaseCount,
      utf16OrderingCaseCount,
      uts46ConfigurationCaseCount,
      precisProfileCaseCount,
      composedProtocolRelationCaseCount,
      negativeCaseCount: negativeCases.length,
      totalCaseCount: requests.length
    }
  };
}

function buildRequests() {
  const corpus = JSON.parse(readFileSync(path.join(ROOT, "reference", "behavior-corpus.json"), "utf8"));
  const requests = corpus.cases
    .filter((entry) => ["index", "inspect", "normalize", "transcode"].includes(entry.operation)
      || entry.operation === "protocol_profile"
      || entry.operation === "security")
    .map((entry) => ({ id: `corpus:${entry.id}`, operation: entry.operation, arguments: entry.arguments }));
  const differenceSpineRequests = corpus.cases
    .filter((entry) => entry.operation === "explain_difference")
    .map((entry) => ({
      id: `corpus:${entry.id}`,
      operation: "reference_explain_difference_spine",
      arguments: entry.arguments
    }));
  requests.push(...differenceSpineRequests);
  const namespace = buildNamespaceRequests(corpus);
  requests.push(...namespace.requests);
  const baseOperationShape = buildBaseOperationShapeRequests();
  requests.push(...baseOperationShape.requests);
  const differenceCoverage = {
    canonicalCaseCount: differenceSpineRequests.length,
    graphemeConformanceCaseCount: 0,
    normalizationConformanceCaseCount: 0,
    nfkcCasefoldCaseCount: 0,
    confusableComparisonCaseCount: 0,
    signalBoundaryCaseCount: 0,
    composedSequenceCaseCount: 0,
    totalCaseCount: 0
  };
  const state = { value: 0x54495854 };
  const representations = ["bytes", "hex", "base64"];
  const witnessModes = ["none", "summary", "full_required"];
  const encodings = ["utf-8", "utf-16le"];

  for (let index = 0; index < 1024; index += 1) {
    const length = index % 17;
    const bytes = Array.from({ length }, () => nextRandom(state) & 0xff);
    const sourceEncoding = encodings[index % encodings.length];
    requests.push({
      id: `hostile-bytes:${index}`,
      operation: "transcode",
      arguments: {
        sourceKind: "bytes",
        bytes,
        sourceEncoding,
        targetEncoding: encodings[(index >>> 1) % encodings.length],
        allowLossy: true,
        byteRepresentation: representations[index % representations.length],
        witnessMode: witnessModes[(index >>> 2) % witnessModes.length]
      }
    });
  }

  for (let index = 0; index < 512; index += 1) {
    const length = index % 9;
    const units = Array.from({ length }, () => nextRandom(state) & 0xffff);
    requests.push({
      id: `hostile-utf16:${index}`,
      operation: "transcode",
      arguments: {
        sourceKind: "text",
        text: taggedUnits(units),
        targetEncoding: encodings[index % encodings.length],
        allowLossy: true,
        byteRepresentation: representations[(index >>> 1) % representations.length],
        witnessMode: witnessModes[(index >>> 2) % witnessModes.length]
      }
    });
  }

  for (const [index, units] of [
    [0xd800, 0x0301, 0xdc00],
    [0x0600, 0xd800],
    [0xd800, 0xd801],
    [0xd800, 0x200d]
  ].entries()) {
    requests.push({
      id: `inspect-explicit-unpaired-grapheme:${index}`,
      operation: "inspect",
      arguments: { text: taggedUnits(units), detailLimit: 128 }
    });
  }

  for (const [index, value] of ["", "ASCII", "é", "😀", "\ufeffA", "家族👨‍👩‍👧‍👦"].entries()) {
    requests.push({
      id: `scalar-text:${index}`,
      operation: "transcode",
      arguments: {
        sourceKind: "text",
        text: taggedScalar(value),
        targetEncoding: encodings[index % encodings.length],
        allowLossy: false,
        byteRepresentation: representations[index % representations.length],
        witnessMode: witnessModes[index % witnessModes.length]
      }
    });
  }

  for (let index = 0; index < 512; index += 1) {
    const length = index % 17;
    const units = Array.from({ length }, () => nextRandom(state) & 0xffff);
    requests.push({
      id: `inspect-hostile-utf16:${index}`,
      operation: "inspect",
      arguments: { text: taggedUnits(units), detailLimit: 128 }
    });
  }

  for (const [index, value] of ["", "ASCII", "e\u0301", "😀", "\ufeffA", "家族👨‍👩‍👧‍👦"].entries()) {
    requests.push({
      id: `inspect-scalar:${index}`,
      operation: "inspect",
      arguments: { text: taggedScalar(value), detailLimit: 128 }
    });
  }

  const conformanceRoot = path.join(ROOT, "vendor", "unicode", "17.0.0");
  const conformanceManifest = JSON.parse(readFileSync(path.join(conformanceRoot, "CONFORMANCE_MANIFEST.json")));
  const graphemeEntry = conformanceManifest.files.find((entry) => entry.path.endsWith("/GraphemeBreakTest.txt.gz"));
  const graphemeCorpus = gunzipSync(readFileSync(path.join(conformanceRoot, graphemeEntry.path))).toString("utf8");
  let graphemeCase = 0;
  for (const sourceLine of graphemeCorpus.split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "") continue;
    const value = line.split(/\s+/u)
      .filter((token) => token !== "÷" && token !== "×")
      .map((token) => String.fromCodePoint(Number.parseInt(token, 16)))
      .join("");
    requests.push({
      id: `inspect-grapheme-conformance:${graphemeCase}`,
      operation: "inspect",
      arguments: { text: taggedScalar(value), detailLimit: 128 }
    });
    requests.push({
      id: `index-grapheme-conformance:${graphemeCase}`,
      operation: "index",
      arguments: { text: taggedScalar(value), detailLimit: 128 }
    });
    differenceSpineRequests.push({
      id: `difference-spine:grapheme-conformance:${graphemeCase}`,
      operation: "reference_explain_difference_spine",
      arguments: differenceSpineArguments(taggedScalar(value))
    });
    differenceCoverage.graphemeConformanceCaseCount += 1;
    graphemeCase += 1;
  }
  if (graphemeCase !== 766) throw new Error(`expected 766 GraphemeBreakTest cases, received ${graphemeCase}`);

  const normalizationEntry = conformanceManifest.files.find((entry) => entry.path.endsWith("/NormalizationTest.txt.gz"));
  const normalizationCorpus = gunzipSync(readFileSync(path.join(conformanceRoot, normalizationEntry.path))).toString("utf8");
  let normalizationCase = 0;
  for (const sourceLine of normalizationCorpus.split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "" || line.startsWith("@")) continue;
    const source = line.split(";", 1)[0].trim().split(/\s+/u)
      .map((token) => String.fromCodePoint(Number.parseInt(token, 16)))
      .join("");
    for (const form of ["NFC", "NFD", "NFKC", "NFKD"]) {
      requests.push({
        id: `normalize-conformance:${normalizationCase}:${form}`,
        operation: "normalize",
        arguments: { text: taggedScalar(source), form }
      });
    }
    differenceSpineRequests.push({
      id: `difference-spine:normalization-conformance:${normalizationCase}`,
      operation: "reference_explain_difference_spine",
      arguments: differenceSpineArguments(taggedScalar(source))
    });
    differenceCoverage.normalizationConformanceCaseCount += 1;
    normalizationCase += 1;
  }
  if (normalizationCase !== 20034) {
    throw new Error(`expected 20034 NormalizationTest cases, received ${normalizationCase}`);
  }

  const idnaEntry = conformanceManifest.files.find((entry) => entry.path.endsWith("/IdnaTestV2.txt.gz"));
  const idnaCorpus = gunzipSync(readFileSync(path.join(conformanceRoot, idnaEntry.path))).toString("utf8");
  let idnaCase = 0;
  const idnaCommon = {
    checkBidi: true,
    checkHyphens: true,
    checkJoiners: true,
    ignoreInvalidPunycode: false,
    useSTD3ASCIIRules: false
  };
  for (const sourceLine of idnaCorpus.split(/\r?\n/u)) {
    const line = sourceLine.split("#", 1)[0].trim();
    if (line === "") continue;
    const source = decodeIdna(line.split(";")[0], "");
    if (!source.isWellFormed()) continue;
    requests.push({
      id: `uts46-conformance:${idnaCase}:unicode`,
      operation: "protocol_profile",
      arguments: {
        profile: "uts46_domain",
        action: "to_unicode",
        text: taggedScalar(source),
        options: { ...idnaCommon, transitionalProcessing: false },
        witnessMode: "none"
      }
    });
    for (const transitionalProcessing of [false, true]) {
      requests.push({
        id: `uts46-conformance:${idnaCase}:ascii:${transitionalProcessing ? "transitional" : "nontransitional"}`,
        operation: "protocol_profile",
        arguments: {
          profile: "uts46_domain",
          action: "to_ascii",
          text: taggedScalar(source),
          options: {
            ...idnaCommon,
            transitionalProcessing,
            verifyDNSLength: true
          },
          witnessMode: "none"
        }
      });
    }
    idnaCase += 1;
  }
  if (idnaCase !== 6389) throw new Error(`expected 6389 IdnaTestV2 cases, received ${idnaCase}`);

  const uts46Options = buildUts46OptionRequests();
  requests.push(...uts46Options.requests);

  const precis = buildPrecisRequests();
  requests.push(...precis.requests);

  const protocolShape = buildProtocolShapeRequests();
  requests.push(...protocolShape.requests);

  const witnessSamples = [
    "",
    "ASCII",
    "e\u0301",
    "\u1E9B\u0323",
    "①A\u0315\u0300",
    "\u1100\u1161\u11A8",
    "\uAC01",
    "A\u0315\u0300",
    "\u212B",
    "\uFB03",
    "\uFDFA",
    "\u{1D15E}"
  ];
  for (const [index, value] of witnessSamples.entries()) {
    for (const form of ["NFC", "NFD", "NFKC", "NFKD"]) {
      for (const witnessMode of ["summary", "full_required"]) {
        requests.push({
          id: `normalize-witness:${index}:${form}:${witnessMode}`,
          operation: "normalize",
          arguments: { text: taggedScalar(value), form, witnessMode }
        });
      }
    }
  }

  const indexCharacters = ["A", "\r", "\n", "\u0085", "\u2028", "\u2029", "e", "\u0301", "😀", "👨", "\u200d", "👩"];
  for (let index = 0; index < 200; index += 1) {
    const length = index % 13;
    const value = Array.from({ length }, () => indexCharacters[nextRandom(state) % indexCharacters.length]).join("");
    requests.push({
      id: `index-lines-chunks:${index}`,
      operation: "index",
      arguments: {
        text: taggedScalar(value),
        detailLimit: 128,
        ...(index % 3 === 0 ? { maxChunkUtf8Bytes: 64 } : {})
      }
    });
  }
  const nfkcCasefold = buildNfkcCasefoldRequests();
  requests.push(...nfkcCasefold.requests);
  for (const request of nfkcCasefold.requests) {
    differenceSpineRequests.push({
      id: `difference-spine:${request.id}`,
      operation: "reference_explain_difference_spine",
      arguments: differenceSpineArguments(request.arguments.text)
    });
  }
  differenceCoverage.nfkcCasefoldCaseCount = nfkcCasefold.requests.length;
  const uts39PostReorderSkeleton = buildUts39PostReorderSkeletonRequests();
  requests.push(...uts39PostReorderSkeleton.requests);
  const bidiSkeleton = buildBidiSkeletonRequests();
  requests.push(...bidiSkeleton.requests);
  const confusableComparison = buildConfusableComparisonRequests();
  requests.push(...confusableComparison.requests);
  for (const request of confusableComparison.requests) {
    differenceSpineRequests.push({
      id: `difference-spine:${request.id}`,
      operation: "reference_explain_difference_spine",
      arguments: differenceSpineArguments(
        request.arguments.text,
        request.arguments.comparison,
        { direction: request.arguments.direction }
      )
    });
  }
  differenceCoverage.confusableComparisonCaseCount = confusableComparison.requests.length;
  const security = buildSecurityRequests();
  const sourceDiagnostics = buildSourceDiagnosticsRequests();
  requests.push(...security.requests, ...sourceDiagnostics.requests);
  const signalRequests = security.requests.filter((request) => request.id.startsWith("security:free-text-boundary:"));
  for (const request of signalRequests) {
    differenceSpineRequests.push({
      id: `difference-spine:${request.id}`,
      operation: "reference_explain_difference_spine",
      arguments: differenceSpineArguments(request.arguments.text, request.arguments.text, {
        detailLimit: 1
      })
    });
  }
  differenceCoverage.signalBoundaryCaseCount = signalRequests.length;
  const composedDifferenceCases = [
    ["line-endings", "A\r\nB\rC\nD\u0085E\u2028F\u2029G", "A\nB\nC\nD\nE\nF\nG", "LTR", "summary"],
    ["canonical", "é", "e\u0301", "LTR", "full_required"],
    ["compatibility", "①", "1", "LTR", "full_required"],
    ["casefold", "Straße", "strasse", "LTR", "summary"],
    ["confusable-ltr", "pаypal", "paypal", "LTR", "summary"],
    ["confusable-rtl", "א(١)", "א(1)", "RTL", "summary"],
    ["confusable-first-strong", "א(١)", "א(1)", "FS", "full_required"],
    ["alignment-multiple", "Aé🙂Z", "Axe\u0301🙂Y", "LTR", "full_required"],
    ["alignment-insert", "a", "aa", "LTR", "full_required"],
    ["alignment-delete", "aa", "a", "LTR", "full_required"],
    ["alignment-empty", "", "x", "LTR", "full_required"],
    ["alignment-grapheme", "A👨‍👩‍👧‍👦B", "A👨‍👩‍👧‍👦XB", "LTR", "full_required"],
    ["alignment-repeated", "abab", "aabb", "LTR", "summary"]
  ];
  for (const [id, left, right, direction, witnessMode] of composedDifferenceCases) {
    differenceSpineRequests.push({
      id: `difference-spine:composed:${id}`,
      operation: "reference_explain_difference_spine",
      arguments: differenceSpineArguments(taggedScalar(left), taggedScalar(right), {
        direction,
        detailLimit: 128,
        witnessMode
      })
    });
  }
  differenceCoverage.composedSequenceCaseCount = composedDifferenceCases.length;
  requests.push(...differenceSpineRequests.slice(differenceCoverage.canonicalCaseCount));
  differenceCoverage.totalCaseCount = differenceSpineRequests.length;
  security.coverage.sourceDiagnostics = sourceDiagnostics.coverage;
  security.coverage.totalCaseCount += sourceDiagnostics.coverage.totalCaseCount;
  return {
    requests,
    nfkcCasefoldCoverage: nfkcCasefold.coverage,
    uts39PostReorderSkeletonCoverage: uts39PostReorderSkeleton.coverage,
    bidiSkeletonCoverage: bidiSkeleton.coverage,
    confusableComparisonCoverage: confusableComparison.coverage,
    uts46Coverage: uts46Options.coverage,
    protocolShapeCoverage: protocolShape.coverage,
    precisCoverage: precis.coverage,
    securityCoverage: security.coverage,
    differenceCoverage,
    namespaceCoverage: namespace.coverage,
    baseOperationShapeCoverage: baseOperationShape.coverage,
    baseOperationShapeRequests: baseOperationShape.requests
  };
}

const nodeUnicodeData = unicodeSecurityData();
const nodeUnicodeIdentity = unicodeDataIdentity();

function nodeReferenceNfkcCasefold(requestArguments) {
  const { text } = materializeTaggedArguments(requestArguments);
  const transformed = nfkcCasefold(nodeUnicodeData, text);
  return {
    status: "ok",
    operation: "reference_nfkc_casefold",
    original: text,
    transformed,
    changed: text !== transformed,
    engine: "text-integrity-node-core",
    standards: {
      specification: "Unicode Standard Annex #15",
      unicodeVersion: nodeUnicodeIdentity.unicodeVersion,
      mappingProperty: "NFKC_CF",
      source: {
        manifestSha256: nodeUnicodeIdentity.sourceManifestSha256,
        path: "ucd/DerivedNormalizationProps.txt",
        sha256: "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488",
        mappingRowCount: 6183,
        mappedCodePointCount: 10583
      }
    }
  };
}

function nodeReferenceUts39PostReorderSkeleton(requestArguments) {
  const { text } = materializeTaggedArguments(requestArguments);
  const skeleton = uts39PostReorderSkeleton(nodeUnicodeData, text);
  return {
    status: "ok",
    operation: "reference_uts39_post_reorder_skeleton",
    original: text,
    skeleton,
    changed: text !== skeleton,
    engine: "text-integrity-node-core",
    standards: {
      specification: "Unicode Technical Standard #39",
      unicodeVersion: nodeUnicodeIdentity.unicodeVersion,
      uts39Revision: nodeUnicodeIdentity.uts39Revision,
      stage: "post_reorder_internal_skeleton",
      source: {
        manifestSha256: nodeUnicodeIdentity.sourceManifestSha256,
        confusables: {
          path: "security/confusables.txt",
          sha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
          mappingRowCount: 6565
        },
        defaultIgnorable: {
          path: "ucd/DerivedCoreProperties.txt",
          sha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08",
          rangeCount: 27,
          codePointCount: 4174
        }
      }
    }
  };
}

function nodeReferenceBidiSkeleton(requestArguments) {
  const { text, direction } = materializeTaggedArguments(requestArguments);
  const reordered = reorderForDisplay(nodeUnicodeData, text, direction);
  const skeleton = uts39PostReorderSkeleton(nodeUnicodeData, reordered.text);
  const resolvedLevels = Array.from({ length: [...text].length });
  for (const entry of reordered.entries) {
    resolvedLevels[entry.logicalCodePointIndex] = entry.level;
  }
  return {
    status: "ok",
    operation: "reference_bidi_skeleton",
    original: text,
    direction,
    resolvedLevels,
    visualOrder: reordered.entries.map((entry) => entry.logicalCodePointIndex),
    entries: reordered.entries,
    reordered: reordered.text,
    skeleton,
    changed: text !== skeleton,
    paragraphLevels: reordered.paragraphLevels,
    engine: "text-integrity-node-core",
    standards: {
      specification: "Unicode Standard Annex #9 + Unicode Technical Standard #39",
      unicodeVersion: "17.0.0",
      uts39Revision: 32,
      stage: "complete_bidi_skeleton",
      uba: {
        algorithm: "bidi-js@1.0.3+text-integrity-unicode17-data",
        hardcodedDataFeature: null,
        dataSource: "vendored-generated-unicode-17",
        conformance: {
          bidiTestParagraphModeCases: 770241,
          bidiCharacterTestCases: 91707
        },
        source: {
          manifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
          bidiClass: {
            path: "ucd/extracted/DerivedBidiClass.txt",
            sha256: "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4",
            rangeCount: 1267
          },
          bidiBrackets: {
            path: "ucd/BidiBrackets.txt",
            sha256: "dadbaf38a0d0246e5b805bf8725cb81b7c621f93d030595635f5ba2c2f179428",
            entryCount: 128
          },
          unicodeData: {
            path: "ucd/UnicodeData.txt",
            sha256: "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
            combiningClassRangeCount: 403,
            combiningClassCodePointCount: 968
          },
          bidiMirroring: {
            path: "ucd/BidiMirroring.txt",
            sha256: "a2f16fb873ab4fcdf3221cb1a8a85a134ddd6ed03603181823ff5206af3741ce",
            entryCount: 428
          }
        }
      }
    }
  };
}

function nodeReferenceConfusableComparison(requestArguments) {
  const { text, comparison, direction } = materializeTaggedArguments(requestArguments);
  return {
    status: "ok",
    operation: "reference_confusable_comparison",
    text,
    comparison,
    ...compareConfusables(nodeUnicodeData, text, comparison, direction),
    standards: {
      specification: "Unicode Technical Standard #39",
      unicodeVersion: nodeUnicodeIdentity.unicodeVersion,
      uts39Revision: nodeUnicodeIdentity.uts39Revision,
      stage: "confusable_comparison",
      source: {
        manifestSha256: nodeUnicodeIdentity.sourceManifestSha256,
        scripts: {
          path: "ucd/Scripts.txt",
          sha256: "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf",
          rangeCount: 2287
        },
        scriptExtensions: {
          path: "ucd/ScriptExtensions.txt",
          sha256: "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6",
          rangeCount: 206
        },
        propertyValueAliases: {
          path: "ucd/PropertyValueAliases.txt",
          sha256: "64e9a5f76f7a1e8b5a47d6a1f9a26522a251208f5276bdfa1559dac7cf2e827a"
        }
      }
    }
  };
}

function nodeReferenceDifferenceSpine(requestArguments) {
  const result = executeOperation(
    "explain_difference",
    materializeTaggedArguments(requestArguments)
  );
  const projected = structuredClone(semanticProjection(result));
  projected.operation = "reference_explain_difference_spine";
  projected.consumerOperation = "explain_difference";
  projected.projection = DIFFERENCE_SPINE_PROJECTION;
  delete projected.collation;
  if (projected.witness) {
    projected.witness.factBoundaries.collation = {
      authority: "runtime_icu",
      environmentBound: true,
      includedInProjection: false
    };
  }
  return projected;
}

function nodeResults(requests) {
  return requests.map((request) => {
    try {
      let result;
      if (request.operation === "reference_bidi_skeleton") {
        result = nodeReferenceBidiSkeleton(request.arguments);
      } else if (request.operation === "reference_confusable_comparison") {
        result = nodeReferenceConfusableComparison(request.arguments);
      } else if (request.operation === "reference_explain_difference_spine") {
        result = nodeReferenceDifferenceSpine(request.arguments);
      } else if (request.operation === "reference_nfkc_casefold") {
        result = nodeReferenceNfkcCasefold(request.arguments);
      } else if (request.operation === "reference_uts39_post_reorder_skeleton") {
        result = nodeReferenceUts39PostReorderSkeleton(request.arguments);
      } else if (request.operation === "namespace_integrity") {
        result = analyzeNamespaceIntegrity(materializeTaggedArguments(request.arguments));
      } else {
        result = executeOperation(request.operation, materializeTaggedArguments(request.arguments));
      }
      return independentProjection(request.operation, result);
    } catch (error) {
      return independentProjection(request.operation, errorPayload(error));
    }
  });
}

function nativeResults(requests) {
  const runnerRequests = requests.map((request) => ({
    operation: request.operation,
    arguments: request.arguments
  }));
  const child = spawnSync(NATIVE_BINARY, [], {
    cwd: ROOT,
    input: JSON.stringify(runnerRequests),
    encoding: "utf8",
    maxBuffer: 256 << 20,
    timeout: 120000
  });
  if (child.status !== 0) {
    const range = `${requests[0]?.id ?? "empty"}..${requests.at(-1)?.id ?? "empty"}`;
    throw new Error(child.stderr || child.error?.message
      || `native independent runner failed for ${range}`);
  }
  observeBatchFrame("maximumNativeOutput", Buffer.byteLength(child.stdout), requests);
  return JSON.parse(child.stdout).map((result, index) => independentProjection(requests[index].operation, result));
}

function nativeFrame(input) {
  const child = spawnSync(NATIVE_BINARY, [], {
    cwd: ROOT,
    input,
    maxBuffer: 16 << 20,
    timeout: 120000
  });
  if (child.error) throw child.error;
  return {
    status: child.status,
    stdout: Buffer.from(child.stdout ?? []),
    stderr: Buffer.from(child.stderr ?? []).toString("utf8")
  };
}

async function independentWasmInstance() {
  wasmResults.instance ??= WebAssembly.compile(readFileSync(WASM_BINARY))
    .then((module) => WebAssembly.instantiate(module, {}));
  return wasmResults.instance;
}

function rawWasmFrame(instance, input) {
  const pointer = instance.exports.ti_alloc(input.length);
  if (pointer === 0) throw new Error(`raw WASM rejected a boundary-test ${input.length}-byte allocation`);
  try {
    new Uint8Array(instance.exports.memory.buffer, pointer, input.length).set(input);
    const status = instance.exports.ti_run(pointer, input.length);
    const resultLength = instance.exports.ti_result_len();
    const result = resultLength === 0
      ? Buffer.alloc(0)
      : Buffer.from(new Uint8Array(
        instance.exports.memory.buffer,
        instance.exports.ti_result_ptr(),
        resultLength
      ));
    return { status, result };
  } finally {
    instance.exports.ti_dealloc(pointer, input.length);
  }
}

function rawRequestWork(request) {
  let args;
  try {
    args = materializeTaggedArguments(request.arguments);
  } catch {
    return {
      differenceAlignmentCells: 0, sourceDiagnosticUnits: 0, uts46PunycodeScanUnits: 0
    };
  }
  if (request.operation === "reference_explain_difference_spine"
    && ["summary", "full_required"].includes(args?.witnessMode)
    && typeof args.left === "string" && typeof args.right === "string") {
    return {
      differenceAlignmentCells: 2 * [...args.left].length * [...args.right].length,
      sourceDiagnosticUnits: 0,
      uts46PunycodeScanUnits: 0
    };
  }
  if (request.operation === "protocol_profile" && args?.profile === "uts46_domain"
    && args.action === "to_ascii" && typeof args.text === "string") {
    const uts46PunycodeScanUnits = args.text.split(".").reduce((sum, label) => {
      const codePoints = [...label];
      if (label.startsWith("xn--")) return sum + (codePoints.length ** 2);
      const distinctNonAscii = new Set(
        codePoints.filter((value) => value.codePointAt(0) > 0x7f)
      );
      return sum + (codePoints.length * distinctNonAscii.size);
    }, 0);
    return { differenceAlignmentCells: 0, sourceDiagnosticUnits: 0, uts46PunycodeScanUnits };
  }
  if (request.operation !== "security" || args?.mode !== "source"
    || typeof args.source !== "string" || !Array.isArray(args.spans)) {
    return {
      differenceAlignmentCells: 0, sourceDiagnosticUnits: 0, uts46PunycodeScanUnits: 0
    };
  }
  const identifiers = args.spans.filter((span) => span?.kind === "identifier"
    && Number.isInteger(span.startUtf16) && Number.isInteger(span.endUtf16)
    && span.startUtf16 >= 0 && span.endUtf16 >= span.startUtf16
    && span.endUtf16 <= args.source.length);
  const lengths = identifiers.map((span) => span.endUtf16 - span.startUtf16);
  const pairUnits = [];
  for (let leftIndex = 0; leftIndex < identifiers.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < identifiers.length; rightIndex += 1) {
      if ((identifiers[leftIndex].scope ?? null) === (identifiers[rightIndex].scope ?? null)) {
        pairUnits.push(lengths[leftIndex] + lengths[rightIndex]);
      }
    }
  }
  pairUnits.sort((left, right) => right - left);
  const detailLimit = Number.isInteger(args.detailLimit) ? args.detailLimit : 64;
  return {
    differenceAlignmentCells: 0,
    sourceDiagnosticUnits: args.source.length
      + lengths.reduce((sum, length) => sum + length, 0)
      + pairUnits.slice(0, detailLimit).reduce((sum, units) => sum + units, 0),
    uts46PunycodeScanUnits: 0
  };
}

function partitionRawBatches(requests) {
  const batches = [];
  let batch = [];
  let inputBytes = 2;
  let differenceAlignmentCells = 0;
  let sourceDiagnosticUnits = 0;
  let uts46PunycodeScanUnits = 0;
  const flush = () => {
    if (batch.length === 0) return;
    batches.push({
      batch, differenceAlignmentCells, sourceDiagnosticUnits, uts46PunycodeScanUnits
    });
    batch = [];
    inputBytes = 2;
    differenceAlignmentCells = 0;
    sourceDiagnosticUnits = 0;
    uts46PunycodeScanUnits = 0;
  };
  for (const request of requests) {
    const runnerRequest = { operation: request.operation, arguments: request.arguments };
    const requestBytes = Buffer.byteLength(JSON.stringify(runnerRequest));
    const work = rawRequestWork(request);
    if (requestBytes + 2 > REFERENCE_WASM_RAW_ABI.maxInputBytes
      || work.differenceAlignmentCells > REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells
      || work.sourceDiagnosticUnits > REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits) {
      throw new Error(`independent case ${request.id} cannot fit one declared raw ABI frame`);
    }
    if (work.uts46PunycodeScanUnits
      > REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits) {
      throw new Error(`independent case ${request.id} cannot fit one declared raw ABI frame`);
    }
    const separatorBytes = batch.length === 0 ? 0 : 1;
    const wouldExceed = batch.length >= REFERENCE_WASM_RAW_ABI.maxBatchRequests
      || inputBytes + separatorBytes + requestBytes > REFERENCE_WASM_RAW_ABI.maxInputBytes
      || differenceAlignmentCells + work.differenceAlignmentCells
        > REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells
      || sourceDiagnosticUnits + work.sourceDiagnosticUnits
        > REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits
      || uts46PunycodeScanUnits + work.uts46PunycodeScanUnits
        > REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits;
    if (wouldExceed) flush();
    inputBytes += (batch.length === 0 ? 0 : 1) + requestBytes;
    differenceAlignmentCells += work.differenceAlignmentCells;
    sourceDiagnosticUnits += work.sourceDiagnosticUnits;
    uts46PunycodeScanUnits += work.uts46PunycodeScanUnits;
    batch.push(request);
  }
  flush();
  return batches;
}

async function verifyRawFrameBoundary() {
  const statuses = REFERENCE_WASM_RAW_ABI.statuses;
  const instance = await independentWasmInstance();
  for (const [name, expected] of Object.entries({
    ti_abi_version: REFERENCE_WASM_RAW_ABI.version,
    ti_max_input_len: REFERENCE_WASM_RAW_ABI.maxInputBytes,
    ti_max_batch_len: REFERENCE_WASM_RAW_ABI.maxBatchRequests,
    ti_max_result_len: REFERENCE_WASM_RAW_ABI.maxResultBytes,
    ti_max_difference_alignment_cells:
      REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells,
    ti_max_source_diagnostic_units:
      REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits,
    ti_max_uts46_punycode_scan_units:
      REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits
  })) {
    if (instance.exports[name]() !== expected) {
      throw new Error(`raw WASM ${name} does not match its declared ABI`);
    }
  }

  const memoryBefore = instance.exports.memory.buffer.byteLength;
  if (instance.exports.ti_alloc(0) !== 0
    || instance.exports.ti_alloc(REFERENCE_WASM_RAW_ABI.maxInputBytes + 1) !== 0
    || instance.exports.memory.buffer.byteLength !== memoryBefore) {
    throw new Error("raw WASM oversized allocation did not fail before memory growth");
  }
  if (instance.exports.ti_run(0, REFERENCE_WASM_RAW_ABI.maxInputBytes + 1)
      !== statuses.inputTooLarge
    || instance.exports.ti_result_len() !== 0) {
    throw new Error("raw WASM oversized run did not return the closed empty-result status");
  }

  const valid = Buffer.from(JSON.stringify({
    operation: "inspect",
    arguments: { text: taggedScalar("A"), detailLimit: 1 }
  }));
  const ownedPointer = instance.exports.ti_alloc(valid.length);
  if (ownedPointer === 0) throw new Error("raw WASM could not allocate a valid boundary request");
  new Uint8Array(instance.exports.memory.buffer, ownedPointer, valid.length).set(valid);
  if (instance.exports.ti_alloc(1) !== 0) {
    throw new Error("raw WASM admitted a second live input allocation");
  }
  instance.exports.ti_dealloc(ownedPointer, valid.length - 1);
  if (instance.exports.ti_alloc(1) !== 0
    || instance.exports.ti_run(ownedPointer, valid.length - 1) !== statuses.invalidInputBuffer
    || instance.exports.ti_result_len() !== 0) {
    throw new Error("raw WASM did not preserve ownership across a mismatched buffer call");
  }
  if (instance.exports.ti_run(ownedPointer, valid.length) !== statuses.ok) {
    throw new Error("raw WASM did not recover with the exact owned buffer");
  }
  if (instance.exports.ti_alloc(REFERENCE_WASM_RAW_ABI.maxInputBytes + 1) !== 0
    || instance.exports.ti_result_len() !== 0
    || instance.exports.ti_run(ownedPointer, valid.length) !== statuses.ok) {
    throw new Error("raw WASM did not invalidate stale output and recover after allocation failure");
  }
  instance.exports.ti_dealloc(ownedPointer, valid.length);

  const malformed = Buffer.from("{");
  const nativeMalformed = nativeFrame(malformed);
  const wasmMalformed = rawWasmFrame(instance, malformed);
  if (nativeMalformed.status !== statuses.ok || wasmMalformed.status !== statuses.ok
    || canonicalJson(JSON.parse(nativeMalformed.stdout))
      !== canonicalJson(JSON.parse(wasmMalformed.result))) {
    throw new Error("native and raw WASM malformed-JSON envelopes do not match");
  }

  const oversizedInput = Buffer.alloc(REFERENCE_WASM_RAW_ABI.maxInputBytes + 1, 0x20);
  const oversizedBatch = Buffer.from(JSON.stringify(Array.from(
    { length: REFERENCE_WASM_RAW_ABI.maxBatchRequests + 1 },
    () => ({ operation: "inspect", arguments: null })
  )));
  const amplifyingRequest = {
    operation: "inspect",
    arguments: { text: taggedScalar("A".repeat(64)), detailLimit: 64 }
  };
  const amplifyingBatch = Buffer.from(JSON.stringify(Array.from(
    { length: REFERENCE_WASM_RAW_ABI.maxBatchRequests },
    () => amplifyingRequest
  )));
  const differenceRequest = {
    operation: "reference_explain_difference_spine",
    arguments: {
      left: taggedScalar("A".repeat(4096)),
      right: taggedScalar("B".repeat(4096)),
      locale: "en",
      options: {
        usage: "sort", sensitivity: "variant", ignorePunctuation: false,
        numeric: false, caseFirst: "false", localeMatcher: "lookup", collation: "default"
      },
      confusableDirection: "LTR",
      detailLimit: 0,
      witnessMode: "summary"
    }
  };
  const differenceWorkBatch = Buffer.from(JSON.stringify([
    differenceRequest, differenceRequest
  ]));
  const sourceRequest = {
    operation: "security",
    arguments: {
      source: taggedScalar("A".repeat(4096)),
      mode: "source",
      spans: Array.from({ length: 128 }, () => ({
        kind: "identifier", startUtf16: 0, endUtf16: 4096, scope: "same"
      })),
      confusableDirection: "LTR",
      detailLimit: 128
    }
  };
  const sourceWorkBatch = Buffer.from(JSON.stringify([sourceRequest, sourceRequest]));
  const punycodeText = Array.from(
    { length: 1365 },
    (_, index) => String.fromCodePoint(0x4e00 + index)
  ).join("");
  const punycodeRequest = {
    operation: "protocol_profile",
    arguments: {
      profile: "uts46_domain",
      action: "to_ascii",
      text: taggedScalar(punycodeText),
      options: {
        checkBidi: false, checkHyphens: true, checkJoiners: true,
        ignoreInvalidPunycode: false, transitionalProcessing: false,
        useSTD3ASCIIRules: true, verifyDNSLength: false
      },
      witnessMode: "full_required"
    }
  };
  const punycodeWorkBatch = Buffer.from(JSON.stringify(Array.from(
    { length: 10 }, () => punycodeRequest
  )));
  const nativeFailures = [
    [oversizedInput, statuses.inputTooLarge],
    [oversizedBatch, statuses.batchTooLarge],
    [amplifyingBatch, statuses.resultTooLarge],
    [differenceWorkBatch, statuses.differenceAlignmentWorkTooLarge],
    [sourceWorkBatch, statuses.sourceDiagnosticWorkTooLarge],
    [punycodeWorkBatch, statuses.uts46PunycodeWorkTooLarge]
  ];
  for (const [input, expectedStatus] of nativeFailures) {
    const result = nativeFrame(input);
    if (result.status !== expectedStatus || result.stdout.length !== 0
      || !result.stderr.startsWith(`raw frame error ${expectedStatus}:`)) {
      throw new Error(`native raw frame did not fail closed with status ${expectedStatus}`);
    }
  }
  for (const [input, expectedStatus] of nativeFailures.slice(1)) {
    const result = rawWasmFrame(instance, input);
    if (result.status !== expectedStatus || result.result.length !== 0) {
      throw new Error(`raw WASM frame did not fail closed with status ${expectedStatus}`);
    }
  }
  const recovered = rawWasmFrame(instance, valid);
  if (recovered.status !== statuses.ok || JSON.parse(recovered.result).operation !== "inspect") {
    throw new Error("raw WASM did not recover after batch/result framing failures");
  }
  return {
    abiIntrospection: true,
    allocatorOwnership: true,
    allocationRejectedBeforeMemoryGrowth: true,
    malformedJsonParity: true,
    nativeFailureStatuses: nativeFailures.map(([, status]) => status),
    wasmFailureStatuses: [
      statuses.invalidInputBuffer,
      statuses.inputTooLarge,
      statuses.batchTooLarge,
      statuses.resultTooLarge,
      statuses.differenceAlignmentWorkTooLarge,
      statuses.sourceDiagnosticWorkTooLarge,
      statuses.uts46PunycodeWorkTooLarge
    ],
    emptyResultOnCarrierFailure: true,
    recovery: true
  };
}

async function wasmResults(requests) {
  const instance = await independentWasmInstance();
  const runnerRequests = requests.map((request) => ({
    operation: request.operation,
    arguments: request.arguments
  }));
  const input = Buffer.from(JSON.stringify(runnerRequests));
  observeBatchFrame("maximumInput", input.length, requests);
  const pointer = instance.exports.ti_alloc(input.length);
  if (pointer === 0) throw new Error(`WASM independent runner rejected a ${input.length}-byte allocation`);
  let status;
  try {
    new Uint8Array(instance.exports.memory.buffer, pointer, input.length).set(input);
    status = instance.exports.ti_run(pointer, input.length);
  } finally {
    instance.exports.ti_dealloc(pointer, input.length);
  }
  if (status !== 0) throw new Error(`WASM independent runner returned status ${status}`);
  const outputPointer = instance.exports.ti_result_ptr();
  const outputLength = instance.exports.ti_result_len();
  observeBatchFrame("maximumWasmOutput", outputLength, requests);
  const output = Buffer.from(
    new Uint8Array(instance.exports.memory.buffer, outputPointer, outputLength)
  ).toString("utf8");
  return JSON.parse(output).map((result, index) => independentProjection(requests[index].operation, result));
}

async function compareInBatches(requests) {
  batchFrameMeasurements.configuredBatchSize = REFERENCE_WASM_RAW_ABI.maxBatchRequests;
  const semanticHash = createHash("sha256");
  semanticHash.update("[");
  let first = true;
  for (const {
    batch, differenceAlignmentCells, sourceDiagnosticUnits, uts46PunycodeScanUnits
  } of partitionRawBatches(requests)) {
    batchFrameMeasurements.batchCount += 1;
    batchFrameMeasurements.maximumRequestCount = Math.max(
      batchFrameMeasurements.maximumRequestCount,
      batch.length
    );
    observeBatchWork("maximumDifferenceAlignmentCells", differenceAlignmentCells, batch);
    observeBatchWork("maximumSourceDiagnosticUnits", sourceDiagnosticUnits, batch);
    observeBatchWork("maximumUts46PunycodeScanUnits", uts46PunycodeScanUnits, batch);
    const expected = nodeResults(batch);
    const native = nativeResults(batch);
    const wasm = await wasmResults(batch);
    compare("native", batch, expected, native);
    compare("wasm", batch, expected, wasm);
    compare("wasm-vs-native", batch, native, wasm);
    for (const result of expected) {
      if (!first) semanticHash.update(",");
      semanticHash.update(canonicalJson(result));
      first = false;
    }
  }
  semanticHash.update("]");
  return semanticHash.digest("hex");
}

function compare(label, requests, expected, actual) {
  if (!Array.isArray(actual) || actual.length !== expected.length) {
    throw new Error(`${label} returned ${actual?.length ?? "non-array"} results for ${expected.length} requests`);
  }
  for (let index = 0; index < expected.length; index += 1) {
    const left = canonicalJson(expected[index]);
    const right = canonicalJson(actual[index]);
    if (left !== right) {
      throw new Error(
        `${label} semantic mismatch for ${requests[index].id}\nnode: ${left}\n${label}: ${right}`
      );
    }
  }
}

runCargo(["fmt", "--manifest-path", MANIFEST, "--", "--check"]);
runCargo(["test", "--manifest-path", MANIFEST, "--locked", "--quiet"]);
runCargo(["build", "--manifest-path", MANIFEST, "--locked", "--release", "--quiet"]);
runCargo([
  "build", "--manifest-path", MANIFEST, "--locked", "--release", "--quiet",
  "--target", "wasm32-unknown-unknown"
]);
const rawAbiBoundary = await verifyRawFrameBoundary();

const {
  requests,
  nfkcCasefoldCoverage,
  uts39PostReorderSkeletonCoverage,
  bidiSkeletonCoverage,
  confusableComparisonCoverage,
  uts46Coverage,
  protocolShapeCoverage,
  precisCoverage,
  securityCoverage,
  differenceCoverage,
  namespaceCoverage,
  baseOperationShapeCoverage,
  baseOperationShapeRequests
} = buildRequests();
const semanticRootSha256 = await compareInBatches(requests);
if (batchFrameMeasurements.configuredBatchSize > REFERENCE_WASM_RAW_ABI.maxBatchRequests
  || batchFrameMeasurements.maximumRequestCount > REFERENCE_WASM_RAW_ABI.maxBatchRequests
  || batchFrameMeasurements.maximumInput?.bytes > REFERENCE_WASM_RAW_ABI.maxInputBytes
  || batchFrameMeasurements.maximumDifferenceAlignmentCells?.units
    > REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells
  || batchFrameMeasurements.maximumSourceDiagnosticUnits?.units
    > REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits
  || batchFrameMeasurements.maximumUts46PunycodeScanUnits?.units
    > REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits
  || batchFrameMeasurements.maximumNativeOutput?.bytes > REFERENCE_WASM_RAW_ABI.maxResultBytes
  || batchFrameMeasurements.maximumWasmOutput?.bytes > REFERENCE_WASM_RAW_ABI.maxResultBytes) {
  throw new Error("the independent differential workload exceeds the declared raw WASM ABI");
}
const packagedReferenceWasmRunner = await createReferenceWasmRunner(readFileSync(
  path.join(ROOT, "wasm", "text_integrity_reference.wasm")
));
const packagedReferenceWasmResults = baseOperationShapeRequests.map((request) => (
  packagedReferenceWasmRunner.run({
    operation: request.operation,
    arguments: request.arguments
  })
));
compare(
  "packaged-reference-wasm",
  baseOperationShapeRequests,
  nodeResults(baseOperationShapeRequests),
  packagedReferenceWasmResults
);
const committedManifest = JSON.parse(readFileSync(
  path.join(ROOT, "reference", "behavior-manifest.json"),
  "utf8"
));
const operationCounts = {};
for (const operation of ["index", "inspect", "namespace_integrity", "normalize", "protocol_profile", "security", "transcode"]) {
  const operationRequests = requests.filter((request) => request.operation === operation);
  const canonicalCount = operationRequests.filter((request) => request.id.startsWith("corpus:")).length;
  operationCounts[operation] = {
    cases: operationRequests.length,
    canonicalCases: canonicalCount,
    additionalCases: operationRequests.length - canonicalCount
  };
  const locator = committedManifest.operations?.[operation];
  const expectedStatus = operation === "namespace_integrity"
    ? "scoped_native_wasm_parity"
    : "native_wasm_parity";
  if (locator?.verificationStatus !== expectedStatus
    || locator.independentVerification?.canonicalCaseCount !== canonicalCount
    || locator.independentVerification?.additionalComparisonCaseCount
      !== operationRequests.length - canonicalCount
    || locator.independentVerification?.totalCaseCount !== operationRequests.length) {
    throw new Error(`the committed ${operation} verification locator does not match this differential run`);
  }
  const negativeRequestShapeCaseCount = baseOperationShapeCoverage[operation]
    ?.negativeRequestShapeCaseCount;
  if (negativeRequestShapeCaseCount !== undefined
    && locator.independentVerification?.negativeRequestShapeCaseCount
      !== negativeRequestShapeCaseCount) {
    throw new Error(`the committed ${operation} request-shape locator does not match this differential run`);
  }
  if (negativeRequestShapeCaseCount !== undefined
    && locator.independentVerification?.packagedReferenceWasmNegativeRequestShapeCaseCount
      !== negativeRequestShapeCaseCount) {
    throw new Error(
      `the committed ${operation} packaged-WASM request-shape locator does not match this run`
    );
  }
}

const namespaceVerification = committedManifest.operations?.namespace_integrity?.independentVerification;
const namespaceScope = {
  includedRelations: [
    "exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable",
    "protocol:uts46_domain", "protocol:precis_username_case_mapped",
    "protocol:precis_username_case_preserved", "protocol:precis_opaque_string"
  ],
  excludedRelations: ["declared_collation"],
  completeConsumerParity: false,
  deterministicUtf16Ordering: true,
  requestShapeValidationIncluded: true,
  completeResultBudgetEnforcementImplemented: true,
  runtimeDependentBudgetDiagnosticsExcluded: true
};
if (canonicalJson(namespaceVerification?.scope) !== canonicalJson(namespaceScope)
  || namespaceVerification?.simpleDirectionCaseCount !== namespaceCoverage.simpleDirectionCaseCount
  || namespaceVerification?.utf16OrderingCaseCount !== namespaceCoverage.utf16OrderingCaseCount
  || namespaceVerification?.uts46ConfigurationCaseCount !== namespaceCoverage.uts46ConfigurationCaseCount
  || namespaceVerification?.precisProfileCaseCount !== namespaceCoverage.precisProfileCaseCount
  || namespaceVerification?.composedProtocolRelationCaseCount
    !== namespaceCoverage.composedProtocolRelationCaseCount
  || namespaceVerification?.negativeCaseCount !== namespaceCoverage.negativeCaseCount) {
  throw new Error("the committed namespace-integrity scope does not match this differential run");
}

const protocolVerification = committedManifest.operations?.protocol_profile?.independentVerification;
const protocolScope = {
  uts46: {
    profile: "uts46_domain",
    actions: ["to_ascii", "to_unicode"],
    witnessModes: ["none", "summary", "full_required"],
    implementationScope: "complete_option_space",
    requestShapeValidationIncluded: true
  },
  precis: {
    profiles: precisCoverage.profiles,
    actions: precisCoverage.actions,
      witnessModes: precisCoverage.witnessModes,
      implementationScope: "complete_profile_execution",
      requestShapeValidationIncluded: true
  }
};
const protocolPrecisCoverage = {
  sourceManifestSha256: precisCoverage.sourceManifestSha256,
  sourceFiles: precisCoverage.sourceFiles,
  propertyBoundaryCodePointCount: precisCoverage.propertyBoundaryCodePointCount,
  propertyBoundaryProfileCaseCount: precisCoverage.propertyBoundaryProfileCaseCount,
  widthMappingCaseCount: precisCoverage.widthMappingCaseCount,
  lowercaseMappingCaseCount: precisCoverage.lowercaseMappingCaseCount,
  normalizationConformanceSourceCaseCount: precisCoverage.normalizationConformanceSourceCaseCount,
  contextSequenceCaseCount: precisCoverage.contextSequenceCaseCount,
  bidiSequenceCaseCount: precisCoverage.bidiSequenceCaseCount,
  composedSequenceCaseCount: precisCoverage.composedSequenceCaseCount,
  negativeEncodingCaseCount: precisCoverage.negativeEncodingCaseCount,
  totalCaseCount: precisCoverage.totalCaseCount
};
if (protocolVerification?.dataAuthority
    !== "locked_independent_uts46_engines_and_same_pinned_unicode_source_for_precis"
  || canonicalJson(protocolVerification?.scope) !== canonicalJson(protocolScope)
  || canonicalJson(protocolVerification?.uts46Options) !== canonicalJson(uts46Coverage)
  || canonicalJson(protocolVerification?.requestShape) !== canonicalJson(protocolShapeCoverage)
  || canonicalJson(protocolVerification?.precis) !== canonicalJson(protocolPrecisCoverage)
  || canonicalJson(protocolVerification?.projectionExcludedFields)
    !== canonicalJson(["standards.engine", "witness.engine"])) {
  throw new Error("the committed protocol-profile scope does not match this differential run");
}

const differenceSpineRequests = requests.filter(
  (request) => request.operation === "reference_explain_difference_spine"
);
const differenceVerification = committedManifest.operations?.explain_difference?.independentVerification;
const differenceScope = {
  kind: "deterministic_spine",
  includedStages: DIFFERENCE_SPINE_PROJECTION.includedStages,
  excludedStages: DIFFERENCE_SPINE_PROJECTION.excludedStages,
  requiresValidNodeCollationRequest: true,
  completeConsumerParity: false
};
if (committedManifest.operations?.explain_difference?.verificationStatus
    !== "scoped_native_wasm_parity"
  || differenceVerification?.canonicalCaseCount !== differenceCoverage.canonicalCaseCount
  || differenceVerification?.additionalComparisonCaseCount
    !== differenceCoverage.totalCaseCount - differenceCoverage.canonicalCaseCount
  || differenceVerification?.totalCaseCount !== differenceCoverage.totalCaseCount
  || canonicalJson(differenceVerification?.projectionExcludedFields)
    !== canonicalJson(DIFFERENCE_SPINE_PROJECTION.excludedFields)
  || canonicalJson(differenceVerification?.scope) !== canonicalJson(differenceScope)
  || differenceVerification?.graphemeConformanceCaseCount
    !== differenceCoverage.graphemeConformanceCaseCount
  || differenceVerification?.normalizationConformanceCaseCount
    !== differenceCoverage.normalizationConformanceCaseCount
  || differenceVerification?.nfkcCasefoldCaseCount !== differenceCoverage.nfkcCasefoldCaseCount
  || differenceVerification?.confusableComparisonCaseCount
    !== differenceCoverage.confusableComparisonCaseCount
  || differenceVerification?.signalBoundaryCaseCount !== differenceCoverage.signalBoundaryCaseCount
  || differenceVerification?.composedSequenceCaseCount
    !== differenceCoverage.composedSequenceCaseCount
  || differenceSpineRequests.length !== differenceCoverage.totalCaseCount) {
  throw new Error(
    "the committed explain-difference deterministic-spine locator does not match this differential run"
  );
}

const securityVerification = committedManifest.operations?.security?.independentVerification;
if (securityVerification?.sourceManifestSha256 !== securityCoverage.sourceManifestSha256
  || canonicalJson(securityVerification?.sourceFiles) !== canonicalJson(securityCoverage.sourceFiles)
  || securityVerification?.propertyBoundaryCaseCount !== securityCoverage.propertyBoundaryCaseCount
  || securityVerification?.freeTextBoundaryCaseCount !== securityCoverage.freeTextBoundaryCaseCount
  || securityVerification?.xidProfileCaseCount !== securityCoverage.xidProfileCaseCount
  || securityVerification?.nfkcCasefoldProfileCaseCount
    !== securityCoverage.nfkcCasefoldProfileCaseCount
  || securityVerification?.confusableEnvelopeCaseCount
    !== securityCoverage.confusableEnvelopeCaseCount
  || securityVerification?.sequenceCaseCount !== securityCoverage.sequenceCaseCount
  || securityVerification?.negativeCaseCount !== securityCoverage.negativeCaseCount
  || canonicalJson(securityVerification?.sourceDiagnostics)
    !== canonicalJson(securityCoverage.sourceDiagnostics)
  || securityVerification?.additionalComparisonCaseCount !== securityCoverage.totalCaseCount
  || canonicalJson(securityVerification?.projectionExcludedFields)
    !== canonicalJson(["confusableComparison.engine"])
  || canonicalJson(securityVerification?.scope)
    !== canonicalJson({ modes: ["free_text", "identifier", "source"] })) {
  throw new Error("the committed security verification locator does not match this differential run");
}

const primitiveRequests = requests.filter((request) => request.operation === "reference_nfkc_casefold");
const primitiveLocator = committedManifest.primitives?.nfkcCasefold;
if (primitiveLocator?.verificationStatus !== "native_wasm_parity"
  || primitiveLocator.independentVerification?.sourceManifestSha256 !== nfkcCasefoldCoverage.sourceManifestSha256
  || primitiveLocator.independentVerification?.sourceFilePath !== nfkcCasefoldCoverage.sourceFilePath
  || primitiveLocator.independentVerification?.sourceFileSha256 !== nfkcCasefoldCoverage.sourceFileSha256
  || primitiveLocator.independentVerification?.mappingRowCount !== nfkcCasefoldCoverage.mappingRowCount
  || primitiveLocator.independentVerification?.mappedCodePointCaseCount
    !== nfkcCasefoldCoverage.mappedCodePointCaseCount
  || primitiveLocator.independentVerification?.identityBoundaryCaseCount
    !== nfkcCasefoldCoverage.identityBoundaryCaseCount
  || primitiveLocator.independentVerification?.sequenceCaseCount !== nfkcCasefoldCoverage.sequenceCaseCount
  || primitiveLocator.independentVerification?.totalCaseCount !== primitiveRequests.length) {
  throw new Error("the committed NFKC_Casefold primitive verification locator does not match this differential run");
}

const uts39SkeletonRequests = requests.filter(
  (request) => request.operation === "reference_uts39_post_reorder_skeleton"
);
const uts39SkeletonLocator = committedManifest.primitives?.uts39PostReorderSkeleton;
const uts39SkeletonVerification = uts39SkeletonLocator?.independentVerification;
if (uts39SkeletonLocator?.verificationStatus !== "native_wasm_parity"
  || uts39SkeletonVerification?.sourceManifestSha256
    !== uts39PostReorderSkeletonCoverage.sourceManifestSha256
  || uts39SkeletonVerification?.confusablesSourcePath
    !== uts39PostReorderSkeletonCoverage.confusablesSourcePath
  || uts39SkeletonVerification?.confusablesSourceSha256
    !== uts39PostReorderSkeletonCoverage.confusablesSourceSha256
  || uts39SkeletonVerification?.derivedCoreSourcePath
    !== uts39PostReorderSkeletonCoverage.derivedCoreSourcePath
  || uts39SkeletonVerification?.derivedCoreSourceSha256
    !== uts39PostReorderSkeletonCoverage.derivedCoreSourceSha256
  || uts39SkeletonVerification?.confusableMappingRowCount
    !== uts39PostReorderSkeletonCoverage.confusableMappingRowCount
  || uts39SkeletonVerification?.mappedSourceCaseCount
    !== uts39PostReorderSkeletonCoverage.mappedSourceCaseCount
  || uts39SkeletonVerification?.defaultIgnorableRangeCount
    !== uts39PostReorderSkeletonCoverage.defaultIgnorableRangeCount
  || uts39SkeletonVerification?.defaultIgnorableCodePointCount
    !== uts39PostReorderSkeletonCoverage.defaultIgnorableCodePointCount
  || uts39SkeletonVerification?.defaultIgnorableCaseCount
    !== uts39PostReorderSkeletonCoverage.defaultIgnorableCaseCount
  || uts39SkeletonVerification?.identityBoundaryCaseCount
    !== uts39PostReorderSkeletonCoverage.identityBoundaryCaseCount
  || uts39SkeletonVerification?.sequenceCaseCount
    !== uts39PostReorderSkeletonCoverage.sequenceCaseCount
  || uts39SkeletonVerification?.normalizationConformanceSourceCaseCount
    !== uts39PostReorderSkeletonCoverage.normalizationConformanceSourceCaseCount
  || uts39SkeletonVerification?.totalCaseCount !== uts39SkeletonRequests.length) {
  throw new Error("the committed UTS #39 skeleton primitive verification locator does not match this differential run");
}

const bidiSkeletonRequests = requests.filter(
  (request) => request.operation === "reference_bidi_skeleton"
);
const bidiSkeletonLocator = committedManifest.primitives?.bidiSkeleton;
const bidiSkeletonVerification = bidiSkeletonLocator?.independentVerification;
const bidiProjectionExcludedFields = [
  "engine",
  "standards.uba.algorithm",
  "standards.uba.hardcodedDataFeature",
  "standards.uba.dataSource",
  "resolvedLevels",
  "visualOrder",
  "entries",
  "reordered"
];
if (bidiSkeletonLocator?.verificationStatus !== "scoped_native_wasm_parity"
  || canonicalJson(bidiSkeletonVerification?.projectionExcludedFields)
    !== canonicalJson(bidiProjectionExcludedFields)
  || bidiSkeletonVerification?.totalCaseCount !== bidiSkeletonRequests.length
  || Object.entries(bidiSkeletonCoverage).some(
    ([field, value]) => bidiSkeletonVerification?.[field] !== value
  )) {
  throw new Error("the committed bidiSkeleton primitive verification locator does not match this differential run");
}

const confusableComparisonRequests = requests.filter(
  (request) => request.operation === "reference_confusable_comparison"
);
const confusableComparisonLocator = committedManifest.primitives?.confusableComparison;
const confusableComparisonVerification = confusableComparisonLocator?.independentVerification;
if (confusableComparisonLocator?.verificationStatus !== "native_wasm_parity"
  || canonicalJson(confusableComparisonVerification?.projectionExcludedFields)
    !== canonicalJson(["engine"])
  || confusableComparisonVerification?.totalCaseCount !== confusableComparisonRequests.length
  || Object.entries(confusableComparisonCoverage).some(
    ([field, value]) => confusableComparisonVerification?.[field] !== value
  )) {
  throw new Error(
    "the committed confusable-comparison primitive verification locator does not match this differential run"
  );
}

process.stdout.write(`${JSON.stringify({
  operations: operationCounts,
  scopedOperations: {
    protocolProfile: {
      uts46OfficialOperationCaseCount: 19167,
      uts46Options: uts46Coverage,
      requestShape: protocolShapeCoverage,
      precis: protocolPrecisCoverage
    },
    security: securityCoverage
  },
  primitives: {
    bidiSkeleton: bidiSkeletonCoverage,
    confusableComparison: confusableComparisonCoverage,
    nfkcCasefold: nfkcCasefoldCoverage,
    uts39PostReorderSkeleton: uts39PostReorderSkeletonCoverage
  },
  scopedConsumers: {
    explainDifference: differenceCoverage,
    namespaceIntegrity: namespaceCoverage
  },
  baseOperationRequestShape: baseOperationShapeCoverage,
  packagedReferenceWasm: {
    negativeRequestShapeCaseCount: baseOperationShapeRequests.length,
    completeSemanticResultSchemaValidation: true,
    result: "match"
  },
  rawBatchFraming: {
    contract: REFERENCE_WASM_RAW_ABI,
    ...batchFrameMeasurements,
    inputHeadroomBytes:
      REFERENCE_WASM_RAW_ABI.maxInputBytes - batchFrameMeasurements.maximumInput.bytes,
    differenceAlignmentHeadroomCells:
      REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells
        - batchFrameMeasurements.maximumDifferenceAlignmentCells.units,
    sourceDiagnosticHeadroomUnits:
      REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits
        - batchFrameMeasurements.maximumSourceDiagnosticUnits.units,
    uts46PunycodeHeadroomUnits:
      REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits
        - batchFrameMeasurements.maximumUts46PunycodeScanUnits.units,
    nativeOutputHeadroomBytes:
      REFERENCE_WASM_RAW_ABI.maxResultBytes - batchFrameMeasurements.maximumNativeOutput.bytes,
    wasmOutputHeadroomBytes:
      REFERENCE_WASM_RAW_ABI.maxResultBytes - batchFrameMeasurements.maximumWasmOutput.bytes
  },
  rawAbiBoundary,
  totalCases: requests.length,
  semanticRootSha256,
  native: "match",
  wasm: "match"
})}\n`);
