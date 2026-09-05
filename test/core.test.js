import test from "node:test";
import assert from "node:assert/strict";
import { executeOperation, SUPPORTED_OPERATIONS } from "../src/core/operations.js";
import { TextIntegrityError, errorPayload } from "../src/core/errors.js";
import {
  LIMITS,
  RESULT_METADATA_RESERVATION_BYTES,
  enforceResultBudget,
  splitResultProjections
} from "../src/core/limits.js";
import { analyzeNamespaceIntegrity, SUPPORTED_NAMESPACE_RELATIONS } from "../src/core/namespace-integrity.js";

const OPTIONS = Object.freeze({
  usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
  caseFirst: "false", localeMatcher: "best fit", collation: "default"
});
const IDENTIFIER = Object.freeze({ mode: "identifier", profile: "uts39_general_security" });

function expectCode(code, callback) {
  assert.throws(callback, (error) => error instanceof TextIntegrityError && error.code === code);
}

function publicError(operation, arguments_) {
  try {
    executeOperation(operation, arguments_);
    assert.fail(`${operation} unexpectedly accepted invalid input`);
  } catch (error) {
    assert.ok(error instanceof TextIntegrityError);
    return errorPayload(error);
  }
}

test("base-operation validation preserves the complete public error envelope and order", () => {
  assert.deepEqual(publicError("inspect", { text: "A", z: true, a: true }), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "Unknown fields are not allowed.",
      details: { unknownFields: ["a", "z"] }
    }
  });
  assert.deepEqual(publicError("inspect", { text: "A", detailLimit: 1.5 }), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "detailLimit must be an integer from 0 to 128.",
      details: { field: "detailLimit", minimum: 0, maximum: 128 }
    }
  });
  assert.deepEqual(publicError("normalize", { text: "A" }), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "Required fields are missing.",
      details: { missingFields: ["form"] }
    }
  });
  assert.deepEqual(publicError("normalize", { text: "A", form: "bad" }), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "form must be one of: NFC, NFD, NFKC, NFKD.",
      details: { field: "form", allowed: ["NFC", "NFD", "NFKC", "NFKD"] }
    }
  });
  assert.deepEqual(publicError("index", { text: "A", maxChunkUtf8Bytes: 0 }), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "maxChunkUtf8Bytes must be an integer from 1 to 4096.",
      details: { field: "maxChunkUtf8Bytes", minimum: 1, maximum: 4096 }
    }
  });
  assert.deepEqual(publicError("transcode", {
    sourceKind: "text", text: "A", allowLossy: false, byteRepresentation: "hex"
  }), {
    status: "error",
    error: {
      code: "UNSUPPORTED_ENCODING",
      message: "targetEncoding is not supported.",
      details: {
        field: "targetEncoding", requestedType: "undefined", supported: ["utf-8", "utf-16le"]
      }
    }
  });
  assert.deepEqual(publicError("transcode", {
    sourceKind: "text", text: "A", bytes: [65], sourceEncoding: "utf-8",
    targetEncoding: "utf-8", allowLossy: false, byteRepresentation: "hex"
  }), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "Unknown fields are not allowed.",
      details: { unknownFields: ["bytes", "sourceEncoding"] }
    }
  });
  assert.deepEqual(publicError("transcode", {
    sourceKind: "bytes", bytes: [65, 256], sourceEncoding: "utf-8",
    targetEncoding: "utf-8", allowLossy: false, byteRepresentation: "hex"
  }), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "Every byte must be an integer from 0 to 255.",
      details: { field: "bytes", index: 1 }
    }
  });
});

test("the core exposes exactly eight bounded deterministic operations", () => {
  assert.deepEqual(SUPPORTED_OPERATIONS, [
    "inspect", "normalize", "compare", "transcode", "security",
    "explain_difference", "index", "protocol_profile"
  ]);
  expectCode("UNKNOWN_OPERATION", () => executeOperation("translate", { text: "hello" }));
});

test("namespace integrity groups bounded same-scope collisions without adding an MCP operation", () => {
  const args = {
    items: [
      { id: "user-1", text: "paypal", scope: "tenant-a" },
      { id: "user-2", text: "pаypal", scope: "tenant-a" },
      { id: "user-3", text: "ＰａｙＰａｌ", scope: "tenant-a" },
      { id: "user-4", text: "paypal", scope: "tenant-b" }
    ],
    relations: ["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable"],
    confusableDirection: "LTR"
  };
  const result = analyzeNamespaceIntegrity(args);
  assert.equal(result.operation, "namespace_integrity");
  assert.deepEqual(result.groups.map(({ relation, memberIds }) => ({ relation, memberIds })), [
    { relation: "nfkc_casefold", memberIds: ["user-1", "user-3"] },
    { relation: "uts39_confusable", memberIds: ["user-1", "user-2"] }
  ]);
  assert.deepEqual(result.isolatedIds, ["user-4"]);
  assert.equal(result.summary.scopeCount, 2);
  assert.ok(result.groups.every((group) => !Object.hasOwn(group, "key") && /^[0-9a-f]{64}$/u.test(group.keySha256)));
  assert.equal(result.limitations.some((item) => item.includes("not anonymization")), true);
  assert.deepEqual(SUPPORTED_OPERATIONS, [
    "inspect", "normalize", "compare", "transcode", "security",
    "explain_difference", "index", "protocol_profile"
  ]);

  expectCode("DUPLICATE_ITEM_ID", () => analyzeNamespaceIntegrity({
    items: [{ id: "same", text: "a", scope: "x" }, { id: "same", text: "b", scope: "x" }],
    relations: ["exact"]
  }));
  expectCode("INVALID_INPUT", () => analyzeNamespaceIntegrity({ items: [], relations: [] }));
  expectCode("INVALID_INPUT", () => analyzeNamespaceIntegrity({
    items: [], relations: ["uts39_confusable"]
  }));
  expectCode("INVALID_INPUT", () => analyzeNamespaceIntegrity({
    items: [], relations: ["exact"], confusableDirection: "LTR"
  }));
  expectCode("REQUEST_TOO_LARGE", () => analyzeNamespaceIntegrity({
    items: Array.from({ length: 17 }, (_, index) => ({
      id: `large-${index}`,
      text: String.fromCharCode(65 + index).repeat(LIMITS.maxTextBytes),
      scope: "large"
    })),
    relations: ["exact"]
  }));
  expectCode("RESULT_TOO_LARGE", () => analyzeNamespaceIntegrity({
    items: Array.from({ length: LIMITS.maxNamespaceItems }, (_, index) => ({
      id: `item-${String(index).padStart(3, "0")}-${"x".repeat(116)}`,
      text: `unique-${index}`,
      scope: "large"
    })),
    relations: ["exact"]
  }));
  expectCode("INVALID_UNICODE", () => analyzeNamespaceIntegrity({
    items: [{ id: "\ud800", text: "a", scope: "x" }], relations: ["exact"]
  }));
  expectCode("INVALID_UNICODE", () => analyzeNamespaceIntegrity({
    items: [{ id: "a", text: "a", scope: "\udfff" }], relations: ["exact"]
  }));

  const deterministicOrder = analyzeNamespaceIntegrity({
    items: [
      { id: "\ue000", text: "first", scope: "\ue000" },
      { id: "\ue001", text: "first", scope: "\ue000" },
      { id: "𐀀", text: "second", scope: "𐀀" },
      { id: "𐀁", text: "second", scope: "𐀀" }
    ],
    relations: ["exact"]
  });
  assert.deepEqual(deterministicOrder.groups.map(({ scope, memberIds }) => ({ scope, memberIds })), [
    { scope: "𐀀", memberIds: ["𐀀", "𐀁"] },
    { scope: "\ue000", memberIds: ["\ue000", "\ue001"] }
  ]);
});

test("namespace integrity supports explicit protocol and runtime-bound declared-collation relations", () => {
  const domainOptions = {
    checkBidi: true, checkHyphens: true, checkJoiners: true, ignoreInvalidPunycode: false,
    transitionalProcessing: false, useSTD3ASCIIRules: true, verifyDNSLength: true
  };
  const protocol = { kind: "protocol", profile: "uts46_domain", action: "to_ascii", options: domainOptions };
  const declaredCollation = {
    kind: "declared_collation",
    locale: "en",
    options: { ...OPTIONS, sensitivity: "base" }
  };
  const result = analyzeNamespaceIntegrity({
    items: [
      { id: "domain-unicode", text: "faß.de", scope: "domains" },
      { id: "domain-ascii", text: "xn--fa-hia.de", scope: "domains" },
      { id: "name-accented", text: "résumé", scope: "names" },
      { id: "name-uppercase", text: "RESUME", scope: "names" },
      { id: "isolated", text: "other", scope: "names" }
    ],
    relations: [protocol, declaredCollation]
  });
  assert.deepEqual(result.groups.map(({ relation, memberIds }) => ({ relation, memberIds })), [
    { relation: "protocol", memberIds: ["domain-ascii", "domain-unicode"] },
    { relation: "declared_collation", memberIds: ["name-accented", "name-uppercase"] }
  ]);
  assert.equal(result.relations[0].definition.profile, "uts46_domain");
  assert.equal(result.relations[1].definition.resolvedOptions.sensitivity, "base");
  assert.equal(Object.hasOwn(result.groups[0], "keySha256"), true);
  assert.equal(Object.hasOwn(result.groups[1], "keySha256"), false);
  assert.equal(Object.hasOwn(result.groups[1], "memberSetSha256"), true);
  assert.doesNotMatch(JSON.stringify(result), /sortKey|protocolOutput|skeletonValue/u);
  assert.deepEqual(SUPPORTED_NAMESPACE_RELATIONS, [
    "exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable", "protocol", "declared_collation"
  ]);

  expectCode("INVALID_INPUT", () => analyzeNamespaceIntegrity({ items: [], relations: [protocol, protocol] }));
  expectCode("INVALID_INPUT", () => analyzeNamespaceIntegrity({
    items: [], relations: [declaredCollation], confusableDirection: "LTR"
  }));
  expectCode("INVALID_INPUT", () => analyzeNamespaceIntegrity({
    items: [], relations: [{ ...declaredCollation, options: { ...declaredCollation.options, sensitivity: "semantic" } }]
  }));
  expectCode("PROTOCOL_STRING_INVALID", () => analyzeNamespaceIntegrity({
    items: [{ id: "invalid", text: "-bad", scope: "domains" }], relations: [protocol]
  }));
});

test("inspection distinguishes code points, graphemes, encodings, and malformed UTF-16", () => {
  const value = executeOperation("inspect", { text: "e\u0301👨‍👩‍👧‍👦", detailLimit: 16 });
  assert.equal(value.counts.codePoints, 9);
  assert.equal(value.counts.graphemes, 2);
  assert.equal(value.counts.utf8Bytes, 28);
  const malformed = executeOperation("inspect", { text: "\ud800" });
  assert.equal(malformed.inputWellFormed, false);
  assert.equal(malformed.counts.utf8Bytes, null);
  assert.equal(malformed.encodings.utf16le.hex, "00d8");
  assert.equal(malformed.detail.codePoints[0].kind, "unpaired_surrogate");
});

test("grapheme segmentation remains available when the host segmenter is disabled", () => {
  const HostSegmenter = Intl.Segmenter;
  Intl.Segmenter = class DisabledSegmenter {
    constructor() {
      throw new Error("host grapheme segmenter was called");
    }
  };
  try {
    const family = "👨‍👩‍👧‍👦";
    const inspected = executeOperation("inspect", { text: `e\u0301${family}`, detailLimit: 8 });
    const indexed = executeOperation("index", { text: `A${family}B`, maxChunkUtf8Bytes: 25 });
    const malformed = executeOperation("inspect", { text: "\ud800\u0301\udc00", detailLimit: 8 });
    assert.equal(inspected.counts.graphemes, 2);
    assert.deepEqual(indexed.chunking.chunks.map((chunk) => chunk.text), ["A", family, "B"]);
    assert.deepEqual(malformed.detail.graphemes.map((entry) => entry.text), ["\ud800\u0301", "\udc00"]);
  } finally {
    Intl.Segmenter = HostSegmenter;
  }
});

test("normalization is non-mutating and reports canonical and compatibility relations", () => {
  const canonical = executeOperation("normalize", { text: "e\u0301", form: "NFC" });
  assert.equal(canonical.original, "e\u0301");
  assert.equal(canonical.normalized, "é");
  assert.equal(canonical.canonicalEquivalent, true);
  const compatibility = executeOperation("normalize", { text: "①", form: "NFKC" });
  assert.equal(compatibility.normalized, "1");
  assert.equal(compatibility.canonicalEquivalent, false);
  assert.equal(compatibility.compatibilityEquivalent, true);
  expectCode("INVALID_UNICODE", () => executeOperation("normalize", { text: "\ud800", form: "NFC" }));
});

test("normalization remains available when the host normalization primitive is disabled", () => {
  const hostNormalize = String.prototype.normalize;
  String.prototype.normalize = () => { throw new Error("host normalization was called"); };
  try {
    const canonical = executeOperation("normalize", { text: "\u1100\u1161\u11A8", form: "NFC" });
    const compatibility = executeOperation("normalize", { text: "①", form: "NFKD" });
    assert.equal(canonical.normalized, "각");
    assert.equal(compatibility.normalized, "1");
  } finally {
    String.prototype.normalize = hostNormalize;
  }
});

test("PRECIS case mapping remains available when the host lowercase primitive is disabled", () => {
  const hostLowercase = String.prototype.toLowerCase;
  String.prototype.toLowerCase = () => { throw new Error("host lowercase was called"); };
  try {
    const dottedI = executeOperation("protocol_profile", {
      profile: "precis_username_case_mapped", action: "enforce", text: "\u0130"
    });
    const finalSigma = executeOperation("protocol_profile", {
      profile: "precis_username_case_mapped", action: "enforce", text: "\u039F\u03A3"
    });
    const medialSigma = executeOperation("protocol_profile", {
      profile: "precis_username_case_mapped", action: "enforce", text: "\u039F\u03A3\u0391"
    });
    assert.equal(dottedI.output, "i\u0307");
    assert.equal(finalSigma.output, "\u03BF\u03C2");
    assert.equal(medialSigma.output, "\u03BF\u03C3\u03B1");
  } finally {
    String.prototype.toLowerCase = hostLowercase;
  }
});

test("normalization witnesses expose complete stages or fail instead of truncating", () => {
  const value = executeOperation("normalize", {
    text: "①A\u0315\u0300",
    form: "NFKC",
    witnessMode: "full_required"
  });
  assert.equal(value.normalized, "1À\u0315");
  assert.deepEqual(value.witness.stages, {
    input: ["U+2460", "U+0041", "U+0315", "U+0300"],
    decomposed: ["U+0031", "U+0041", "U+0315", "U+0300"],
    canonicalOrdered: ["U+0031", "U+0041", "U+0300", "U+0315"],
    compositions: [{
      starter: "U+0041",
      current: "U+0300",
      composite: "U+00C0",
      outputIndexCodePoint: 1
    }]
  });
  assert.equal(value.witness.canonicalReorderedPositionCount, 2);
  assert.equal(value.witness.compositionCount, 1);

  const maximumSummary = executeOperation("normalize", {
    text: "a".repeat(LIMITS.maxTextBytes),
    form: "NFC",
    witnessMode: "summary"
  });
  assert.equal(maximumSummary.witness.inputCodePointCount, LIMITS.maxTextBytes);
  assert.equal(Object.hasOwn(maximumSummary.witness, "stages"), false);
  expectCode("RESULT_TOO_LARGE", () => executeOperation("normalize", {
    text: "a".repeat(LIMITS.maxTextBytes),
    form: "NFC",
    witnessMode: "full_required"
  }));
  expectCode("INVALID_INPUT", () => executeOperation("normalize", {
    text: "a", form: "NFC", witnessMode: "full"
  }));
});

test("locale comparison requires and returns every explicit option", () => {
  const value = executeOperation("compare", { left: "A", right: "a", locale: "en", options: { ...OPTIONS, sensitivity: "base" } });
  assert.equal(value.collatesEqual, true);
  assert.equal(value.codeUnitEqual, false);
  assert.equal(value.requestedOptions.localeMatcher, "best fit");
  assert.equal(value.requestedOptions.collation, "default");
  expectCode("INVALID_INPUT", () => executeOperation("compare", {
    left: "a", right: "b", locale: "en", options: { ...OPTIONS, localeMatcher: undefined }
  }));
  expectCode("INVALID_LOCALE", () => executeOperation("compare", { left: "a", right: "b", locale: "not_a_locale", options: OPTIONS }));
  expectCode("REQUEST_TOO_LARGE", () => executeOperation("compare", { left: "a", right: "b", locale: "e".repeat(LIMITS.maxLocaleChars + 1), options: OPTIONS }));
});

test("transcoding reports BOM, exact round trips, invalid offsets, and every lossy replacement", () => {
  const encoded = executeOperation("transcode", {
    sourceKind: "text", text: "A😀", targetEncoding: "utf-16le", allowLossy: false, byteRepresentation: "hex"
  });
  assert.equal(encoded.hex, "41003dd800de");
  assert.equal("bytes" in encoded, false);
  assert.equal("base64" in encoded, false);
  const asBytes = executeOperation("transcode", {
    sourceKind: "text", text: "A😀", targetEncoding: "utf-16le", allowLossy: false, byteRepresentation: "bytes"
  });
  assert.deepEqual(asBytes.bytes, [0x41, 0x00, 0x3d, 0xd8, 0x00, 0xde]);
  assert.equal("hex" in asBytes, false);
  const asBase64 = executeOperation("transcode", {
    sourceKind: "text", text: "A😀", targetEncoding: "utf-16le", allowLossy: false, byteRepresentation: "base64"
  });
  assert.equal(asBase64.base64, Buffer.from("41003dd800de", "hex").toString("base64"));
  assert.equal("bytes" in asBase64, false);
  const decoded = executeOperation("transcode", {
    sourceKind: "bytes", bytes: [0xff, 0xfe, ...asBytes.bytes], sourceEncoding: "utf-16le", targetEncoding: "utf-8",
    allowLossy: false, byteRepresentation: "hex", witnessMode: "summary"
  });
  assert.equal(decoded.text, "﻿A😀");
  assert.equal(decoded.source.bom, "utf-16le");
  assert.equal(decoded.source.decodedThenReencodedEqual, true);
  assert.equal(decoded.source.firstInvalidByte, null);
  assert.deepEqual(decoded.witness.bom, { kind: "utf-16le", handling: "preserved_as_character" });
  const invalid = {
    sourceKind: "bytes", bytes: [0x61, 0xc3, 0x28], sourceEncoding: "utf-8", targetEncoding: "utf-8",
    allowLossy: false, byteRepresentation: "hex"
  };
  assert.throws(() => executeOperation("transcode", invalid), (error) => error.code === "DECODE_FAILED" && error.details.firstInvalidByte === 1);
  const lossy = executeOperation("transcode", { ...invalid, allowLossy: true });
  assert.equal(lossy.lossy, true);
  assert.equal(lossy.source.firstInvalidByte, 1);
  assert.match(lossy.text, /�/u);
  const witnessed = executeOperation("transcode", {
    ...invalid,
    bytes: [0x61, 0xe1, 0x80, 0x41, 0x80],
    allowLossy: true,
    witnessMode: "full_required"
  });
  assert.equal(witnessed.text, "a�A�");
  assert.equal(witnessed.witness.replacementCount, 2);
  assert.deepEqual(
    witnessed.witness.segments.filter((segment) => segment.kind === "replacement")
      .map(({ sourceStart, sourceEnd, targetStartByte, targetEndByte }) => ({
        sourceStart, sourceEnd, targetStartByte, targetEndByte
      })),
    [
      { sourceStart: 1, sourceEnd: 3, targetStartByte: 1, targetEndByte: 4 },
      { sourceStart: 4, sourceEnd: 5, targetStartByte: 5, targetEndByte: 8 }
    ]
  );
  const utf16Witness = executeOperation("transcode", {
    ...invalid,
    bytes: [0x30, 0xd8, 0xef],
    sourceEncoding: "utf-16le",
    allowLossy: true,
    witnessMode: "full_required"
  });
  assert.equal(utf16Witness.source.firstInvalidByte, 0);
  assert.deepEqual(
    utf16Witness.witness.segments.map(({ kind, sourceStart, sourceEnd }) => ({ kind, sourceStart, sourceEnd })),
    [{ kind: "replacement", sourceStart: 0, sourceEnd: 3 }]
  );
  const textWitness = executeOperation("transcode", {
    sourceKind: "text", text: "A\ud800B", targetEncoding: "utf-8", allowLossy: true,
    byteRepresentation: "hex", witnessMode: "full_required"
  });
  assert.equal(textWitness.witness.sourceUnit, "utf16_code_unit");
  assert.equal(textWitness.witness.replacementCount, 1);
  assert.equal("witness" in encoded, false);
  const summary = executeOperation("transcode", {
    sourceKind: "text", text: "a".repeat(LIMITS.maxTextBytes), targetEncoding: "utf-8", allowLossy: false,
    byteRepresentation: "hex", witnessMode: "summary"
  });
  assert.equal(summary.witness.segmentCount, LIMITS.maxTextBytes);
  assert.equal("segments" in summary.witness, false);
  expectCode("RESULT_TOO_LARGE", () => executeOperation("transcode", {
    sourceKind: "text", text: "a".repeat(LIMITS.maxTextBytes), targetEncoding: "utf-8", allowLossy: false,
    byteRepresentation: "hex", witnessMode: "full_required"
  }));
  expectCode("DECODE_FAILED", () => executeOperation("transcode", { ...invalid, bytes: [0x00], sourceEncoding: "utf-16le" }));
  expectCode("INVALID_INPUT", () => executeOperation("transcode", { ...invalid, byteRepresentation: "octal" }));
  expectCode("INVALID_INPUT", () => executeOperation("transcode", { ...invalid, byteRepresentation: undefined }));
  expectCode("INVALID_INPUT", () => executeOperation("transcode", { ...invalid, witnessMode: "full" }));
});

test("transcode witnesses reproduce executed codec segments over deterministic hostile byte samples", () => {
  let state = 0x7f4a7c15;
  const nextByte = () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state & 0xff;
  };
  for (const sourceEncoding of ["utf-8", "utf-16le"]) {
    for (let sample = 0; sample < 2000; sample += 1) {
      const bytes = Array.from({ length: sample % 9 }, nextByte);
      const result = executeOperation("transcode", {
        sourceKind: "bytes",
        bytes,
        sourceEncoding,
        targetEncoding: "utf-8",
        allowLossy: true,
        byteRepresentation: "hex",
        witnessMode: "summary"
      });
      assert.equal(result.witness.segmentCount >= result.witness.replacementCount, true);
    }
  }
});

test("transcoding remains available when the host decoder primitive is disabled", () => {
  const HostDecoder = globalThis.TextDecoder;
  globalThis.TextDecoder = class DisabledDecoder {
    constructor() {
      throw new Error("host decoder was called");
    }
  };
  try {
    const utf8 = executeOperation("transcode", {
      sourceKind: "bytes", bytes: [0x61, 0xe2, 0x28, 0xa1], sourceEncoding: "utf-8",
      targetEncoding: "utf-16le", allowLossy: true, byteRepresentation: "hex",
      witnessMode: "full_required"
    });
    const utf16 = executeOperation("transcode", {
      sourceKind: "bytes", bytes: [0x3d, 0xd8, 0x00], sourceEncoding: "utf-16le",
      targetEncoding: "utf-8", allowLossy: true, byteRepresentation: "bytes"
    });
    assert.equal(utf8.text, "a\ufffd(\ufffd");
    assert.equal(utf8.source.firstInvalidByte, 1);
    assert.equal(utf8.witness.replacementCount, 2);
    assert.equal(utf16.text, "\ufffd");
    assert.equal(utf16.source.firstInvalidByte, 0);
  } finally {
    globalThis.TextDecoder = HostDecoder;
  }
});

test("one call explains exact, normalized, casefolded, coordinate, newline, collation, and confusable differences", () => {
  const value = executeOperation("explain_difference", {
    left: "e\u0301\r\nраypal", right: "é\npaypal", locale: "en", options: OPTIONS, confusableDirection: "LTR",
    witnessMode: "full_required"
  });
  assert.equal(value.exact.equal, false);
  assert.equal(value.normalization.NFC.equal, false);
  assert.equal(value.firstDifference.codePoint.index, 0);
  assert.equal(value.firstDifference.codePoint.left.position.utf8Byte, 0);
  assert.equal(value.lineEndings.left.counts.crlf, 1);
  assert.equal(value.lineEndings.right.counts.lf, 1);
  assert.equal(value.collation.requestedOptions.localeMatcher, "best fit");
  assert.equal(typeof value.identifierConfusableComparison.uts39Confusable, "boolean");
  assert.deepEqual(value.witness.stageOrder, [
    "exact_representation", "normalization", "nfkc_casefold", "coordinate_mapping",
    "alignment", "unicode_signals", "line_endings", "collation", "identifier_confusable"
  ]);
  assert.equal(value.witness.transformations.normalization.NFC.leftOutput, "é\r\nраypal");
  assert.equal(value.witness.transformations.normalization.NFC.rightOutput, "é\npaypal");
  assert.equal(value.witness.factBoundaries.collation.environmentBound, true);
  assert.equal(value.witness.factBoundaries.coordinateMapping.authority, "bundled_unicode_17_uax29_revision_47");
  assert.equal(value.witness.factBoundaries.coordinateMapping.environmentBound, false);
  assert.equal(value.witness.factBoundaries.alignment.complete, true);
  assert.equal(value.witness.factBoundaries.identifierConfusable.internalSkeletonDisclosed, false);
  assert.doesNotMatch(JSON.stringify(value), /authorIntent|riskScore/u);

  const expansion = "\uFDFA".repeat(Math.floor(LIMITS.maxTextBytes / 3));
  const summary = executeOperation("explain_difference", {
    left: expansion, right: expansion, locale: "en", options: OPTIONS, confusableDirection: "LTR",
    detailLimit: 0, witnessMode: "summary"
  });
  assert.equal(summary.witness.transformations.normalization.NFKD.leftCodePointCount > expansion.length, true);
  assert.equal(Object.hasOwn(summary.witness.transformations.normalization.NFKD, "leftOutput"), false);
  expectCode("RESULT_TOO_LARGE", () => executeOperation("explain_difference", {
    left: expansion, right: expansion, locale: "en", options: OPTIONS, confusableDirection: "LTR",
    detailLimit: 0, witnessMode: "full_required"
  }));
  expectCode("INVALID_INPUT", () => executeOperation("explain_difference", {
    left: "a", right: "b", locale: "en", options: OPTIONS, confusableDirection: "LTR", witnessMode: "full"
  }));
});

test("difference witnesses align every exact code point and grapheme segment deterministically", () => {
  const left = "Aé🙂Z";
  const right = "Axe\u0301🙂Y";
  const full = executeOperation("explain_difference", {
    left, right, locale: "en", options: OPTIONS, confusableDirection: "LTR",
    detailLimit: 0, witnessMode: "full_required"
  });
  const summary = executeOperation("explain_difference", {
    left, right, locale: "en", options: OPTIONS, confusableDirection: "LTR",
    detailLimit: 0, witnessMode: "summary"
  });
  assert.deepEqual(
    {
      algorithm: full.witness.alignment.algorithm,
      tieBreak: full.witness.alignment.tieBreak,
      replacementGrouping: full.witness.alignment.replacementGrouping
    },
    {
      algorithm: "text-integrity.lcs-insert-delete-alignment/1",
      tieBreak: "highest_right_split_then_first_match",
      replacementGrouping: "contiguous_non_equal"
    }
  );
  assert.deepEqual(
    full.witness.alignment.codePoint.segments.map((segment) => [
      segment.kind,
      segment.left.startIndex,
      segment.left.endIndex,
      segment.right.startIndex,
      segment.right.endIndex
    ]),
    [
      ["equal", 0, 1, 0, 1],
      ["replace", 1, 2, 1, 4],
      ["equal", 2, 3, 4, 5],
      ["replace", 3, 4, 5, 6]
    ]
  );
  assert.deepEqual(
    full.witness.alignment.grapheme.segments.map((segment) => [
      segment.kind,
      segment.left.startIndex,
      segment.left.endIndex,
      segment.right.startIndex,
      segment.right.endIndex
    ]),
    [
      ["equal", 0, 1, 0, 1],
      ["replace", 1, 2, 1, 3],
      ["equal", 2, 3, 3, 4],
      ["replace", 3, 4, 4, 5]
    ]
  );
  assert.equal(full.witness.alignment.codePoint.matchedItemCount, 2);
  assert.equal(full.witness.alignment.codePoint.insertedItemCount, 4);
  assert.equal(full.witness.alignment.codePoint.deletedItemCount, 2);
  assert.equal(full.witness.alignment.codePoint.segments.at(-1).right.end.utf8Byte, 10);
  assert.equal(summary.witness.alignment.codePoint.segmentIndexSha256,
    full.witness.alignment.codePoint.segmentIndexSha256);
  assert.equal(summary.witness.alignment.grapheme.segmentIndexSha256,
    full.witness.alignment.grapheme.segmentIndexSha256);
  assert.equal(Object.hasOwn(summary.witness.alignment.codePoint, "segments"), false);
  assert.equal(Object.hasOwn(summary.witness.alignment.grapheme, "segments"), false);
  assert.equal(summary.witness.factBoundaries.alignment.complete, false);

  const repeated = executeOperation("explain_difference", {
    left: "aa", right: "a", locale: "en", options: OPTIONS, confusableDirection: "LTR",
    detailLimit: 0, witnessMode: "full_required"
  });
  assert.deepEqual(
    repeated.witness.alignment.codePoint.segments.map((segment) => [
      segment.kind, segment.left.startIndex, segment.left.endIndex,
      segment.right.startIndex, segment.right.endIndex
    ]),
    [["equal", 0, 1, 0, 1], ["delete", 1, 2, 1, 1]]
  );

  const manySegments = {
    left: "ab".repeat(32),
    right: "ac".repeat(32),
    locale: "en",
    options: OPTIONS,
    confusableDirection: "LTR",
    detailLimit: 0
  };
  const manySummary = executeOperation("explain_difference", {
    ...manySegments,
    witnessMode: "summary"
  });
  assert.equal(manySummary.witness.alignment.codePoint.segmentCount, 64);
  assert.equal(Object.hasOwn(manySummary.witness.alignment.codePoint, "segments"), false);
  expectCode("RESULT_TOO_LARGE", () => executeOperation("explain_difference", {
    ...manySegments,
    witnessMode: "full_required"
  }));
});

test("coordinate maps and chunks preserve extended grapheme boundaries", () => {
  const family = "👨‍👩‍👧‍👦";
  const value = executeOperation("index", { text: `A${family}\r\nB`, detailLimit: 16, maxChunkUtf8Bytes: 25 });
  assert.equal(value.counts.graphemes, 4);
  assert.equal(value.counts.lines, 2);
  assert.equal(value.detail.codePoints[1].start.utf8Byte, 1);
  assert.equal(value.detail.graphemes[1].text, family);
  assert.deepEqual(value.chunking.chunks.map((chunk) => chunk.text), ["A", family, "\r\nB"]);
  assert.equal(value.chunking.chunks.map((chunk) => chunk.text).join(""), `A${family}\r\nB`);
  expectCode("CHUNK_GRAPHEME_TOO_LARGE", () => executeOperation("index", { text: family, maxChunkUtf8Bytes: 24 }));
});

test("UTS #39 and UAX #31 profiles remain named, descriptive, and data-pinned", () => {
  const free = executeOperation("security", { text: "Hello 世界", mode: "free_text" });
  assert.equal(free.data.unicodeVersion, "17.0.0");
  assert.equal(free.data.uts39Revision, 32);
  assert.equal(free.data.manifestSha256, "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf");
  assert.equal(Object.hasOwn(free, "identifierProfile"), false);

  const identifier = executeOperation("security", {
    text: "pаypаl", ...IDENTIFIER, comparison: "paypal", confusableDirection: "LTR"
  });
  assert.equal(identifier.identifierProfile.name, "uts39_general_security");
  assert.equal(identifier.confusableComparison.relation, "confusable");
  assert.equal(identifier.confusableComparison.confusableClass, "mixed_script");
  assert.equal(Object.hasOwn(identifier.confusableComparison, "skeleton"), false);
  assert.doesNotMatch(JSON.stringify(identifier), /"(?:safe|malicious|spoofed|riskScore)"/u);

  const repeatableArguments = {
    text: "pаypаl", ...IDENTIFIER, comparison: "paypal", confusableDirection: "LTR"
  };
  const firstRepeatable = executeOperation("security", repeatableArguments);
  const expectedRepeatable = JSON.stringify(firstRepeatable);
  firstRepeatable.observations.characterDetail.characters[0].identifierTypes.push("Caller_Mutation");
  assert.throws(() => {
    firstRepeatable.confusableComparison.engine.conformance.push("Caller_Mutation.txt");
  }, TypeError);
  assert.equal(JSON.stringify(executeOperation("security", repeatableArguments)), expectedRepeatable);

  const xid = executeOperation("security", { text: "hello_1", mode: "identifier", profile: "uax31_xid" });
  assert.equal(xid.identifierProfile.conforms, true);
  const casefold = executeOperation("security", { text: "Straße", mode: "identifier", profile: "uax31_nfkc_casefold" });
  assert.equal(casefold.identifierProfile.transformedText, "strasse");
  const composedCasefold = executeOperation("security", { text: "A\u030A", mode: "identifier", profile: "uax31_nfkc_casefold" });
  assert.equal(composedCasefold.identifierProfile.transformedText, "å");
});

test("confusable processing removes default ignorables and implements bidiSkeleton", () => {
  const selector = executeOperation("security", {
    text: "☝", ...IDENTIFIER, comparison: "☝️", confusableDirection: "LTR"
  });
  assert.equal(selector.confusableComparison.relation, "confusable");
  assert.equal(selector.confusableComparison.skeletonsEqual, true);

  const bidi = executeOperation("security", {
    text: "A1<שׂ", ...IDENTIFIER, comparison: "Αשֺ>1", confusableDirection: "LTR"
  });
  assert.equal(bidi.confusableComparison.uts39Confusable, true);
  const identical = executeOperation("security", { text: "same", ...IDENTIFIER, comparison: "same", confusableDirection: "FS" });
  assert.equal(identical.confusableComparison.relation, "identical");
});

test("source diagnostics consume only explicit source and host spans", () => {
  const source = "let pаypаl = paypal;\rnext\u202E";
  const value = executeOperation("security", {
    source, mode: "source", confusableDirection: "LTR",
    spans: [
      { kind: "identifier", startUtf16: 4, endUtf16: 10, scope: "file" },
      { kind: "identifier", startUtf16: 13, endUtf16: 19, scope: "file" },
      { kind: "token", startUtf16: 0, endUtf16: source.length }
    ]
  });
  assert.equal(value.operation, "source_diagnose");
  assert.equal(value.diagnostics.confusableIdentifiers.count, 1);
  assert.equal(value.diagnostics.abnormalLineEndings.count, 1);
  assert.equal(value.diagnostics.hiddenCharacters.count, 1);
  assert.equal(value.limitations.some((item) => item.includes("No file")), true);
  const compatibilityConfusable = executeOperation("security", {
    source: "A Ａ", mode: "source", confusableDirection: "LTR",
    spans: [
      { kind: "identifier", startUtf16: 0, endUtf16: 1, scope: "file" },
      { kind: "identifier", startUtf16: 2, endUtf16: 3, scope: "file" }
    ]
  });
  assert.equal(compatibilityConfusable.diagnostics.confusableIdentifiers.count, 1);
  const differentScopes = executeOperation("security", {
    source: "A Ａ", mode: "source", confusableDirection: "LTR",
    spans: [
      { kind: "identifier", startUtf16: 0, endUtf16: 1, scope: "left" },
      { kind: "identifier", startUtf16: 2, endUtf16: 3, scope: "right" }
    ]
  });
  assert.equal(differentScopes.diagnostics.confusableIdentifiers.count, 0);
  expectCode("INVALID_SPAN", () => executeOperation("security", {
    source: "😀", mode: "source", spans: [{ kind: "token", startUtf16: 1, endUtf16: 2 }], confusableDirection: "LTR"
  }));
  assert.throws(() => executeOperation("security", {
    source: "a".repeat(LIMITS.maxTextBytes), mode: "source",
    spans: Array.from({ length: LIMITS.maxSourceSpans }, () => ({
      kind: "identifier", startUtf16: 0, endUtf16: LIMITS.maxTextBytes, scope: "file"
    })),
    confusableDirection: "LTR", detailLimit: 0
  }), (error) => error instanceof TextIntegrityError
    && error.code === "RESULT_TOO_LARGE"
    && error.details.budgetedBytes
      === error.details.semanticBytes + RESULT_METADATA_RESERVATION_BYTES
    && error.details.metadataReservationBytes === RESULT_METADATA_RESERVATION_BYTES
    && error.details.budgetedBytes > LIMITS.maxResultBytes);
});

test("UTS #46 and PRECIS are separate named protocol profiles", () => {
  const domainOptions = {
    checkBidi: true, checkHyphens: true, checkJoiners: true, ignoreInvalidPunycode: false,
    transitionalProcessing: false, useSTD3ASCIIRules: true, verifyDNSLength: true
  };
  const ascii = executeOperation("protocol_profile", {
    profile: "uts46_domain", action: "to_ascii", text: "faß.de", options: domainOptions,
    witnessMode: "full_required"
  });
  assert.equal(ascii.output, "xn--fa-hia.de");
  assert.deepEqual(ascii.witness.stages, [
    { stage: "input", text: "faß.de", codePointCount: 6, ascii: false },
    { stage: "engine_output", text: "xn--fa-hia.de", codePointCount: 13, ascii: true }
  ]);
  const unicode = executeOperation("protocol_profile", {
    profile: "uts46_domain", action: "to_unicode", text: ascii.output,
    options: Object.fromEntries(Object.entries(domainOptions).filter(([key]) => key !== "verifyDNSLength")),
    witnessMode: "summary"
  });
  assert.equal(unicode.output, "faß.de");
  assert.equal(unicode.witness.outputAscii, false);
  expectCode("PROTOCOL_STRING_INVALID", () => executeOperation("protocol_profile", { profile: "uts46_domain", action: "to_ascii", text: "-bad", options: domainOptions }));

  const mapped = executeOperation("protocol_profile", {
    profile: "precis_username_case_mapped", action: "enforce", text: "Ｕser",
    witnessMode: "full_required"
  });
  assert.equal(mapped.output, "user");
  assert.deepEqual(
    mapped.witness.sides[0].passes[0].events.filter((event) => event.kind === "transform")
      .map(({ stage, output, changed }) => ({ stage, output, changed })),
    [
      { stage: "width_mapping", output: "User", changed: true },
      { stage: "case_mapping", output: "user", changed: true },
      { stage: "nfc", output: "user", changed: false }
    ]
  );
  assert.equal(mapped.witness.sides[0].stabilizedAfterPass, 2);
  const contextual = executeOperation("protocol_profile", {
    profile: "precis_username_case_mapped", action: "enforce", text: "A\u0301\u03A3",
    witnessMode: "full_required"
  });
  assert.equal(contextual.output, "\u00E1\u03C2");
  assert.equal(
    contextual.witness.sides[0].passes[0].events.find((event) => event.stage === "case_mapping").output,
    "a\u0301\u03C2"
  );
  const preserved = executeOperation("protocol_profile", {
    profile: "precis_username_case_preserved", action: "compare", text: "User", comparison: "User",
    witnessMode: "summary"
  });
  assert.equal(preserved.equal, true);
  assert.deepEqual(preserved.witness.sides.map((side) => side.side), ["text", "comparison"]);
  const opaque = executeOperation("protocol_profile", { profile: "precis_opaque_string", action: "enforce", text: "A\u00A0B" });
  assert.equal(opaque.output, "A B");
  expectCode("PROTOCOL_STRING_INVALID", () => executeOperation("protocol_profile", { profile: "precis_username_case_mapped", action: "enforce", text: "a b" }));
  assert.throws(
    () => executeOperation("protocol_profile", { profile: "precis_username_case_mapped", action: "enforce", text: "\uFDD0" }),
    (error) => error.code === "PROTOCOL_STRING_INVALID" && error.details.property === "DISALLOWED"
  );
  assert.throws(
    () => executeOperation("protocol_profile", { profile: "precis_username_case_mapped", action: "enforce", text: "\u0378" }),
    (error) => error.code === "PROTOCOL_STRING_INVALID" && error.details.property === "UNASSIGNED"
  );
  expectCode("PROTOCOL_STRING_INVALID", () => executeOperation("protocol_profile", {
    profile: "precis_username_case_mapped", action: "enforce", text: "\u00B9"
  }));
  expectCode("PROTOCOL_STRING_INVALID", () => executeOperation("protocol_profile", {
    profile: "precis_username_case_mapped", action: "enforce", text: "\u212A"
  }));
  expectCode("PROTOCOL_STRING_INVALID", () => executeOperation("protocol_profile", {
    profile: "precis_username_case_preserved", action: "enforce", text: "\u212A"
  }));
  assert.equal(executeOperation("protocol_profile", {
    profile: "precis_opaque_string", action: "enforce", text: "\u00B9"
  }).output, "\u00B9");
  expectCode("INVALID_INPUT", () => executeOperation("protocol_profile", {
    profile: "precis_username_case_mapped", action: "enforce", text: "user", witnessMode: "full"
  }));
  const maximumSummary = executeOperation("protocol_profile", {
    profile: "precis_username_case_mapped", action: "compare",
    text: "A".repeat(LIMITS.maxTextBytes), comparison: "A".repeat(LIMITS.maxTextBytes),
    witnessMode: "summary"
  });
  assert.equal(maximumSummary.witness.sides.length, 2);
  expectCode("RESULT_TOO_LARGE", () => executeOperation("protocol_profile", {
    profile: "precis_username_case_mapped", action: "compare",
    text: "A".repeat(LIMITS.maxTextBytes), comparison: "A".repeat(LIMITS.maxTextBytes),
    witnessMode: "full_required"
  }));
});

test("strict keys, cumulative request budgets, complete result budgets, and repeatability are enforced", () => {
  expectCode("REQUEST_TOO_LARGE", () => executeOperation("inspect", { text: "a".repeat(LIMITS.maxTextBytes + 1) }));
  expectCode("REQUEST_TOO_LARGE", () => executeOperation("security", {
    text: "a".repeat(2049), ...IDENTIFIER, comparison: "b".repeat(2048), confusableDirection: "LTR"
  }));
  expectCode("INVALID_INPUT", () => executeOperation("inspect", { text: "ok", invented: true }));
  const request = { text: "pаypаl", ...IDENTIFIER, comparison: "paypal", confusableDirection: "LTR" };
  assert.deepEqual(executeOperation("security", request), executeOperation("security", request));
  for (const [name, args] of [
    ["inspect", { text: "😀".repeat(1000), detailLimit: 128 }],
    ["transcode", { sourceKind: "bytes", bytes: Array(4096).fill(65), sourceEncoding: "utf-8", targetEncoding: "utf-16le", allowLossy: false, byteRepresentation: "bytes" }],
    ["index", { text: "a".repeat(4096), detailLimit: 64 }]
  ]) {
    assert.ok(Buffer.byteLength(JSON.stringify(executeOperation(name, args)), "utf8") <= LIMITS.maxResultBytes);
  }
});

test("complete-result budgets reuse the non-mutating semantic/environment split", () => {
  const value = {
    status: "ok",
    operation: "security",
    payload: "",
    confusableComparison: {
      relation: "confusable",
      engine: {
        name: "bounded-engine-label",
        version: "1.0.0",
        sourceSha256: "a".repeat(64)
      }
    },
    runtime: { node: "22.22.1", icu: "78.2", unicode: "17.0", cldr: "48.0" }
  };
  const semanticOverhead = Buffer.byteLength(JSON.stringify(splitResultProjections(value).semantic), "utf8");
  value.payload = "a".repeat(
    LIMITS.maxResultBytes - RESULT_METADATA_RESERVATION_BYTES - semanticOverhead
  );
  const preserved = structuredClone(value);
  assert.equal(enforceResultBudget(value), value);
  assert.deepEqual(value, preserved);
  const { semantic, environment } = splitResultProjections(value);
  assert.equal(
    Buffer.byteLength(JSON.stringify(semantic), "utf8") + RESULT_METADATA_RESERVATION_BYTES,
    LIMITS.maxResultBytes
  );
  assert.equal(Object.hasOwn(semantic.confusableComparison, "engine"), false);
  assert.equal(environment.confusableComparison.engine.name, "bounded-engine-label");
});
