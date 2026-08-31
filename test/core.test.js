import test from "node:test";
import assert from "node:assert/strict";
import { executeOperation, SUPPORTED_OPERATIONS } from "../src/core/operations.js";
import { TextIntegrityError } from "../src/core/errors.js";
import { LIMITS } from "../src/core/limits.js";

const OPTIONS = Object.freeze({
  usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
  caseFirst: "false", localeMatcher: "best fit", collation: "default"
});
const IDENTIFIER = Object.freeze({ mode: "identifier", profile: "uts39_general_security" });

function expectCode(code, callback) {
  assert.throws(callback, (error) => error instanceof TextIntegrityError && error.code === code);
}

test("the core exposes exactly eight bounded deterministic operations", () => {
  assert.deepEqual(SUPPORTED_OPERATIONS, [
    "inspect", "normalize", "compare", "transcode", "security",
    "explain_difference", "index", "protocol_profile"
  ]);
  expectCode("UNKNOWN_OPERATION", () => executeOperation("translate", { text: "hello" }));
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
    allowLossy: false, byteRepresentation: "hex"
  });
  assert.equal(decoded.text, "﻿A😀");
  assert.equal(decoded.source.bom, "utf-16le");
  assert.equal(decoded.source.decodedThenReencodedEqual, true);
  assert.equal(decoded.source.firstInvalidByte, null);
  const invalid = {
    sourceKind: "bytes", bytes: [0x61, 0xc3, 0x28], sourceEncoding: "utf-8", targetEncoding: "utf-8",
    allowLossy: false, byteRepresentation: "hex"
  };
  assert.throws(() => executeOperation("transcode", invalid), (error) => error.code === "DECODE_FAILED" && error.details.firstInvalidByte === 1);
  const lossy = executeOperation("transcode", { ...invalid, allowLossy: true });
  assert.equal(lossy.lossy, true);
  assert.equal(lossy.source.firstInvalidByte, 1);
  assert.match(lossy.text, /�/u);
  expectCode("DECODE_FAILED", () => executeOperation("transcode", { ...invalid, bytes: [0x00], sourceEncoding: "utf-16le" }));
  expectCode("INVALID_INPUT", () => executeOperation("transcode", { ...invalid, byteRepresentation: "octal" }));
  expectCode("INVALID_INPUT", () => executeOperation("transcode", { ...invalid, byteRepresentation: undefined }));
});

test("one call explains exact, normalized, casefolded, coordinate, newline, collation, and confusable differences", () => {
  const value = executeOperation("explain_difference", {
    left: "e\u0301\r\nраypal", right: "é\npaypal", locale: "en", options: OPTIONS, confusableDirection: "LTR"
  });
  assert.equal(value.exact.equal, false);
  assert.equal(value.normalization.NFC.equal, false);
  assert.equal(value.firstDifference.codePoint.index, 0);
  assert.equal(value.firstDifference.codePoint.left.position.utf8Byte, 0);
  assert.equal(value.lineEndings.left.counts.crlf, 1);
  assert.equal(value.lineEndings.right.counts.lf, 1);
  assert.equal(value.collation.requestedOptions.localeMatcher, "best fit");
  assert.equal(typeof value.identifierConfusableComparison.uts39Confusable, "boolean");
  assert.doesNotMatch(JSON.stringify(value), /authorIntent|riskScore/u);
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
  assert.equal(free.data.manifestSha256, "1ffde2215f0cada8c74e656afdb0a92226c1b293f1ef68776bed2e583869b4a7");
  assert.equal(Object.hasOwn(free, "identifierProfile"), false);

  const identifier = executeOperation("security", {
    text: "pаypаl", ...IDENTIFIER, comparison: "paypal", confusableDirection: "LTR"
  });
  assert.equal(identifier.identifierProfile.name, "uts39_general_security");
  assert.equal(identifier.confusableComparison.relation, "confusable");
  assert.equal(identifier.confusableComparison.confusableClass, "mixed_script");
  assert.equal(Object.hasOwn(identifier.confusableComparison, "skeleton"), false);
  assert.doesNotMatch(JSON.stringify(identifier), /"(?:safe|malicious|spoofed|riskScore)"/u);

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
});

test("UTS #46 and PRECIS are separate named protocol profiles", () => {
  const domainOptions = {
    checkBidi: true, checkHyphens: true, checkJoiners: true, ignoreInvalidPunycode: false,
    transitionalProcessing: false, useSTD3ASCIIRules: true, verifyDNSLength: true
  };
  const ascii = executeOperation("protocol_profile", { profile: "uts46_domain", action: "to_ascii", text: "faß.de", options: domainOptions });
  assert.equal(ascii.output, "xn--fa-hia.de");
  const unicode = executeOperation("protocol_profile", {
    profile: "uts46_domain", action: "to_unicode", text: ascii.output,
    options: Object.fromEntries(Object.entries(domainOptions).filter(([key]) => key !== "verifyDNSLength"))
  });
  assert.equal(unicode.output, "faß.de");
  expectCode("PROTOCOL_STRING_INVALID", () => executeOperation("protocol_profile", { profile: "uts46_domain", action: "to_ascii", text: "-bad", options: domainOptions }));

  const mapped = executeOperation("protocol_profile", { profile: "precis_username_case_mapped", action: "enforce", text: "Ｕser" });
  assert.equal(mapped.output, "user");
  const preserved = executeOperation("protocol_profile", { profile: "precis_username_case_preserved", action: "compare", text: "User", comparison: "User" });
  assert.equal(preserved.equal, true);
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
