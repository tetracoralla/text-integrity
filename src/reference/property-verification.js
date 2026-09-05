import { analyzeNamespaceIntegrity } from "../core/namespace-integrity.js";
import { TextIntegrityError } from "../core/errors.js";
import { executeOperation } from "../core/operations.js";
import { runtimeInfo } from "../core/runtime.js";
import { canonicalDigest } from "./canonical.js";
import { PROPERTY_VERIFICATION_SCHEMA_VERSION } from "./versions.js";

export { PROPERTY_VERIFICATION_SCHEMA_VERSION } from "./versions.js";

export const PROPERTY_VERIFICATION_LIMITS = Object.freeze({
  generatedTextCases: 256,
  generatedProtocolCases: 64,
  maxGeneratedCodePoints: 24,
  maxSerializedBytes: 8192
});

const SEED = 0x9e3779b9;
const NORMALIZATION_FORMS = Object.freeze(["NFC", "NFD", "NFKC", "NFKD"]);
const COLLATION_OPTIONS = Object.freeze({
  usage: "sort",
  sensitivity: "variant",
  ignorePunctuation: false,
  numeric: false,
  caseFirst: "false",
  localeMatcher: "best fit",
  collation: "default"
});
const SCALAR_PROBES = Object.freeze([
  0x0000, 0x000a, 0x000d, 0x0020, 0x0041, 0x0061, 0x0030, 0x007f,
  0x00e9, 0x00df, 0x0130, 0x0300, 0x0301, 0x034f, 0x061c, 0x093c,
  0x094d, 0x1100, 0x1161, 0x11a8, 0x200d, 0x202e, 0x2066, 0x212b,
  0x2460, 0xfe0f, 0xff21, 0x1f1e6, 0x1f3fb, 0x1f468, 0x1f469,
  0x1f4a9, 0x10ffff
]);
const PROTOCOL_PROBES = Object.freeze([
  "a", "B", "7", "é", "e\u0301", "ß", "Σ", "ς", "Ｕ", "Ｋ"
]);

function xorshift32(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function generatedScalar(next) {
  if ((next() & 1) === 0) return SCALAR_PROBES[next() % SCALAR_PROBES.length];
  while (true) {
    const value = next() % 0x110000;
    if (value < 0xd800 || value > 0xdfff) return value;
  }
}

function generateCorpus() {
  const next = xorshift32(SEED);
  const texts = Array.from(
    { length: PROPERTY_VERIFICATION_LIMITS.generatedTextCases },
    (_, index) => {
      const length = index === 0 ? 0 : next() % (PROPERTY_VERIFICATION_LIMITS.maxGeneratedCodePoints + 1);
      return Array.from({ length }, () => String.fromCodePoint(generatedScalar(next))).join("");
    }
  );
  const protocolTexts = Array.from(
    { length: PROPERTY_VERIFICATION_LIMITS.generatedProtocolCases },
    () => Array.from(
      { length: 1 + (next() % 8) },
      () => PROTOCOL_PROBES[next() % PROTOCOL_PROBES.length]
    ).join("")
  );
  return { texts, protocolTexts };
}

function propertyRecord(records, id, target, caseCount, environmentBound, run) {
  let assertionCount = 0;
  const check = (condition, caseIndex, assertion) => {
    assertionCount += 1;
    if (!condition) {
      throw new Error(`Property ${id} failed at case ${caseIndex}: ${assertion}.`);
    }
  };
  run(check);
  records.push({
    id,
    target,
    environmentBound,
    caseCount,
    assertionCount,
    passed: true
  });
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function expectCode(callback, expectedCode) {
  try {
    callback();
  } catch (error) {
    return error instanceof TextIntegrityError && error.code === expectedCode;
  }
  return false;
}

function verifyNormalization(records, texts) {
  propertyRecord(
    records,
    "normalization_closure",
    "normalize",
    texts.length,
    false,
    (check) => texts.forEach((text, index) => {
      const results = {};
      for (const form of NORMALIZATION_FORMS) {
        const first = executeOperation("normalize", { text, form });
        const second = executeOperation("normalize", { text: first.normalized, form });
        results[form] = first;
        check(first.original === text, index, `${form} retained the explicit source`);
        check(first.normalized.isWellFormed(), index, `${form} returned well-formed text`);
        check(second.normalized === first.normalized, index, `${form} was idempotent`);
        check(second.changed === false, index, `${form} stabilized after one pass`);
        check(
          form === "NFC" || form === "NFD"
            ? first.canonicalEquivalent === true
            : first.compatibilityEquivalent === true,
          index,
          `${form} reported its named equivalence`
        );
      }
      check(
        executeOperation("normalize", { text: results.NFD.normalized, form: "NFC" }).normalized
          === results.NFC.normalized,
        index,
        "NFD then NFC reached the NFC closure"
      );
      check(
        executeOperation("normalize", { text: results.NFC.normalized, form: "NFD" }).normalized
          === results.NFD.normalized,
        index,
        "NFC then NFD reached the NFD closure"
      );
      check(
        executeOperation("normalize", { text: results.NFKD.normalized, form: "NFKC" }).normalized
          === results.NFKC.normalized,
        index,
        "NFKD then NFKC reached the NFKC closure"
      );
      check(
        executeOperation("normalize", { text: results.NFKC.normalized, form: "NFKD" }).normalized
          === results.NFKD.normalized,
        index,
        "NFKC then NFKD reached the NFKD closure"
      );
    })
  );
}

function verifyTranscoding(records, texts) {
  propertyRecord(
    records,
    "lossless_transcode_round_trip",
    "transcode",
    texts.length * 2,
    false,
    (check) => texts.forEach((text, index) => {
      for (const encoding of ["utf-8", "utf-16le"]) {
        const encoded = executeOperation("transcode", {
          sourceKind: "text",
          text,
          targetEncoding: encoding,
          allowLossy: false,
          byteRepresentation: "bytes"
        });
        const decoded = executeOperation("transcode", {
          sourceKind: "bytes",
          bytes: encoded.bytes,
          sourceEncoding: encoding,
          targetEncoding: encoding,
          allowLossy: false,
          byteRepresentation: "bytes"
        });
        check(encoded.text === text, index, `${encoding} retained source text`);
        check(decoded.text === text, index, `${encoding} decoded to the same text`);
        check(decoded.lossy === false, index, `${encoding} remained lossless`);
        check(decoded.source.decodedThenReencodedEqual === true, index, `${encoding} bytes round-tripped`);
        check(sameJson(decoded.bytes, encoded.bytes), index, `${encoding} byte identity was stable`);
        check(decoded.byteLength === encoded.byteLength, index, `${encoding} byte length was stable`);
      }
    })
  );
}

function verifyIndexing(records, texts) {
  propertyRecord(
    records,
    "coordinate_and_chunk_reconstruction",
    "index",
    texts.length,
    false,
    (check) => texts.forEach((text, index) => {
      const result = executeOperation("index", {
        text,
        detailLimit: 128,
        maxChunkUtf8Bytes: 128
      });
      check(result.detail.codePoints.map(({ character }) => character).join("") === text, index, "code points reconstructed input");
      check(result.detail.graphemes.map(({ text: item }) => item).join("") === text, index, "graphemes reconstructed input");
      check(result.chunking.chunks.map(({ text: item }) => item).join("") === text, index, "chunks reconstructed input");
      check(result.detail.codePointsTruncated === false, index, "code-point detail was complete");
      check(result.detail.graphemesTruncated === false, index, "grapheme detail was complete");
      check(result.counts.codePoints === [...text].length, index, "code-point count matched iteration");
      check(result.counts.utf16CodeUnits === text.length, index, "UTF-16 count matched string length");
      check(result.counts.utf8Bytes === Buffer.byteLength(text, "utf8"), index, "UTF-8 count matched encoded bytes");
      check(result.chunking.chunks.every((chunk) =>
        chunk.utf8Bytes === Buffer.byteLength(chunk.text, "utf8") && chunk.utf8Bytes <= 128
      ), index, "every chunk respected its byte boundary");
      check(result.chunking.chunks.every((chunk, chunkIndex, chunks) => chunkIndex === 0
        || chunk.start.utf8Byte === chunks[chunkIndex - 1].end.utf8Byte
          && chunk.start.utf16CodeUnit === chunks[chunkIndex - 1].end.utf16CodeUnit
          && chunk.start.codePoint === chunks[chunkIndex - 1].end.codePoint
          && chunk.start.grapheme === chunks[chunkIndex - 1].end.grapheme
      ), index, "chunk coordinates were contiguous");
    })
  );
}

function verifyDifferenceAlignment(records, texts) {
  const pairCount = texts.length / 2;
  propertyRecord(
    records,
    "difference_alignment_conservation",
    "explain_difference",
    pairCount,
    false,
    (check) => Array.from({ length: pairCount }, (_, index) => {
      const left = texts[index];
      const right = texts[index + pairCount];
      const args = {
        left,
        right,
        locale: "en",
        options: COLLATION_OPTIONS,
        confusableDirection: "LTR",
        detailLimit: 0
      };
      const full = executeOperation("explain_difference", {
        ...args,
        witnessMode: "full_required"
      }).witness.alignment;
      const summary = executeOperation("explain_difference", {
        ...args,
        witnessMode: "summary"
      }).witness.alignment;
      for (const key of ["codePoint", "grapheme"]) {
        const alignment = full[key];
        const compact = summary[key];
        const segments = alignment.segments;
        let leftCursor = 0;
        let rightCursor = 0;
        const contiguous = segments.every((segment) => {
          const matches = segment.left.startIndex === leftCursor
            && segment.right.startIndex === rightCursor;
          leftCursor = segment.left.endIndex;
          rightCursor = segment.right.endIndex;
          return matches;
        });
        check(segments.length === alignment.segmentCount, index, `${key} segment count was complete`);
        check(
          contiguous
            && leftCursor === alignment.leftItemCount
            && rightCursor === alignment.rightItemCount,
          index,
          `${key} segments covered both inputs contiguously`
        );
        check(
          alignment.matchedItemCount + alignment.deletedItemCount === alignment.leftItemCount,
          index,
          `${key} left items were conserved`
        );
        check(
          alignment.matchedItemCount + alignment.insertedItemCount === alignment.rightItemCount,
          index,
          `${key} right items were conserved`
        );
        check(segments.filter(({ kind }) => kind === "equal").every((segment) =>
          left.slice(segment.left.start.utf16CodeUnit, segment.left.end.utf16CodeUnit)
            === right.slice(segment.right.start.utf16CodeUnit, segment.right.end.utf16CodeUnit)
        ), index, `${key} equal spans contained identical source text`);
        check(segments.every((segment) => {
          const leftLength = segment.left.endIndex - segment.left.startIndex;
          const rightLength = segment.right.endIndex - segment.right.startIndex;
          if (segment.kind === "equal") return leftLength > 0 && rightLength > 0;
          if (segment.kind === "insert") return leftLength === 0 && rightLength > 0;
          if (segment.kind === "delete") return leftLength > 0 && rightLength === 0;
          return segment.kind === "replace" && leftLength > 0 && rightLength > 0;
        }), index, `${key} change kinds matched their index ranges`);
        const coordinateField = key === "codePoint" ? "codePoint" : "grapheme";
        check(segments.every((segment) =>
          segment.left.start[coordinateField] === segment.left.startIndex
            && segment.left.end[coordinateField] === segment.left.endIndex
            && segment.right.start[coordinateField] === segment.right.startIndex
            && segment.right.end[coordinateField] === segment.right.endIndex
        ), index, `${key} item indexes matched complete coordinates`);
        check(
          compact.segmentIndexSha256 === alignment.segmentIndexSha256
            && compact.segmentCount === alignment.segmentCount
            && !Object.hasOwn(compact, "segments"),
          index,
          `${key} summary retained complete identity without expanded segments`
        );
      }
    })
  );
}

function verifyCollation(records, texts) {
  propertyRecord(
    records,
    "declared_collation_algebra",
    "compare",
    texts.length,
    true,
    (check) => texts.forEach((left, index) => {
      const right = texts[(index + 1) % texts.length];
      const same = executeOperation("compare", { left, right: left, locale: "en", options: COLLATION_OPTIONS });
      const forward = executeOperation("compare", { left, right, locale: "en", options: COLLATION_OPTIONS });
      const reverse = executeOperation("compare", { left: right, right: left, locale: "en", options: COLLATION_OPTIONS });
      check(same.order === 0 && same.collatesEqual === true, index, "self comparison was equal");
      check(forward.order === -reverse.order, index, "pair order was antisymmetric");
      check(forward.canonicalLocale === reverse.canonicalLocale, index, "canonical locale was stable");
      check(sameJson(forward.resolvedOptions, reverse.resolvedOptions), index, "resolved options were stable");
    })
  );
}

function verifyNamespace(records, texts) {
  const batchSize = 8;
  const batchCount = texts.length / batchSize;
  propertyRecord(
    records,
    "namespace_input_permutation_invariance",
    "namespace_integrity",
    batchCount,
    false,
    (check) => Array.from({ length: batchCount }, (_, batchIndex) => {
      const items = texts.slice(batchIndex * batchSize, (batchIndex + 1) * batchSize)
        .map((text, index) => ({ id: `b${batchIndex}-i${index}`, text, scope: `s${batchIndex % 3}` }));
      const argumentsValue = {
        items,
        relations: ["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable"],
        confusableDirection: "LTR"
      };
      const forward = analyzeNamespaceIntegrity(argumentsValue);
      const reversed = analyzeNamespaceIntegrity({ ...argumentsValue, items: [...items].reverse() });
      check(sameJson(forward, reversed), batchIndex, "item order did not change the result");
    })
  );
}

function verifyPrecis(records, protocolTexts) {
  const profiles = [
    "precis_username_case_mapped",
    "precis_username_case_preserved",
    "precis_opaque_string"
  ];
  propertyRecord(
    records,
    "precis_enforcement_stability",
    "protocol_profile",
    protocolTexts.length * profiles.length,
    false,
    (check) => protocolTexts.forEach((text, index) => profiles.forEach((profile) => {
      const first = executeOperation("protocol_profile", { profile, action: "enforce", text });
      const second = executeOperation("protocol_profile", { profile, action: "enforce", text: first.output });
      const comparison = executeOperation("protocol_profile", {
        profile,
        action: "compare",
        text,
        comparison: first.output
      });
      check(second.output === first.output, index, `${profile} stabilized after enforcement`);
      check(comparison.equal === true, index, `${profile} compared source and enforced output equivalently`);
    }))
  );
}

function verifyRequestMutations(records) {
  const compareArguments = {
    left: "a",
    right: "b",
    locale: "en",
    options: COLLATION_OPTIONS
  };
  const domainOptions = {
    checkBidi: true,
    checkHyphens: true,
    checkJoiners: true,
    ignoreInvalidPunycode: false,
    transitionalProcessing: false,
    useSTD3ASCIIRules: true,
    verifyDNSLength: true
  };
  const mutations = [
    [() => executeOperation("inspect", { text: "a", unexpected: true }), "INVALID_INPUT"],
    [() => executeOperation("normalize", { text: "a", form: "NFC", unexpected: true }), "INVALID_INPUT"],
    [() => executeOperation("compare", { ...compareArguments, unexpected: true }), "INVALID_INPUT"],
    [() => executeOperation("compare", {
      ...compareArguments,
      options: { ...COLLATION_OPTIONS, unexpected: true }
    }), "INVALID_INPUT"],
    [() => executeOperation("transcode", {
      sourceKind: "text", text: "a", targetEncoding: "utf-8", allowLossy: false,
      byteRepresentation: "bytes", unexpected: true
    }), "INVALID_INPUT"],
    [() => executeOperation("security", { text: "a", mode: "free_text", unexpected: true }), "INVALID_INPUT"],
    [() => executeOperation("security", {
      source: "a", mode: "source", spans: [{
        kind: "token", startUtf16: 0, endUtf16: 1, unexpected: true
      }], confusableDirection: "LTR"
    }), "INVALID_INPUT"],
    [() => executeOperation("explain_difference", {
      ...compareArguments, confusableDirection: "LTR", unexpected: true
    }), "INVALID_INPUT"],
    [() => executeOperation("index", { text: "a", unexpected: true }), "INVALID_INPUT"],
    [() => executeOperation("protocol_profile", {
      profile: "precis_username_case_mapped", action: "enforce", text: "a", unexpected: true
    }), "INVALID_INPUT"],
    [() => executeOperation("protocol_profile", {
      profile: "uts46_domain", action: "to_ascii", text: "example.com",
      options: { ...domainOptions, unexpected: true }
    }), "INVALID_INPUT"],
    [() => analyzeNamespaceIntegrity({ items: [], relations: ["exact"], unexpected: true }), "INVALID_INPUT"],
    [() => analyzeNamespaceIntegrity({
      items: [{ id: "a", text: "a", scope: "s", unexpected: true }], relations: ["exact"]
    }), "INVALID_INPUT"],
    [() => executeOperation("unknown", {}), "UNKNOWN_OPERATION"]
  ];
  propertyRecord(
    records,
    "closed_request_mutation_rejection",
    "all_public_operations",
    mutations.length,
    false,
    (check) => mutations.forEach(([callback, code], index) => {
      check(expectCode(callback, code), index, `mutation was rejected as ${code}`);
    })
  );
}

export function runPropertyVerification() {
  const corpus = generateCorpus();
  const properties = [];
  verifyNormalization(properties, corpus.texts);
  verifyTranscoding(properties, corpus.texts);
  verifyIndexing(properties, corpus.texts);
  verifyDifferenceAlignment(properties, corpus.texts);
  verifyCollation(properties, corpus.texts);
  verifyNamespace(properties, corpus.texts);
  verifyPrecis(properties, corpus.protocolTexts);
  verifyRequestMutations(properties);

  const generator = {
    algorithm: "xorshift32",
    revision: 1,
    seedHex: `0x${SEED.toString(16).padStart(8, "0")}`,
    generatedTextCases: corpus.texts.length,
    generatedProtocolCases: corpus.protocolTexts.length,
    maxGeneratedCodePoints: PROPERTY_VERIFICATION_LIMITS.maxGeneratedCodePoints,
    corpusSha256: canonicalDigest(corpus)
  };
  const result = {
    schemaVersion: PROPERTY_VERIFICATION_SCHEMA_VERSION,
    authority: "deterministic_check_observation",
    scope: "fixed_generated_corpus_and_named_properties_only",
    selfCertifying: false,
    complete: true,
    passed: true,
    generator,
    properties,
    totals: {
      propertyCount: properties.length,
      caseEvaluationCount: properties.reduce((total, property) => total + property.caseCount, 0),
      assertionCount: properties.reduce((total, property) => total + property.assertionCount, 0)
    },
    propertyRootSha256: canonicalDigest({ generator, properties }),
    environment: runtimeInfo(),
    nonClaims: [
      "generated cases do not establish correctness for every possible input",
      "passing algebraic properties do not replace official conformance corpora",
      "the collation property is bounded to the recorded runtime environment",
      "this implementation-authored observation does not certify itself or authorize release"
    ]
  };
  if (Buffer.byteLength(JSON.stringify(result), "utf8") > PROPERTY_VERIFICATION_LIMITS.maxSerializedBytes) {
    throw new RangeError("The complete property-verification result exceeds its serialized-result limit.");
  }
  return result;
}
