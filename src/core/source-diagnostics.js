import { createHash } from "node:crypto";
import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertTextBudget } from "./limits.js";
import { runtimeInfo } from "./runtime.js";
import {
  bidiSkeleton,
  compareConfusables
} from "./security.js";
import { buildTextMap, coordinateAtUtf16, lineEndingObservations } from "./text-position.js";
import { dataLookup, unicodeSecurityData } from "./unicode-security-data.js";
import {
  assertKeys,
  requireArray,
  requireEnum,
  requireInteger,
  requireObject,
  requireString
} from "./validation.js";

const SPAN_KINDS = Object.freeze(["identifier", "token"]);
const DIRECTIONS = Object.freeze(["LTR", "RTL", "FS"]);

function codePointLabel(codePoint) {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

function digest(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function validateSpans(source, map, value) {
  const spans = requireArray(value, "spans", LIMITS.maxSourceSpans);
  return spans.map((input, index) => {
    const field = `spans[${index}]`;
    requireObject(input, field);
    const kind = requireEnum(input.kind, `${field}.kind`, SPAN_KINDS);
    const allowed = kind === "identifier"
      ? ["kind", "startUtf16", "endUtf16", "scope"]
      : ["kind", "startUtf16", "endUtf16"];
    const required = kind === "identifier"
      ? ["kind", "startUtf16", "endUtf16", "scope"]
      : ["kind", "startUtf16", "endUtf16"];
    assertKeys(input, allowed, required);

    const startUtf16 = requireInteger(input.startUtf16, `${field}.startUtf16`, 0, source.length);
    const endUtf16 = requireInteger(input.endUtf16, `${field}.endUtf16`, 0, source.length);
    if (endUtf16 <= startUtf16) {
      throw new TextIntegrityError("INVALID_SPAN", `${field} must have endUtf16 greater than startUtf16.`, {
        field,
        startUtf16,
        endUtf16
      });
    }
    const start = coordinateAtUtf16(map, startUtf16, `${field}.startUtf16`);
    const end = coordinateAtUtf16(map, endUtf16, `${field}.endUtf16`);
    let scope;
    if (kind === "identifier") {
      scope = requireString(input.scope, `${field}.scope`);
      if (scope === "" || scope.length > LIMITS.maxScopeChars) {
        throw new TextIntegrityError(
          "INVALID_INPUT",
          `${field}.scope must contain 1 to ${LIMITS.maxScopeChars} characters.`,
          { field: `${field}.scope` }
        );
      }
    }
    return {
      index,
      kind,
      ...(scope === undefined ? {} : { scope }),
      text: source.slice(startUtf16, endUtf16),
      start,
      end
    };
  });
}

function coveringSpans(spans, indexUtf16) {
  return spans
    .filter((span) => span.start.utf16CodeUnit <= indexUtf16 && span.end.utf16CodeUnit > indexUtf16)
    .map((span) => span.index);
}

function hiddenCharacterDiagnostics(data, map, spans, detailLimit) {
  const items = [];
  let count = 0;
  for (const entry of map.codePoints) {
    const codePoint = entry.character.codePointAt(0);
    const signalKinds = [];
    if (dataLookup(data.bidiControl, codePoint) === true) signalKinds.push("bidi_control");
    if (dataLookup(data.defaultIgnorable, codePoint) === true) signalKinds.push("default_ignorable");
    if (dataLookup(data.formatCharacter, codePoint) === true) signalKinds.push("format_character");
    if (signalKinds.length === 0) continue;
    count += 1;
    if (items.length < detailLimit) {
      items.push({
        codePoint: codePointLabel(codePoint),
        character: entry.character,
        signalKinds,
        position: entry.start,
        coveringSpanIndexes: coveringSpans(spans, entry.start.utf16CodeUnit)
      });
    }
  }
  return { count, items, truncated: count > items.length };
}

function abnormalLineEndings(source, detailLimit) {
  const observations = lineEndingObservations(source, detailLimit);
  const abnormalKinds = new Set(["cr", "nel", "lineSeparator", "paragraphSeparator"]);
  const count = Object.entries(observations.counts)
    .filter(([kind]) => abnormalKinds.has(kind))
    .reduce((sum, [, value]) => sum + value, 0);
  const items = observations.items.filter((item) => abnormalKinds.has(item.kind));
  return {
    count,
    items,
    truncated: count > items.length,
    allCounts: observations.counts
  };
}

function confusableIdentifierDiagnostics(data, identifiers, direction, detailLimit) {
  const enriched = identifiers.map((span) => {
    const skeleton = bidiSkeleton(data, span.text, direction).value;
    return {
      ...span,
      skeleton,
      skeletonSha256: digest(skeleton)
    };
  });
  const buckets = new Map();
  for (const identifier of enriched) {
    const key = `${identifier.scope}\u0000${identifier.skeletonSha256}`;
    const bucket = buckets.get(key) ?? [];
    bucket.push(identifier);
    buckets.set(key, bucket);
  }

  let count = 0;
  const pairs = [];
  for (const bucket of buckets.values()) {
    for (let leftIndex = 0; leftIndex < bucket.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < bucket.length; rightIndex += 1) {
        const left = bucket[leftIndex];
        const right = bucket[rightIndex];
        if (left.skeleton !== right.skeleton || left.text === right.text) continue;
        count += 1;
        if (pairs.length < detailLimit) {
          const relation = compareConfusables(data, left.text, right.text, direction);
          pairs.push({
            scope: left.scope,
            leftSpanIndex: left.index,
            rightSpanIndex: right.index,
            leftText: left.text,
            rightText: right.text,
            relation: relation.relation,
            confusableClass: relation.confusableClass,
            skeletonSha256: left.skeletonSha256
          });
        }
      }
    }
  }
  return { count, pairs, truncated: count > pairs.length };
}

export function diagnoseSource(args) {
  requireObject(args);
  assertKeys(
    args,
    ["source", "mode", "spans", "confusableDirection", "detailLimit"],
    ["source", "mode", "spans", "confusableDirection"]
  );
  if (args.mode !== "source") {
    throw new TextIntegrityError("INVALID_INPUT", "mode must be source for source diagnostics.", { field: "mode" });
  }
  const source = requireString(args.source, "source");
  assertTextBudget(source, "source");
  if (!source.isWellFormed()) {
    throw new TextIntegrityError("INVALID_UNICODE", "source contains an unpaired UTF-16 surrogate.", { field: "source" });
  }
  const direction = requireEnum(args.confusableDirection, "confusableDirection", DIRECTIONS);
  const detailLimit = Object.hasOwn(args, "detailLimit")
    ? requireInteger(args.detailLimit, "detailLimit", 0, LIMITS.maxDetailItems)
    : LIMITS.defaultDetailItems;

  const map = buildTextMap(source);
  const spans = validateSpans(source, map, args.spans);
  const data = unicodeSecurityData();
  const identifiers = spans.filter((span) => span.kind === "identifier");

  return {
    status: "ok",
    operation: "source_diagnose",
    mode: "source",
    claimScope: "uts55_diagnostics_over_explicit_source_and_host_spans",
    data: {
      ...data.metadata,
      uts55Revision: 5
    },
    spans: {
      count: spans.length,
      identifiers: identifiers.length,
      items: spans
    },
    diagnostics: {
      hiddenCharacters: hiddenCharacterDiagnostics(data, map, spans, detailLimit),
      abnormalLineEndings: abnormalLineEndings(source, detailLimit),
      confusableIdentifiers: confusableIdentifierDiagnostics(data, identifiers, direction, detailLimit)
    },
    limitations: [
      "The caller, not this operation, supplies token, identifier, and scope boundaries.",
      "Diagnostics are representation facts and UTS #55 relations; they are not a maliciousness or code-correctness verdict.",
      "No file, workspace, parser, compiler, or rendering context is accessed."
    ],
    runtime: runtimeInfo()
  };
}
