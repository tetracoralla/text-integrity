import { createHash } from "node:crypto";
import { compareWithCollator } from "./collation.js";
import { LIMITS, assertCombinedTextBudget, assertTextBudget } from "./limits.js";
import { runtimeInfo } from "./runtime.js";
import {
  analyzeText,
  compareConfusables,
  nfkcCasefold
} from "./security.js";
import { buildTextMap, coordinateAtUtf16, lineEndingObservations } from "./text-position.js";
import { unicodeSecurityData } from "./unicode-security-data.js";
import {
  assertKeys,
  requireEnum,
  requireInteger,
  requireObject,
  requireString
} from "./validation.js";
import { TextIntegrityError } from "./errors.js";

const FORMS = Object.freeze(["NFC", "NFD", "NFKC", "NFKD"]);
const DIRECTIONS = Object.freeze(["LTR", "RTL", "FS"]);

function hash(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function assertWellFormed(value, field) {
  if (!value.isWellFormed()) {
    throw new TextIntegrityError("INVALID_UNICODE", `${field} contains an unpaired UTF-16 surrogate.`, { field });
  }
}

function normalizationRelation(left, right, form) {
  const normalizedLeft = left.normalize(form);
  const normalizedRight = right.normalize(form);
  return {
    equal: normalizedLeft === normalizedRight,
    leftChanged: normalizedLeft !== left,
    rightChanged: normalizedRight !== right,
    leftSha256: hash(normalizedLeft),
    rightSha256: hash(normalizedRight)
  };
}

function codePointDifference(leftMap, rightMap) {
  const length = Math.max(leftMap.codePoints.length, rightMap.codePoints.length);
  for (let index = 0; index < length; index += 1) {
    const left = leftMap.codePoints[index];
    const right = rightMap.codePoints[index];
    if (left?.character === right?.character) continue;
    return {
      index,
      left: left
        ? { character: left.character, value: left.value, position: left.start }
        : { character: null, value: null, position: coordinateAtUtf16(leftMap, [...leftMap.boundariesByUtf16.keys()].at(-1)) },
      right: right
        ? { character: right.character, value: right.value, position: right.start }
        : { character: null, value: null, position: coordinateAtUtf16(rightMap, [...rightMap.boundariesByUtf16.keys()].at(-1)) }
    };
  }
  return null;
}

function graphemeDifference(leftMap, rightMap) {
  const length = Math.max(leftMap.graphemes.length, rightMap.graphemes.length);
  for (let index = 0; index < length; index += 1) {
    const left = leftMap.graphemes[index];
    const right = rightMap.graphemes[index];
    if (left?.text === right?.text) continue;
    return {
      index,
      left: left
        ? { text: left.text, position: coordinateAtUtf16(leftMap, left.startUtf16CodeUnit) }
        : { text: null, position: coordinateAtUtf16(leftMap, [...leftMap.boundariesByUtf16.keys()].at(-1)) },
      right: right
        ? { text: right.text, position: coordinateAtUtf16(rightMap, right.startUtf16CodeUnit) }
        : { text: null, position: coordinateAtUtf16(rightMap, [...rightMap.boundariesByUtf16.keys()].at(-1)) }
    };
  }
  return null;
}

function invisibleSummary(data, text, detailLimit) {
  const observations = analyzeText(data, text, "free_text", detailLimit);
  return {
    counts: observations.signalCounts,
    items: observations.characterDetail.characters
      .filter((item) => item.signalKinds.length > 0)
      .map(({ indexCodeUnit, codePoint, character, signalKinds }) => ({
        indexCodeUnit,
        codePoint,
        character,
        signalKinds
      })),
    truncated: observations.characterDetail.truncated
  };
}

export function explainDifference(args) {
  requireObject(args);
  assertKeys(
    args,
    ["left", "right", "locale", "options", "confusableDirection", "detailLimit"],
    ["left", "right", "locale", "options", "confusableDirection"]
  );
  const left = requireString(args.left, "left");
  const right = requireString(args.right, "right");
  assertTextBudget(left, "left");
  assertTextBudget(right, "right");
  assertCombinedTextBudget([["left", left], ["right", right]]);
  assertWellFormed(left, "left");
  assertWellFormed(right, "right");
  const direction = requireEnum(args.confusableDirection, "confusableDirection", DIRECTIONS);
  const detailLimit = Object.hasOwn(args, "detailLimit")
    ? requireInteger(args.detailLimit, "detailLimit", 0, LIMITS.maxDetailItems)
    : LIMITS.defaultDetailItems;

  const data = unicodeSecurityData();
  const leftMap = buildTextMap(left);
  const rightMap = buildTextMap(right);
  const casefoldLeft = nfkcCasefold(data, left);
  const casefoldRight = nfkcCasefold(data, right);
  const collation = compareWithCollator(left, right, args);
  const { status: _status, operation: _operation, runtime: _collationRuntime, ...collationResult } = collation;

  return {
    status: "ok",
    operation: "explain_difference",
    exact: {
      equal: left === right,
      utf8Bytes: {
        left: Buffer.byteLength(left, "utf8"),
        right: Buffer.byteLength(right, "utf8")
      },
      utf16CodeUnits: { left: left.length, right: right.length },
      codePoints: { left: leftMap.codePoints.length, right: rightMap.codePoints.length },
      graphemes: { left: leftMap.graphemes.length, right: rightMap.graphemes.length }
    },
    normalization: Object.fromEntries(FORMS.map((form) => [form, normalizationRelation(left, right, form)])),
    nfkcCasefold: {
      equal: casefoldLeft === casefoldRight,
      leftChanged: casefoldLeft !== left,
      rightChanged: casefoldRight !== right,
      leftSha256: hash(casefoldLeft),
      rightSha256: hash(casefoldRight)
    },
    firstDifference: {
      codePoint: codePointDifference(leftMap, rightMap),
      grapheme: graphemeDifference(leftMap, rightMap)
    },
    invisibleCharacters: {
      left: invisibleSummary(data, left, detailLimit),
      right: invisibleSummary(data, right, detailLimit)
    },
    lineEndings: {
      left: lineEndingObservations(left, detailLimit),
      right: lineEndingObservations(right, detailLimit)
    },
    collation: collationResult,
    identifierConfusableComparison: compareConfusables(data, left, right, direction),
    limitations: [
      "Confusable comparison is an identifier mechanism and is not a font-specific visual judgment.",
      "This operation explains deterministic representation relations; it does not infer author intent."
    ],
    data: data.metadata,
    runtime: runtimeInfo()
  };
}
