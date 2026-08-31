import { createHash } from "node:crypto";
import { BIDI_ENGINE, bidiClassFor, reorderForDisplay } from "./bidi.js";
import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertCombinedTextBudget, assertTextBudget } from "./limits.js";
import { runtimeInfo } from "./runtime.js";
import { dataLookup, unicodeSecurityData } from "./unicode-security-data.js";
import { assertKeys, requireEnum, requireInteger, requireObject, requireString } from "./validation.js";

const SECURITY_MODES = Object.freeze(["free_text", "identifier"]);
const IDENTIFIER_PROFILES = Object.freeze([
  "uax31_xid",
  "uax31_nfkc_casefold",
  "uts39_general_security"
]);
const CONFUSABLE_DIRECTIONS = Object.freeze(["LTR", "RTL", "FS"]);
const COMMON_OR_INHERITED = new Set(["Zyyy", "Zinh"]);

function codePointLabel(codePoint) {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

function assertWellFormed(value, field) {
  if (!value.isWellFormed()) {
    throw new TextIntegrityError("INVALID_UNICODE", `${field} contains an unpaired UTF-16 surrogate.`, { field });
  }
}

export function scriptExtensionsFor(data, codePoint) {
  const explicit = dataLookup(data.scriptExtensions, codePoint);
  if (explicit) return [...explicit].sort();
  return [dataLookup(data.scripts, codePoint) ?? "Zzzz"];
}

export function augmentedScriptSet(scriptExtensions) {
  if (scriptExtensions.some((script) => COMMON_OR_INHERITED.has(script))) return null;
  const scripts = new Set(scriptExtensions);
  if (scripts.has("Hani")) {
    scripts.add("Hanb");
    scripts.add("Jpan");
    scripts.add("Kore");
  }
  if (scripts.has("Hira") || scripts.has("Kana")) scripts.add("Jpan");
  if (scripts.has("Hang")) scripts.add("Kore");
  if (scripts.has("Bopo")) scripts.add("Hanb");
  return scripts;
}

function intersect(left, right) {
  return new Set([...left].filter((item) => right.has(item)));
}

function sortedCounts(counts) {
  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([value, count]) => ({ value, count }));
}

export function resolvedScriptSet(data, text) {
  let resolved = null;
  for (const character of text) {
    const augmented = augmentedScriptSet(scriptExtensionsFor(data, character.codePointAt(0)));
    if (augmented !== null) resolved = resolved === null ? augmented : intersect(resolved, augmented);
  }
  if (resolved === null) return { kind: "all", scripts: [] };
  if (resolved.size === 0) return { kind: "empty", scripts: [] };
  return { kind: "set", scripts: [...resolved].sort() };
}

export function analyzeText(data, text, mode, detailLimit) {
  const signalCounts = { bidiControls: 0, defaultIgnorables: 0, formatCharacters: 0 };
  const statusCounts = { Allowed: 0, Restricted: 0 };
  const typeCounts = new Map();
  const characters = [];
  let codePointCount = 0;
  let codeUnitIndex = 0;

  for (const character of text) {
    const codePoint = character.codePointAt(0);
    const scriptExtensions = scriptExtensionsFor(data, codePoint);
    const bidiControl = dataLookup(data.bidiControl, codePoint) === true;
    const defaultIgnorable = dataLookup(data.defaultIgnorable, codePoint) === true;
    const formatCharacter = dataLookup(data.formatCharacter, codePoint) === true;
    if (bidiControl) signalCounts.bidiControls += 1;
    if (defaultIgnorable) signalCounts.defaultIgnorables += 1;
    if (formatCharacter) signalCounts.formatCharacters += 1;

    let identifierStatus;
    let identifierTypes;
    if (mode === "identifier") {
      identifierStatus = dataLookup(data.identifierAllowed, codePoint) === "Allowed" ? "Allowed" : "Restricted";
      identifierTypes = dataLookup(data.identifierTypes, codePoint) ?? ["Not_Character"];
      statusCounts[identifierStatus] += 1;
      for (const type of identifierTypes) typeCounts.set(type, (typeCounts.get(type) ?? 0) + 1);
    }

    if (characters.length < detailLimit) {
      const signalKinds = [];
      if (bidiControl) signalKinds.push("bidi_control");
      if (defaultIgnorable) signalKinds.push("default_ignorable");
      if (formatCharacter) signalKinds.push("format_character");
      characters.push({
        indexCodeUnit: codeUnitIndex,
        codePoint: codePointLabel(codePoint),
        character,
        scriptExtensions,
        bidiClass: bidiClassFor(data, codePoint),
        signalKinds,
        ...(mode === "identifier" ? { identifierStatus, identifierTypes } : {})
      });
    }

    codePointCount += 1;
    codeUnitIndex += character.length;
  }

  return {
    counts: { utf16CodeUnits: text.length, codePoints: codePointCount },
    signalCounts,
    scriptResolution: resolvedScriptSet(data, text),
    characterDetail: {
      limit: detailLimit,
      characters,
      truncated: codePointCount > characters.length
    },
    ...(mode === "identifier" ? {
      identifierProperties: {
        statusCounts,
        typeCounts: sortedCounts(typeCounts)
      }
    } : {})
  };
}

export function nfkcCasefold(data, text) {
  let result = "";
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    result += data.nfkcCasefoldMappings.has(codePoint)
      ? data.nfkcCasefoldMappings.get(codePoint)
      : character;
  }
  return result.normalize("NFC");
}

function internalSkeleton(data, text) {
  const mapped = [];
  for (const character of text.normalize("NFD")) {
    const codePoint = character.codePointAt(0);
    if (dataLookup(data.defaultIgnorable, codePoint) === true) continue;
    mapped.push(data.confusables.get(codePoint) ?? character);
  }
  return mapped.join("").normalize("NFD");
}

export function bidiSkeleton(data, text, direction) {
  const reordered = reorderForDisplay(data, text, direction);
  return {
    value: internalSkeleton(data, reordered.text),
    paragraphLevels: reordered.paragraphLevels
  };
}

function skeletonDigest(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function compareConfusables(data, text, comparison, direction) {
  const left = bidiSkeleton(data, text, direction);
  const right = bidiSkeleton(data, comparison, direction);
  const skeletonsEqual = left.value === right.value;
  const textScripts = resolvedScriptSet(data, text);
  const comparisonScripts = resolvedScriptSet(data, comparison);
  const sharedScripts = textScripts.kind === "set" && comparisonScripts.kind === "set"
    ? textScripts.scripts.filter((script) => comparisonScripts.scripts.includes(script))
    : [];

  const distinctConfusable = text !== comparison && skeletonsEqual;
  const singleScriptConfusable = distinctConfusable && sharedScripts.length > 0;
  const mixedScriptConfusable = distinctConfusable && sharedScripts.length === 0;
  const wholeScriptConfusable = mixedScriptConfusable
    && textScripts.kind === "set"
    && comparisonScripts.kind === "set";

  return {
    relation: text === comparison ? "identical" : skeletonsEqual ? "confusable" : "not_confusable",
    uts39Confusable: skeletonsEqual,
    direction,
    algorithm: `bidiSkeleton(${direction})`,
    supportedDomain: "unicode_17_full_uba",
    skeletonsEqual,
    confusableClass: !distinctConfusable
      ? null
      : singleScriptConfusable
        ? "single_script"
        : wholeScriptConfusable
          ? "whole_script"
          : "mixed_script",
    singleScriptConfusable,
    mixedScriptConfusable,
    wholeScriptConfusable,
    resolvedScripts: {
      text: textScripts,
      comparison: comparisonScripts,
      shared: sharedScripts
    },
    paragraphLevels: {
      text: left.paragraphLevels,
      comparison: right.paragraphLevels
    },
    skeletonDigests: {
      textSha256: skeletonDigest(left.value),
      comparisonSha256: skeletonDigest(right.value)
    },
    engine: BIDI_ENGINE
  };
}

function profileSyntax(data, text) {
  const failures = [];
  let indexCodeUnit = 0;
  let indexCodePoint = 0;
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    const property = indexCodePoint === 0 ? data.xidStart : data.xidContinue;
    if (dataLookup(property, codePoint) !== true) {
      failures.push({
        indexCodeUnit,
        indexCodePoint,
        codePoint: codePointLabel(codePoint),
        requiredProperty: indexCodePoint === 0 ? "XID_Start" : "XID_Continue"
      });
    }
    indexCodePoint += 1;
    indexCodeUnit += character.length;
  }
  if (text === "") failures.push({ indexCodeUnit: 0, indexCodePoint: 0, codePoint: null, requiredProperty: "XID_Start" });
  return failures;
}

function restrictionLevel(data, text) {
  for (const character of text) {
    if (dataLookup(data.identifierAllowed, character.codePointAt(0)) !== "Allowed") return "Unrestricted";
  }
  if ([...text].every((character) => character.codePointAt(0) <= 0x7f)) return "ASCII-Only";

  const soss = [];
  for (const character of text) {
    const augmented = augmentedScriptSet(scriptExtensionsFor(data, character.codePointAt(0)));
    if (augmented !== null) soss.push(augmented);
  }
  if (soss.length === 0) return "Single Script";
  let shared = new Set(soss[0]);
  for (const scripts of soss.slice(1)) shared = intersect(shared, scripts);
  if (shared.size > 0) return "Single Script";

  const withoutLatin = soss.filter((scripts) => !scripts.has("Latn"));
  if (withoutLatin.length === 0 || ["Kore", "Hanb", "Jpan"].some((script) => withoutLatin.every((scripts) => scripts.has(script)))) {
    return "Highly Restrictive";
  }
  let remainingShared = new Set(withoutLatin[0]);
  for (const scripts of withoutLatin.slice(1)) remainingShared = intersect(remainingShared, scripts);
  if ([...remainingShared].some((script) => data.recommendedScripts.has(script) && script !== "Cyrl" && script !== "Grek")) {
    return "Moderately Restrictive";
  }
  return "Minimally Restrictive";
}

function mixedNumberObservation(data, text) {
  const zeroCodePoints = new Set();
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    const value = dataLookup(data.decimalValues, codePoint);
    if (value !== undefined) zeroCodePoints.add(codePoint - value);
  }
  return {
    mixed: zeroCodePoints.size > 1,
    decimalSystems: [...zeroCodePoints].sort((left, right) => left - right).map(codePointLabel)
  };
}

function evaluateIdentifierProfile(data, text, profile) {
  const profileText = profile === "uax31_nfkc_casefold" ? nfkcCasefold(data, text) : text;
  const syntaxFailures = profileSyntax(data, profileText);
  const restricted = [];
  if (profile === "uts39_general_security") {
    let indexCodeUnit = 0;
    for (const character of profileText) {
      const codePoint = character.codePointAt(0);
      if (dataLookup(data.identifierAllowed, codePoint) !== "Allowed") {
        restricted.push({ indexCodeUnit, codePoint: codePointLabel(codePoint) });
      }
      indexCodeUnit += character.length;
    }
  }
  return {
    name: profile,
    transformedText: profileText,
    changed: profileText !== text,
    conforms: syntaxFailures.length === 0 && restricted.length === 0,
    syntaxFailures,
    restrictedCodePoints: restricted,
    restrictionLevel: restrictionLevel(data, profileText),
    mixedNumbers: mixedNumberObservation(data, profileText)
  };
}

export function observeSecurity(args) {
  requireObject(args);
  const mode = requireEnum(args.mode, "mode", SECURITY_MODES);
  const allowed = mode === "identifier"
    ? ["text", "mode", "profile", "comparison", "confusableDirection", "detailLimit"]
    : ["text", "mode", "detailLimit"];
  const required = mode === "identifier" ? ["text", "mode", "profile"] : ["text", "mode"];
  assertKeys(args, allowed, required);
  const text = requireString(args.text, "text");
  assertTextBudget(text, "text");
  assertWellFormed(text, "text");
  const detailLimit = Object.hasOwn(args, "detailLimit")
    ? requireInteger(args.detailLimit, "detailLimit", 0, LIMITS.maxDetailItems)
    : LIMITS.defaultDetailItems;

  let profile;
  let comparison;
  let direction;
  if (mode === "identifier") {
    profile = requireEnum(args.profile, "profile", IDENTIFIER_PROFILES);
    if (Object.hasOwn(args, "comparison")) {
      comparison = requireString(args.comparison, "comparison");
      assertTextBudget(comparison, "comparison");
      assertWellFormed(comparison, "comparison");
      direction = requireEnum(args.confusableDirection, "confusableDirection", CONFUSABLE_DIRECTIONS);
    } else if (Object.hasOwn(args, "confusableDirection")) {
      throw new TextIntegrityError(
        "INVALID_INPUT",
        "confusableDirection is allowed only when comparison is supplied.",
        { field: "confusableDirection" }
      );
    }
  }
  assertCombinedTextBudget(
    comparison === undefined ? [["text", text]] : [["text", text], ["comparison", comparison]],
    LIMITS.maxSecurityRequestTextBytes
  );

  const data = unicodeSecurityData();
  return {
    status: "ok",
    operation: "security",
    mode,
    claimScope: "unicode_security_observations",
    data: data.metadata,
    limits: {
      maxTextBytesPerField: LIMITS.maxTextBytes,
      maxCombinedTextBytes: LIMITS.maxSecurityRequestTextBytes,
      maxDetailItems: LIMITS.maxDetailItems,
      maxResultBytes: LIMITS.maxResultBytes
    },
    observations: analyzeText(data, text, mode, detailLimit),
    ...(mode === "identifier" ? { identifierProfile: evaluateIdentifierProfile(data, text, profile) } : {}),
    ...(comparison === undefined ? {} : { confusableComparison: compareConfusables(data, text, comparison, direction) }),
    limitations: [
      "The result reports versioned Unicode properties and relations; it does not determine whether text is benign or harmful.",
      "An empty resolved script set can occur in legitimate multilingual text and is not a verdict.",
      ...(mode === "free_text" ? [
        "Identifier profiles and confusable comparison are not applied to unrestricted prose in free_text mode."
      ] : [
        "Profile conformance is limited to the explicitly named identifier profile; it is not an application authorization decision.",
        "A not_confusable relation is limited to Unicode 17.0.0 data and does not establish visual distinction in every font or rendering context."
      ])
    ],
    runtime: runtimeInfo()
  };
}

export const SUPPORTED_SECURITY_MODES = SECURITY_MODES;
export const SUPPORTED_IDENTIFIER_PROFILES = IDENTIFIER_PROFILES;
export const SUPPORTED_CONFUSABLE_DIRECTIONS = CONFUSABLE_DIRECTIONS;
