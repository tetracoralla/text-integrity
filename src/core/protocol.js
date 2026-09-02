import tr46 from "tr46";
import { bidiClassFor } from "./bidi.js";
import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertCombinedTextBudget, assertTextBudget } from "./limits.js";
import { runtimeInfo } from "./runtime.js";
import { dataLookup, unicodeProtocolData } from "./unicode-security-data.js";
import { normalizeUnicode17 } from "./normalization.js";
import { lowercaseUnicode17 } from "./unicode-case.js";
import { UTS46_ENGINE_IDENTITY, UTS46_ENGINE_LABEL } from "./protocol-engine.js";
import {
  buildPrecisWitness,
  buildUts46Witness,
  createPrecisSideTrace
} from "./protocol-witness.js";
import {
  assertKeys,
  requireBoolean,
  requireEnum,
  requireObject,
  requireString
} from "./validation.js";

const PROFILES = Object.freeze([
  "uts46_domain",
  "precis_username_case_mapped",
  "precis_username_case_preserved",
  "precis_opaque_string"
]);
const UTS46_ACTIONS = Object.freeze(["to_ascii", "to_unicode"]);
const PRECIS_ACTIONS = Object.freeze(["enforce", "compare"]);
const WITNESS_MODES = Object.freeze(["none", "summary", "full_required"]);

const EXCEPTIONS = new Map([
  [0x00df, "PVALID"],
  [0x03c2, "PVALID"],
  [0x06fd, "PVALID"],
  [0x06fe, "PVALID"],
  [0x0f0b, "PVALID"],
  [0x3007, "PVALID"],
  [0x00b7, "CONTEXTO"],
  [0x0375, "CONTEXTO"],
  [0x05f3, "CONTEXTO"],
  [0x05f4, "CONTEXTO"],
  [0x30fb, "CONTEXTO"],
  ...Array.from({ length: 10 }, (_, index) => [0x0660 + index, "CONTEXTO"]),
  ...Array.from({ length: 10 }, (_, index) => [0x06f0 + index, "CONTEXTO"]),
  [0x0640, "DISALLOWED"],
  [0x07fa, "DISALLOWED"],
  [0x302e, "DISALLOWED"],
  [0x302f, "DISALLOWED"],
  [0x3031, "DISALLOWED"],
  [0x3032, "DISALLOWED"],
  [0x3033, "DISALLOWED"],
  [0x3034, "DISALLOWED"],
  [0x3035, "DISALLOWED"],
  [0x303b, "DISALLOWED"]
]);

const LETTER_DIGITS = new Set(["Ll", "Lu", "Lo", "Nd", "Lm", "Mn", "Mc"]);
const OTHER_LETTER_DIGITS = new Set(["Lt", "Nl", "No", "Me"]);
const SYMBOLS = new Set(["Sm", "Sc", "Sk", "So"]);
const PUNCTUATION = new Set(["Pc", "Pd", "Ps", "Pe", "Pi", "Pf", "Po"]);

function codePointLabel(codePoint) {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

function assertWellFormed(value, field) {
  if (!value.isWellFormed()) {
    throw new TextIntegrityError("INVALID_UNICODE", `${field} contains an unpaired UTF-16 surrogate.`, { field });
  }
}

function precisProperty(data, codePoint, baseClass) {
  if (EXCEPTIONS.has(codePoint)) return EXCEPTIONS.get(codePoint);
  if (
    dataLookup(data.unassigned, codePoint) === true
    && dataLookup(data.noncharacter, codePoint) !== true
  ) return "UNASSIGNED";
  if (codePoint >= 0x21 && codePoint <= 0x7e) return "PVALID";
  if (dataLookup(data.joinControl, codePoint) === true) return "CONTEXTJ";
  if (dataLookup(data.oldHangulJamo, codePoint) === true) return "DISALLOWED";
  if (
    dataLookup(data.defaultIgnorable, codePoint) === true
    || dataLookup(data.noncharacter, codePoint) === true
  ) return "DISALLOWED";

  const category = dataLookup(data.generalCategories, codePoint);
  if (category === "Cc") return "DISALLOWED";
  const character = String.fromCodePoint(codePoint);
  if (normalizeUnicode17(character, "NFKC", data) !== character) return baseClass === "freeform" ? "PVALID" : "DISALLOWED";
  if (LETTER_DIGITS.has(category)) return "PVALID";
  if (
    OTHER_LETTER_DIGITS.has(category)
    || category === "Zs"
    || SYMBOLS.has(category)
    || PUNCTUATION.has(category)
  ) return baseClass === "freeform" ? "PVALID" : "DISALLOWED";
  return "DISALLOWED";
}

function scriptIs(data, codePoint, script) {
  return dataLookup(data.scripts, codePoint) === script
    || (dataLookup(data.scriptExtensions, codePoint) ?? []).includes(script);
}

function contextRule(data, codePoints, index) {
  const codePoint = codePoints[index];
  const previous = codePoints[index - 1];
  const next = codePoints[index + 1];

  if (codePoint === 0x200d) {
    return previous !== undefined && (dataLookup(data.combiningClasses, previous) ?? 0) === 9;
  }
  if (codePoint === 0x200c) {
    if (previous !== undefined && (dataLookup(data.combiningClasses, previous) ?? 0) === 9) return true;
    let before = index - 1;
    while (before >= 0 && (dataLookup(data.joiningTypes, codePoints[before]) ?? "U") === "T") before -= 1;
    let after = index + 1;
    while (after < codePoints.length && (dataLookup(data.joiningTypes, codePoints[after]) ?? "U") === "T") after += 1;
    const beforeType = before >= 0 ? dataLookup(data.joiningTypes, codePoints[before]) ?? "U" : "U";
    const afterType = after < codePoints.length ? dataLookup(data.joiningTypes, codePoints[after]) ?? "U" : "U";
    return ["L", "D"].includes(beforeType) && ["R", "D"].includes(afterType);
  }
  if (codePoint === 0x00b7) return previous === 0x006c && next === 0x006c;
  if (codePoint === 0x0375) return next !== undefined && scriptIs(data, next, "Grek");
  if (codePoint === 0x05f3 || codePoint === 0x05f4) return previous !== undefined && scriptIs(data, previous, "Hebr");
  if (codePoint === 0x30fb) return codePoints.some((item) => ["Hira", "Kana", "Hani"].some((script) => scriptIs(data, item, script)));
  if (codePoint >= 0x0660 && codePoint <= 0x0669) return !codePoints.some((item) => item >= 0x06f0 && item <= 0x06f9);
  if (codePoint >= 0x06f0 && codePoint <= 0x06f9) return !codePoints.some((item) => item >= 0x0660 && item <= 0x0669);
  return false;
}

function assertPrecisClass(data, text, baseClass) {
  const codePoints = [...text].map((character) => character.codePointAt(0));
  let indexUtf16 = 0;
  for (const [index, codePoint] of codePoints.entries()) {
    const property = precisProperty(data, codePoint, baseClass);
    if (property === "CONTEXTJ" || property === "CONTEXTO") {
      if (!contextRule(data, codePoints, index)) {
        throw new TextIntegrityError("PROTOCOL_STRING_INVALID", "A context-dependent code point fails its PRECIS rule.", {
          indexUtf16,
          codePoint: codePointLabel(codePoint),
          property
        });
      }
    } else if (property !== "PVALID") {
      throw new TextIntegrityError("PROTOCOL_STRING_INVALID", "A code point is not allowed by the selected PRECIS base class.", {
        indexUtf16,
        codePoint: codePointLabel(codePoint),
        property
      });
    }
    indexUtf16 += String.fromCodePoint(codePoint).length;
  }
}

function assertBidiRule(data, text) {
  const codePoints = [...text].map((character) => character.codePointAt(0));
  const classes = codePoints.map((codePoint) => bidiClassFor(data, codePoint));
  if (!classes.some((value) => value === "R" || value === "AL" || value === "AN")) return;
  const allowed = new Set(["R", "AL", "AN", "EN", "ES", "CS", "ET", "ON", "BN", "NSM"]);
  let valid = classes[0] === "R" || classes[0] === "AL";
  valid &&= classes.every((value) => allowed.has(value));
  const lastNonNsm = classes.findLast((value) => value !== "NSM");
  valid &&= ["R", "AL", "EN", "AN"].includes(lastNonNsm);
  valid &&= !(classes.includes("EN") && classes.includes("AN"));
  if (!valid) {
    throw new TextIntegrityError("PROTOCOL_STRING_INVALID", "The string fails the RFC 5893 Bidi Rule.", {
      rule: "RFC5893"
    });
  }
}

function widthMap(data, text) {
  let mapped = "";
  for (const character of text) {
    mapped += data.widthMappings.get(character.codePointAt(0)) ?? character;
  }
  return mapped;
}

function enforcePrecisOnce(data, text, profile, trace) {
  const username = profile !== "precis_opaque_string";
  let output = text;
  if (username) {
    const mapped = widthMap(data, output);
    trace?.transform("width_mapping", output, mapped);
    output = mapped;
  }
  // RFC 8265 username preparation applies width mapping before validating
  // IdentifierClass. OpaqueString preparation validates FreeformClass before
  // its additional non-ASCII-space mapping. In both cases class preparation
  // precedes case mapping and normalization. This is security-relevant: an
  // IdentifierClass-disallowed HasCompat character such as U+212A must not
  // become acceptable merely because a later lowercase operation maps it to
  // ASCII.
  assertPrecisClass(data, output, username ? "identifier" : "freeform");
  trace?.validate(username ? "identifier_class" : "freeform_class");
  if (!username) {
    const mapped = [...output].map((character) => {
      const category = dataLookup(data.generalCategories, character.codePointAt(0));
      return category === "Zs" && character !== " " ? " " : character;
    }).join("");
    trace?.transform("additional_mapping", output, mapped);
    output = mapped;
  }
  if (profile === "precis_username_case_mapped") {
    const mapped = lowercaseUnicode17(output, data);
    trace?.transform("case_mapping", output, mapped);
    output = mapped;
  }
  const normalized = normalizeUnicode17(output, "NFC", data);
  trace?.transform("nfc", output, normalized);
  output = normalized;
  if (username) {
    assertBidiRule(data, output);
    trace?.validate("bidi_rule");
  }
  if (output === "") {
    throw new TextIntegrityError("PROTOCOL_STRING_INVALID", "The selected PRECIS profile does not allow an empty result.");
  }
  trace?.validate("non_empty");
  return output;
}

function enforcePrecis(data, text, profile, trace) {
  let output = text;
  // RFC 8264 section 7 recommends the first application plus at most three
  // additional applications. A fifth evaluation checks whether the fourth
  // result is stable without accepting another transformed value.
  for (let pass = 0; pass < 4; pass += 1) {
    trace?.startPass(output);
    const next = enforcePrecisOnce(data, output, profile, trace);
    const stabilized = next === output;
    trace?.finishPass(next, stabilized);
    if (stabilized) return output;
    output = next;
  }
  trace?.startPass(output, true);
  const verification = enforcePrecisOnce(data, output, profile, trace);
  const stabilized = verification === output;
  trace?.finishPass(verification, stabilized);
  if (!stabilized) {
    throw new TextIntegrityError("PROTOCOL_STRING_INVALID", "PRECIS processing did not stabilize after four passes.");
  }
  return output;
}

function runPrecis(args, profile) {
  assertKeys(
    args,
    ["profile", "action", "text", "comparison", "witnessMode"],
    args.action === "compare" ? ["profile", "action", "text", "comparison"] : ["profile", "action", "text"]
  );
  const action = requireEnum(args.action, "action", PRECIS_ACTIONS);
  const witnessMode = Object.hasOwn(args, "witnessMode")
    ? requireEnum(args.witnessMode, "witnessMode", WITNESS_MODES)
    : "none";
  if (action !== "compare" && Object.hasOwn(args, "comparison")) {
    throw new TextIntegrityError("INVALID_INPUT", "comparison is allowed only for the compare action.", {
      field: "comparison"
    });
  }
  const text = requireString(args.text, "text");
  assertTextBudget(text, "text");
  assertWellFormed(text, "text");
  let comparison;
  if (action === "compare") {
    comparison = requireString(args.comparison, "comparison");
    assertTextBudget(comparison, "comparison");
    assertWellFormed(comparison, "comparison");
    assertCombinedTextBudget([["text", text], ["comparison", comparison]]);
  }

  const data = unicodeProtocolData();
  const textTrace = witnessMode === "none" ? undefined : createPrecisSideTrace(witnessMode, "text");
  const comparisonTrace = witnessMode === "none" || comparison === undefined
    ? undefined
    : createPrecisSideTrace(witnessMode, "comparison");
  const output = enforcePrecis(data, text, profile, textTrace);
  const comparisonOutput = comparison === undefined
    ? undefined
    : enforcePrecis(data, comparison, profile, comparisonTrace);
  const witness = witnessMode === "none"
    ? undefined
    : buildPrecisWitness(witnessMode, profile, [textTrace, ...(comparisonTrace === undefined ? [] : [comparisonTrace])]);
  return {
    status: "ok",
    operation: "protocol_profile",
    profile,
    action,
    output,
    changed: output !== text,
    ...(comparisonOutput === undefined ? {} : {
      comparisonOutput,
      comparisonChanged: comparisonOutput !== comparison,
      equal: output === comparisonOutput
    }),
    standards: {
      framework: "RFC 8264",
      profile: "RFC 8265",
      unicodeVersion: data.metadata.unicodeVersion
    },
    ...(witness === undefined ? {} : { witness }),
    runtime: runtimeInfo()
  };
}

function runUts46(args) {
  assertKeys(args, ["profile", "action", "text", "options", "witnessMode"], ["profile", "action", "text", "options"]);
  const action = requireEnum(args.action, "action", UTS46_ACTIONS);
  const witnessMode = Object.hasOwn(args, "witnessMode")
    ? requireEnum(args.witnessMode, "witnessMode", WITNESS_MODES)
    : "none";
  const text = requireString(args.text, "text");
  assertTextBudget(text, "text");
  assertWellFormed(text, "text");
  const options = requireObject(args.options, "options");
  const allowed = [
    "checkBidi",
    "checkHyphens",
    "checkJoiners",
    "ignoreInvalidPunycode",
    "transitionalProcessing",
    "useSTD3ASCIIRules",
    ...(action === "to_ascii" ? ["verifyDNSLength"] : [])
  ];
  assertKeys(options, allowed, allowed);
  const resolvedOptions = Object.fromEntries(allowed.map((key) => [key, requireBoolean(options[key], `options.${key}`)]));
  const processed = action === "to_ascii"
    ? { domain: tr46.toASCII(text, resolvedOptions), error: false }
    : tr46.toUnicode(text, resolvedOptions);
  const output = processed.domain;
  const compatibilityEmptyLabelError = action === "to_unicode" && output !== null
    && (output === "" || output.split(".").slice(0, -1).some((label) => label === ""));
  if (output === null || processed.error || compatibilityEmptyLabelError) {
    throw new TextIntegrityError("PROTOCOL_STRING_INVALID", "The domain name fails the selected UTS #46 processing rules.", {
      profile: "uts46_domain",
      action
    });
  }
  return {
    status: "ok",
    operation: "protocol_profile",
    profile: "uts46_domain",
    action,
    output,
    changed: output !== text,
    options: resolvedOptions,
    standards: {
      specification: UTS46_ENGINE_IDENTITY.specification,
      unicodeVersion: UTS46_ENGINE_IDENTITY.unicodeVersion,
      engine: UTS46_ENGINE_LABEL
    },
    ...(witnessMode === "none" ? {} : { witness: buildUts46Witness(witnessMode, action, text, output) }),
    runtime: runtimeInfo()
  };
}

export function applyProtocolProfile(args) {
  requireObject(args);
  const profile = requireEnum(args.profile, "profile", PROFILES);
  return profile === "uts46_domain" ? runUts46(args) : runPrecis(args, profile);
}

export const SUPPORTED_PROTOCOL_PROFILES = PROFILES;
