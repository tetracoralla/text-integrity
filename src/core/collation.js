import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertTextBudget } from "./limits.js";
import { runtimeInfo } from "./runtime.js";
import {
  assertKeys,
  requireBoolean,
  requireEnum,
  requireObject,
  requireString
} from "./validation.js";

const COLLATOR_USAGES = Object.freeze(["sort", "search"]);
const COLLATOR_SENSITIVITIES = Object.freeze(["base", "accent", "case", "variant"]);
const COLLATOR_CASE_FIRST = Object.freeze(["upper", "lower", "false"]);
const LOCALE_MATCHERS = Object.freeze(["lookup", "best fit"]);

export function validateCollationRequest(args) {
  const locale = requireString(args.locale, "locale");
  if (locale.length > LIMITS.maxLocaleChars) {
    throw new TextIntegrityError(
      "REQUEST_TOO_LARGE",
      `locale exceeds the ${LIMITS.maxLocaleChars}-character limit.`,
      { field: "locale", actualChars: locale.length, limitChars: LIMITS.maxLocaleChars }
    );
  }
  const options = requireObject(args.options, "options");
  assertKeys(
    options,
    ["usage", "sensitivity", "ignorePunctuation", "numeric", "caseFirst", "localeMatcher", "collation"],
    ["usage", "sensitivity", "ignorePunctuation", "numeric", "caseFirst", "localeMatcher", "collation"]
  );
  const collation = requireString(options.collation, "options.collation");
  if (collation.length < 1 || collation.length > LIMITS.maxCollationChars) {
    throw new TextIntegrityError(
      "INVALID_INPUT",
      `options.collation must contain 1 to ${LIMITS.maxCollationChars} characters.`,
      { field: "options.collation" }
    );
  }
  const requestedOptions = {
    usage: requireEnum(options.usage, "options.usage", COLLATOR_USAGES),
    sensitivity: requireEnum(options.sensitivity, "options.sensitivity", COLLATOR_SENSITIVITIES),
    ignorePunctuation: requireBoolean(options.ignorePunctuation, "options.ignorePunctuation"),
    numeric: requireBoolean(options.numeric, "options.numeric"),
    caseFirst: requireEnum(options.caseFirst, "options.caseFirst", COLLATOR_CASE_FIRST),
    localeMatcher: requireEnum(options.localeMatcher, "options.localeMatcher", LOCALE_MATCHERS),
    collation
  };

  let canonicalLocale;
  try {
    [canonicalLocale] = Intl.getCanonicalLocales(locale);
  } catch {
    throw new TextIntegrityError("INVALID_LOCALE", "locale is not a structurally valid locale identifier.", { locale });
  }
  if (!canonicalLocale || Intl.Collator.supportedLocalesOf([canonicalLocale]).length === 0) {
    throw new TextIntegrityError(
      "UNSUPPORTED_LOCALE",
      "locale is not supported by this runtime.",
      { locale: canonicalLocale ?? locale }
    );
  }

  const runtimeOptions = {
    usage: requestedOptions.usage,
    sensitivity: requestedOptions.sensitivity,
    ignorePunctuation: requestedOptions.ignorePunctuation,
    numeric: requestedOptions.numeric,
    caseFirst: requestedOptions.caseFirst,
    localeMatcher: requestedOptions.localeMatcher,
    ...(collation === "default" ? {} : { collation })
  };
  let collator;
  try {
    collator = new Intl.Collator(canonicalLocale, runtimeOptions);
  } catch {
    throw new TextIntegrityError("INVALID_COLLATION", "options.collation is not a valid collation type.", {
      collation
    });
  }
  return { locale, canonicalLocale, requestedOptions, collator };
}

export function compareWithCollator(left, right, request) {
  const { locale, canonicalLocale, requestedOptions, collator } = validateCollationRequest(request);
  const raw = collator.compare(left, right);
  const order = raw < 0 ? -1 : raw > 0 ? 1 : 0;
  return {
    status: "ok",
    operation: "compare",
    requestedLocale: locale,
    canonicalLocale,
    requestedOptions,
    resolvedOptions: collator.resolvedOptions(),
    order,
    relation: order < 0 ? "before" : order > 0 ? "after" : "equal",
    collatesEqual: order === 0,
    codeUnitEqual: left === right,
    canonicalEquivalent: left.normalize("NFD") === right.normalize("NFD"),
    compatibilityEquivalent: left.normalize("NFKD") === right.normalize("NFKD"),
    runtime: runtimeInfo()
  };
}

export const SUPPORTED_COLLATOR_OPTIONS = Object.freeze({
  usages: COLLATOR_USAGES,
  sensitivities: COLLATOR_SENSITIVITIES,
  caseFirst: COLLATOR_CASE_FIRST,
  localeMatchers: LOCALE_MATCHERS
});
