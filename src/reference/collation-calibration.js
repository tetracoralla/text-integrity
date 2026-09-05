import { validateCollationRequest } from "../core/collation.js";
import { runtimeInfo } from "../core/runtime.js";
import { canonicalDigest } from "./canonical.js";

export const COLLATION_CALIBRATION_SCHEMA_VERSION = "text-integrity.collation-calibration/1";

const DEFAULT_OPTIONS = Object.freeze({
  usage: "sort",
  sensitivity: "variant",
  ignorePunctuation: false,
  numeric: false,
  caseFirst: "false",
  localeMatcher: "best fit",
  collation: "default"
});

function configuration(id, locale, options, pairs) {
  return Object.freeze({
    id,
    locale,
    options: Object.freeze({ ...DEFAULT_OPTIONS, ...options }),
    pairs: Object.freeze(pairs.map(([pairId, left, right]) => Object.freeze({
      id: pairId,
      left,
      right
    })))
  });
}

const CONFIGURATIONS = Object.freeze([
  configuration("en-variant", "en", {}, [
    ["case", "A", "a"],
    ["accent", "resume", "résumé"],
    ["canonical", "é", "e\u0301"]
  ]),
  configuration("en-search-base", "en", {
    usage: "search", sensitivity: "base", localeMatcher: "lookup"
  }, [
    ["case", "A", "a"],
    ["punctuation", "coop", "co-op"],
    ["sharp-s", "ss", "ß"]
  ]),
  configuration("en-accent", "en", { sensitivity: "accent" }, [
    ["accent", "resume", "résumé"],
    ["case", "A", "a"],
    ["canonical", "é", "e\u0301"]
  ]),
  configuration("en-ignore-punctuation", "en", {
    sensitivity: "base", ignorePunctuation: true
  }, [
    ["hyphen", "coop", "co-op"],
    ["space", "ab", "a b"],
    ["apostrophe", "cant", "can't"]
  ]),
  configuration("en-numeric", "en", { numeric: true }, [
    ["integer", "item2", "item10"],
    ["leading-zero", "2", "02"],
    ["suffix", "file9a", "file10a"]
  ]),
  configuration("en-case-upper", "en", { sensitivity: "case", caseFirst: "upper" }, [
    ["ascii", "A", "a"],
    ["word", "Alpha", "alpha"],
    ["accented", "É", "é"]
  ]),
  configuration("en-case-lower", "en", { sensitivity: "case", caseFirst: "lower" }, [
    ["ascii", "A", "a"],
    ["word", "Alpha", "alpha"],
    ["accented", "É", "é"]
  ]),
  configuration("de-default", "de", {}, [
    ["a-umlaut", "ä", "ae"],
    ["o-umlaut", "ö", "oe"],
    ["sharp-s", "ß", "ss"]
  ]),
  configuration("de-phonebook", "de", { collation: "phonebk" }, [
    ["a-umlaut", "ä", "ae"],
    ["o-umlaut", "ö", "oe"],
    ["sharp-s", "ß", "ss"]
  ]),
  configuration("sv-default", "sv", {}, [
    ["z-a-ring", "z", "å"],
    ["a-umlaut", "ä", "ae"],
    ["o-umlaut", "ö", "z"]
  ]),
  configuration("tr-case", "tr", { sensitivity: "case" }, [
    ["dotless", "I", "ı"],
    ["ascii", "I", "i"],
    ["dotted", "İ", "i"]
  ]),
  configuration("ja-default", "ja", {}, [
    ["kana", "あ", "ア"],
    ["width", "ｱ", "ア"],
    ["voicing", "は", "ば"]
  ]),
  configuration("zh-pinyin", "zh", { collation: "pinyin" }, [
    ["a-ba", "阿", "八"],
    ["country-middle", "国", "中"],
    ["polyphone", "行", "重"]
  ]),
  configuration("zh-stroke", "zh", { collation: "stroke" }, [
    ["a-ba", "阿", "八"],
    ["country-middle", "国", "中"],
    ["polyphone", "行", "重"]
  ]),
  configuration("canonical-locale-alias", "EN-us", { localeMatcher: "lookup" }, [
    ["case", "A", "a"],
    ["numeric-text", "2", "10"],
    ["punctuation", "a-b", "ab"]
  ])
]);

function comparisonObservation(collator, pair) {
  const raw = collator.compare(pair.left, pair.right);
  const order = raw < 0 ? -1 : raw > 0 ? 1 : 0;
  return {
    id: pair.id,
    left: pair.left,
    right: pair.right,
    order,
    relation: order < 0 ? "before" : order > 0 ? "after" : "equal"
  };
}

export function createCollationCalibration() {
  const configurations = CONFIGURATIONS.map((configuration) => {
    const { locale, canonicalLocale, requestedOptions, collator } = validateCollationRequest(configuration);
    return {
      id: configuration.id,
      requestedLocale: locale,
      canonicalLocale,
      requestedOptions,
      resolvedOptions: collator.resolvedOptions(),
      comparisons: configuration.pairs.map((pair) => comparisonObservation(collator, pair))
    };
  });
  const environment = runtimeInfo();
  return {
    schemaVersion: COLLATION_CALIBRATION_SCHEMA_VERSION,
    authority: "runtime_icu_observation",
    environmentBound: true,
    configurationCount: configurations.length,
    comparisonCount: configurations.reduce((total, item) => total + item.comparisons.length, 0),
    probeSetSha256: canonicalDigest(CONFIGURATIONS),
    observationSha256: canonicalDigest({ environment, configurations }),
    environment,
    configurations
  };
}
