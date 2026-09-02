import {
  arrayOf,
  boolean,
  closed,
  coordinate,
  integer,
  integerArray,
  limitations,
  lineEndingCounts,
  lineEndingItem,
  nullable,
  runtime,
  string,
  stringArray,
  success,
  unicodeData
} from "./common.js";

const signalKinds = {
  type: "array",
  items: { type: "string", enum: ["bidi_control", "default_ignorable", "format_character"] }
};

export const signalCounts = closed(
  ["bidiControls", "defaultIgnorables", "formatCharacters"],
  { bidiControls: integer, defaultIgnorables: integer, formatCharacters: integer }
);

const scriptResolution = closed(
  ["kind", "scripts"],
  { kind: { type: "string", enum: ["all", "empty", "set"] }, scripts: stringArray }
);

const characterObservationBase = {
  indexCodeUnit: integer,
  codePoint: string,
  character: string,
  scriptExtensions: stringArray,
  bidiClass: string,
  signalKinds
};

const freeTextObservation = closed(
  ["counts", "signalCounts", "scriptResolution", "characterDetail"],
  {
    counts: closed(["utf16CodeUnits", "codePoints"], { utf16CodeUnits: integer, codePoints: integer }),
    signalCounts,
    scriptResolution,
    characterDetail: closed(
      ["limit", "characters", "truncated"],
      {
        limit: integer,
        characters: arrayOf(closed(Object.keys(characterObservationBase), characterObservationBase)),
        truncated: boolean
      }
    )
  }
);

const identifierCharacter = closed(
  [...Object.keys(characterObservationBase), "identifierStatus", "identifierTypes"],
  {
    ...characterObservationBase,
    identifierStatus: { type: "string", enum: ["Allowed", "Restricted"] },
    identifierTypes: stringArray
  }
);

const identifierObservation = closed(
  ["counts", "signalCounts", "scriptResolution", "characterDetail", "identifierProperties"],
  {
    counts: closed(["utf16CodeUnits", "codePoints"], { utf16CodeUnits: integer, codePoints: integer }),
    signalCounts,
    scriptResolution,
    characterDetail: closed(
      ["limit", "characters", "truncated"],
      { limit: integer, characters: arrayOf(identifierCharacter), truncated: boolean }
    ),
    identifierProperties: closed(
      ["statusCounts", "typeCounts"],
      {
        statusCounts: closed(["Allowed", "Restricted"], { Allowed: integer, Restricted: integer }),
        typeCounts: arrayOf(closed(["value", "count"], { value: string, count: integer }))
      }
    )
  }
);

const securityLimits = closed(
  ["maxTextBytesPerField", "maxCombinedTextBytes", "maxDetailItems", "maxResultBytes"],
  {
    maxTextBytesPerField: integer,
    maxCombinedTextBytes: integer,
    maxDetailItems: integer,
    maxResultBytes: integer
  }
);

const profileSyntaxFailure = closed(
  ["indexCodeUnit", "indexCodePoint", "codePoint", "requiredProperty"],
  {
    indexCodeUnit: integer,
    indexCodePoint: integer,
    codePoint: nullable(string),
    requiredProperty: { type: "string", enum: ["XID_Start", "XID_Continue"] }
  }
);

const identifierProfile = closed(
  ["name", "transformedText", "changed", "conforms", "syntaxFailures", "restrictedCodePoints", "restrictionLevel", "mixedNumbers"],
  {
    name: { type: "string", enum: ["uax31_xid", "uax31_nfkc_casefold", "uts39_general_security"] },
    transformedText: string,
    changed: boolean,
    conforms: boolean,
    syntaxFailures: arrayOf(profileSyntaxFailure),
    restrictedCodePoints: arrayOf(closed(["indexCodeUnit", "codePoint"], { indexCodeUnit: integer, codePoint: string })),
    restrictionLevel: {
      type: "string",
      enum: ["ASCII-Only", "Single Script", "Highly Restrictive", "Moderately Restrictive", "Minimally Restrictive", "Unrestricted"]
    },
    mixedNumbers: closed(["mixed", "decimalSystems"], { mixed: boolean, decimalSystems: stringArray })
  }
);

const bidiEngine = closed(
  ["name", "upstreamVersion", "unicodeVersion", "conformance"],
  { name: string, upstreamVersion: string, unicodeVersion: string, conformance: stringArray }
);

export const confusableComparison = closed(
  [
    "relation", "uts39Confusable", "direction", "algorithm", "supportedDomain", "skeletonsEqual",
    "confusableClass", "singleScriptConfusable", "mixedScriptConfusable", "wholeScriptConfusable",
    "resolvedScripts", "paragraphLevels", "skeletonDigests", "engine"
  ],
  {
    relation: { type: "string", enum: ["identical", "confusable", "not_confusable"] },
    uts39Confusable: boolean,
    direction: { type: "string", enum: ["LTR", "RTL", "FS"] },
    algorithm: string,
    supportedDomain: { const: "unicode_17_full_uba" },
    skeletonsEqual: boolean,
    confusableClass: nullable({ type: "string", enum: ["single_script", "whole_script", "mixed_script"] }),
    singleScriptConfusable: boolean,
    mixedScriptConfusable: boolean,
    wholeScriptConfusable: boolean,
    resolvedScripts: closed(
      ["text", "comparison", "shared"],
      { text: scriptResolution, comparison: scriptResolution, shared: stringArray }
    ),
    paragraphLevels: closed(["text", "comparison"], { text: integerArray, comparison: integerArray }),
    skeletonDigests: closed(
      ["textSha256", "comparisonSha256"],
      { textSha256: string, comparisonSha256: string }
    ),
    engine: bidiEngine
  }
);

const securityBase = {
  claimScope: { const: "unicode_security_observations" },
  data: unicodeData,
  limits: securityLimits,
  limitations,
  runtime
};

export const freeTextSecurity = success("security", {
  mode: { const: "free_text" },
  ...securityBase,
  observations: freeTextObservation
});

export const identifierSecurity = success(
  "security",
  {
    mode: { const: "identifier" },
    ...securityBase,
    observations: identifierObservation,
    identifierProfile
  },
  { confusableComparison }
);

const sourceSpan = {
  oneOf: [
    closed(
      ["index", "kind", "scope", "text", "start", "end"],
      {
        index: integer,
        kind: { const: "identifier" },
        scope: string,
        text: string,
        start: coordinate,
        end: coordinate
      }
    ),
    closed(
      ["index", "kind", "text", "start", "end"],
      { index: integer, kind: { const: "token" }, text: string, start: coordinate, end: coordinate }
    )
  ]
};

const hiddenCharacterDiagnostics = closed(
  ["count", "items", "truncated"],
  {
    count: integer,
    items: arrayOf(closed(
      ["codePoint", "character", "signalKinds", "position", "coveringSpanIndexes"],
      {
        codePoint: string,
        character: string,
        signalKinds,
        position: coordinate,
        coveringSpanIndexes: integerArray
      }
    )),
    truncated: boolean
  }
);

const abnormalLineEndingDiagnostics = closed(
  ["count", "items", "truncated", "allCounts"],
  { count: integer, items: arrayOf(lineEndingItem), truncated: boolean, allCounts: lineEndingCounts }
);

const confusableIdentifierDiagnostics = closed(
  ["count", "pairs", "truncated"],
  {
    count: integer,
    pairs: arrayOf(closed(
      ["scope", "leftSpanIndex", "rightSpanIndex", "leftText", "rightText", "relation", "confusableClass", "skeletonSha256"],
      {
        scope: string,
        leftSpanIndex: integer,
        rightSpanIndex: integer,
        leftText: string,
        rightText: string,
        relation: { const: "confusable" },
        confusableClass: { type: "string", enum: ["single_script", "whole_script", "mixed_script"] },
        skeletonSha256: string
      }
    )),
    truncated: boolean
  }
);

export const sourceDiagnose = success("source_diagnose", {
  mode: { const: "source" },
  claimScope: { const: "uts55_diagnostics_over_explicit_source_and_host_spans" },
  data: unicodeData,
  spans: closed(["count", "identifiers", "items"], { count: integer, identifiers: integer, items: arrayOf(sourceSpan) }),
  diagnostics: closed(
    ["hiddenCharacters", "abnormalLineEndings", "confusableIdentifiers"],
    {
      hiddenCharacters: hiddenCharacterDiagnostics,
      abnormalLineEndings: abnormalLineEndingDiagnostics,
      confusableIdentifiers: confusableIdentifierDiagnostics
    }
  ),
  limitations,
  runtime
});
