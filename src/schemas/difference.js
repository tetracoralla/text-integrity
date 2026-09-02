import {
  arrayOf,
  boolean,
  closed,
  collationResult,
  coordinate,
  integer,
  limitations,
  lineEndings,
  nullable,
  pairCounts,
  runtime,
  string,
  success,
  unicodeData
} from "./common.js";
import { confusableComparison, signalCounts } from "./security.js";

const normalizationRelation = closed(
  ["equal", "leftChanged", "rightChanged", "leftSha256", "rightSha256"],
  { equal: boolean, leftChanged: boolean, rightChanged: boolean, leftSha256: string, rightSha256: string }
);

const differenceSideCodePoint = closed(
  ["character", "value", "position"],
  { character: nullable(string), value: nullable(string), position: coordinate }
);

const differenceSideGrapheme = closed(
  ["text", "position"],
  { text: nullable(string), position: coordinate }
);

const signalKinds = {
  type: "array",
  items: { type: "string", enum: ["bidi_control", "default_ignorable", "format_character"] }
};

const invisibleSummary = closed(
  ["counts", "items", "truncated"],
  {
    counts: signalCounts,
    items: arrayOf(closed(
      ["indexCodeUnit", "codePoint", "character", "signalKinds"],
      { indexCodeUnit: integer, codePoint: string, character: string, signalKinds }
    )),
    truncated: boolean
  }
);

const transformationBase = {
  equal: boolean,
  leftChanged: boolean,
  rightChanged: boolean,
  leftSha256: string,
  rightSha256: string,
  leftCodePointCount: integer,
  rightCodePointCount: integer
};

const transformation = (full) => closed(
  [...Object.keys(transformationBase), ...(full ? ["leftOutput", "rightOutput"] : [])],
  { ...transformationBase, ...(full ? { leftOutput: string, rightOutput: string } : {}) }
);

const alignmentSide = closed(
  ["startIndex", "endIndex", "start", "end"],
  { startIndex: integer, endIndex: integer, start: coordinate, end: coordinate }
);

const alignmentSegment = closed(
  ["kind", "left", "right"],
  {
    kind: { type: "string", enum: ["equal", "insert", "delete", "replace"] },
    left: alignmentSide,
    right: alignmentSide
  }
);

const alignmentResult = (unit, full) => closed(
  [
    "unit", "leftItemCount", "rightItemCount", "matchedItemCount",
    "insertedItemCount", "deletedItemCount", "segmentCount",
    "changeSegmentCount", "segmentIndexSha256",
    ...(full ? ["segments"] : [])
  ],
  {
    unit: { const: unit },
    leftItemCount: integer,
    rightItemCount: integer,
    matchedItemCount: integer,
    insertedItemCount: integer,
    deletedItemCount: integer,
    segmentCount: integer,
    changeSegmentCount: integer,
    segmentIndexSha256: string,
    ...(full ? { segments: { type: "array", maxItems: 8192, items: alignmentSegment } } : {})
  }
);

const differenceAlignment = (full) => closed(
  ["algorithm", "tieBreak", "replacementGrouping", "codePoint", "grapheme"],
  {
    algorithm: { const: "text-integrity.lcs-insert-delete-alignment/1" },
    tieBreak: { const: "highest_right_split_then_first_match" },
    replacementGrouping: { const: "contiguous_non_equal" },
    codePoint: alignmentResult("code_point", full),
    grapheme: alignmentResult("extended_grapheme_cluster", full)
  }
);

const normalizationTransformations = (full) => {
  const value = transformation(full);
  return closed(["NFC", "NFD", "NFKC", "NFKD"], { NFC: value, NFD: value, NFKC: value, NFKD: value });
};

const simpleBoundary = (authority, environmentBound) => closed(
  ["authority", "environmentBound"],
  { authority: { const: authority }, environmentBound: { const: environmentBound } }
);

const factBoundaries = closed(
  [
    "exactRepresentation", "normalization", "nfkcCasefold", "coordinateMapping",
    "alignment", "unicodeSignals", "lineEndings", "collation", "identifierConfusable"
  ],
  {
    exactRepresentation: simpleBoundary("explicit_input", false),
    normalization: simpleBoundary("bundled_unicode_17", false),
    nfkcCasefold: simpleBoundary("bundled_unicode_17_uts39_revision_32", false),
    coordinateMapping: closed(
      [
        "authority", "environmentBound", "leftCodePointCount", "rightCodePointCount",
        "leftGraphemeCount", "rightGraphemeCount"
      ],
      {
        authority: { const: "bundled_unicode_17_uax29_revision_47" },
        environmentBound: { const: false },
        leftCodePointCount: integer,
        rightCodePointCount: integer,
        leftGraphemeCount: integer,
        rightGraphemeCount: integer
      }
    ),
    alignment: closed(
      ["authority", "environmentBound", "complete"],
      {
        authority: { const: "project_core_lcs_over_explicit_unicode17_units" },
        environmentBound: { const: false },
        complete: boolean
      }
    ),
    unicodeSignals: closed(
      ["authority", "environmentBound", "detailLimit"],
      {
        authority: { const: "bundled_unicode_17_uts39_revision_32" },
        environmentBound: { const: false },
        detailLimit: integer
      }
    ),
    lineEndings: closed(
      ["authority", "environmentBound", "detailLimit"],
      {
        authority: { const: "project_core_explicit_code_units" },
        environmentBound: { const: false },
        detailLimit: integer
      }
    ),
    collation: closed(
      ["authority", "environmentBound", "requestedLocale", "resolvedLocale", "order"],
      {
        authority: { const: "runtime_icu" },
        environmentBound: { const: true },
        requestedLocale: string,
        resolvedLocale: string,
        order: { type: "integer", enum: [-1, 0, 1] }
      }
    ),
    identifierConfusable: closed(
      ["authority", "environmentBound", "direction", "relation", "internalSkeletonDisclosed"],
      {
        authority: { const: "bundled_unicode_17_uts39_revision_32_vendored_uba" },
        environmentBound: { const: false },
        direction: { type: "string", enum: ["LTR", "RTL", "FS"] },
        relation: { type: "string", enum: ["identical", "confusable", "not_confusable"] },
        internalSkeletonDisclosed: { const: false }
      }
    )
  }
);

const stageOrder = {
  type: "array",
  minItems: 9,
  maxItems: 9,
  uniqueItems: true,
  items: {
    type: "string",
    enum: [
      "exact_representation", "normalization", "nfkc_casefold", "coordinate_mapping",
      "alignment", "unicode_signals", "line_endings", "collation", "identifier_confusable"
    ]
  }
};

const differenceWitness = (mode, full) => closed(
  ["mode", "stageOrder", "inputs", "transformations", "alignment", "factBoundaries"],
  {
    mode: { const: mode },
    stageOrder,
    inputs: closed(
      ["exactEqual", "leftSha256", "rightSha256"],
      { exactEqual: boolean, leftSha256: string, rightSha256: string }
    ),
    transformations: closed(
      ["normalization", "nfkcCasefold"],
      { normalization: normalizationTransformations(full), nfkcCasefold: transformation(full) }
    ),
    alignment: differenceAlignment(full),
    factBoundaries
  }
);

export const explainDifference = success(
  "explain_difference",
  {
    exact: closed(
      ["equal", "utf8Bytes", "utf16CodeUnits", "codePoints", "graphemes"],
      { equal: boolean, utf8Bytes: pairCounts, utf16CodeUnits: pairCounts, codePoints: pairCounts, graphemes: pairCounts }
    ),
    normalization: closed(
      ["NFC", "NFD", "NFKC", "NFKD"],
      { NFC: normalizationRelation, NFD: normalizationRelation, NFKC: normalizationRelation, NFKD: normalizationRelation }
    ),
    nfkcCasefold: normalizationRelation,
    firstDifference: closed(
      ["codePoint", "grapheme"],
      {
        codePoint: nullable(closed(
          ["index", "left", "right"],
          { index: integer, left: differenceSideCodePoint, right: differenceSideCodePoint }
        )),
        grapheme: nullable(closed(
          ["index", "left", "right"],
          { index: integer, left: differenceSideGrapheme, right: differenceSideGrapheme }
        ))
      }
    ),
    invisibleCharacters: closed(["left", "right"], { left: invisibleSummary, right: invisibleSummary }),
    lineEndings: closed(["left", "right"], { left: lineEndings, right: lineEndings }),
    collation: closed(Object.keys(collationResult), collationResult),
    identifierConfusableComparison: confusableComparison,
    limitations,
    data: unicodeData,
    runtime
  },
  { witness: { oneOf: [differenceWitness("summary", false), differenceWitness("full_required", true)] } }
);
