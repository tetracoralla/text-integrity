import { buildDifferenceAlignments } from "./difference-alignment.js";

const STAGE_ORDER = Object.freeze([
  "exact_representation",
  "normalization",
  "nfkc_casefold",
  "coordinate_mapping",
  "alignment",
  "unicode_signals",
  "line_endings",
  "collation",
  "identifier_confusable"
]);

function transform(mode, evaluation) {
  const { relation, leftOutput, rightOutput } = evaluation;
  return {
    ...relation,
    leftCodePointCount: [...leftOutput].length,
    rightCodePointCount: [...rightOutput].length,
    ...(mode === "full_required" ? { leftOutput, rightOutput } : {})
  };
}

export function buildDifferenceWitness({
  mode,
  left,
  right,
  normalization,
  nfkcCasefold,
  detailLimit,
  leftMap,
  rightMap,
  collation,
  confusable
}) {
  return {
    mode,
    stageOrder: [...STAGE_ORDER],
    inputs: {
      exactEqual: left === right,
      leftSha256: normalization.NFC.inputLeftSha256,
      rightSha256: normalization.NFC.inputRightSha256
    },
    transformations: {
      normalization: Object.fromEntries(
        Object.entries(normalization).map(([form, evaluation]) => [form, transform(mode, evaluation)])
      ),
      nfkcCasefold: transform(mode, nfkcCasefold)
    },
    alignment: buildDifferenceAlignments(leftMap, rightMap, mode),
    factBoundaries: {
      exactRepresentation: {
        authority: "explicit_input",
        environmentBound: false
      },
      normalization: {
        authority: "bundled_unicode_17",
        environmentBound: false
      },
      nfkcCasefold: {
        authority: "bundled_unicode_17_uts39_revision_32",
        environmentBound: false
      },
      coordinateMapping: {
        authority: "bundled_unicode_17_uax29_revision_47",
        environmentBound: false,
        leftCodePointCount: leftMap.codePoints.length,
        rightCodePointCount: rightMap.codePoints.length,
        leftGraphemeCount: leftMap.graphemes.length,
        rightGraphemeCount: rightMap.graphemes.length
      },
      alignment: {
        authority: "project_core_lcs_over_explicit_unicode17_units",
        environmentBound: false,
        complete: mode === "full_required"
      },
      unicodeSignals: {
        authority: "bundled_unicode_17_uts39_revision_32",
        environmentBound: false,
        detailLimit
      },
      lineEndings: {
        authority: "project_core_explicit_code_units",
        environmentBound: false,
        detailLimit
      },
      collation: {
        authority: "runtime_icu",
        environmentBound: true,
        requestedLocale: collation.requestedLocale,
        resolvedLocale: collation.resolvedOptions.locale,
        order: collation.order
      },
      identifierConfusable: {
        authority: "bundled_unicode_17_uts39_revision_32_vendored_uba",
        environmentBound: false,
        direction: confusable.direction,
        relation: confusable.relation,
        internalSkeletonDisclosed: false
      }
    }
  };
}

export const DIFFERENCE_WITNESS_STAGES = STAGE_ORDER;
