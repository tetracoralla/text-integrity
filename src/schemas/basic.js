import {
  arrayOf,
  boolean,
  byteArray,
  closed,
  collationResult,
  coordinate,
  integer,
  lineEndings,
  nullable,
  runtime,
  string,
  stringArray,
  success
} from "./common.js";

const inspectCounts = closed(
  ["utf16CodeUnits", "codePoints", "graphemes", "utf8Bytes", "utf16leBytes"],
  {
    utf16CodeUnits: integer,
    codePoints: integer,
    graphemes: integer,
    utf8Bytes: nullable(integer),
    utf16leBytes: integer
  }
);

const encodingObservation = closed(
  ["wellFormed", "byteLength", "hex"],
  { wellFormed: boolean, byteLength: nullable(integer), hex: nullable(string) }
);

export const inspect = success("inspect", {
  inputWellFormed: boolean,
  counts: inspectCounts,
  encodings: closed(["utf8", "utf16le"], { utf8: encodingObservation, utf16le: encodingObservation }),
  detail: closed(
    ["limit", "codePoints", "codePointsTruncated", "graphemes", "graphemesTruncated"],
    {
      limit: integer,
      codePoints: arrayOf(closed(
        ["indexCodeUnit", "value", "character", "kind", "utf8Hex"],
        {
          indexCodeUnit: integer,
          value: string,
          character: string,
          kind: { type: "string", enum: ["scalar", "unpaired_surrogate"] },
          utf8Hex: nullable(string)
        }
      )),
      codePointsTruncated: boolean,
      graphemes: arrayOf(closed(["indexCodeUnit", "text"], { indexCodeUnit: integer, text: string })),
      graphemesTruncated: boolean
    }
  ),
  runtime
});

const normalizationWitnessSummary = {
  specification: { const: "Unicode Standard Annex #15" },
  unicodeVersion: { const: "17.0.0" },
  inputCodePointCount: integer,
  decomposedCodePointCount: integer,
  decompositionChanged: boolean,
  canonicalReorderedPositionCount: integer,
  compositionCount: integer,
  outputCodePointCount: integer
};

const normalizationWitness = {
  oneOf: [
    closed(
      ["mode", ...Object.keys(normalizationWitnessSummary)],
      { mode: { const: "summary" }, ...normalizationWitnessSummary }
    ),
    closed(
      ["mode", ...Object.keys(normalizationWitnessSummary), "stages"],
      {
        mode: { const: "full_required" },
        ...normalizationWitnessSummary,
        stages: closed(
          ["input", "decomposed", "canonicalOrdered", "compositions"],
          {
            input: stringArray,
            decomposed: stringArray,
            canonicalOrdered: stringArray,
            compositions: arrayOf(closed(
              ["starter", "current", "composite", "outputIndexCodePoint"],
              { starter: string, current: string, composite: string, outputIndexCodePoint: integer }
            ))
          }
        )
      }
    )
  ]
};

export const normalize = success("normalize", {
  form: { type: "string", enum: ["NFC", "NFD", "NFKC", "NFKD"] },
  original: string,
  normalized: string,
  changed: boolean,
  canonicalEquivalent: boolean,
  compatibilityEquivalent: boolean,
  bytes: closed(["originalUtf8", "normalizedUtf8"], { originalUtf8: integer, normalizedUtf8: integer }),
  runtime
}, {
  witness: normalizationWitness
});

export const compare = success("compare", { ...collationResult, runtime });

const textSource = closed(["kind", "inputWellFormed"], {
  kind: { const: "text" },
  inputWellFormed: boolean
});

const byteSource = closed(
  ["kind", "encoding", "byteLength", "bom", "firstInvalidByte", "decodedThenReencodedEqual"],
  {
    kind: { const: "bytes" },
    encoding: { type: "string", enum: ["utf-8", "utf-16le"] },
    byteLength: integer,
    bom: nullable({ type: "string", enum: ["utf-8", "utf-16le"] }),
    firstInvalidByte: nullable(integer),
    decodedThenReencodedEqual: boolean
  }
);

const transcodeWitnessBom = closed(
  ["kind", "handling"],
  {
    kind: nullable({ type: "string", enum: ["utf-8", "utf-16le"] }),
    handling: { type: "string", enum: ["not_applicable", "not_present", "preserved_as_character"] }
  }
);

const transcodeWitnessSummaryProperties = {
  sourceUnit: { type: "string", enum: ["byte", "utf16_code_unit"] },
  segmentCount: integer,
  replacementCount: integer,
  bom: transcodeWitnessBom
};

const transcodeWitness = {
  oneOf: [
    closed(
      ["mode", ...Object.keys(transcodeWitnessSummaryProperties)],
      { mode: { const: "summary" }, ...transcodeWitnessSummaryProperties }
    ),
    closed(
      ["mode", ...Object.keys(transcodeWitnessSummaryProperties), "segments"],
      {
        mode: { const: "full_required" },
        ...transcodeWitnessSummaryProperties,
        segments: arrayOf(closed(
          [
            "kind", "codePoint", "sourceStart", "sourceEnd", "decodedStartUtf16", "decodedEndUtf16",
            "targetStartByte", "targetEndByte"
          ],
          {
            kind: { type: "string", enum: ["scalar", "replacement"] },
            codePoint: string,
            sourceStart: integer,
            sourceEnd: integer,
            decodedStartUtf16: integer,
            decodedEndUtf16: integer,
            targetStartByte: integer,
            targetEndByte: integer
          }
        ))
      }
    )
  ]
};

export function transcodeFor(representation, payloadSchema) {
  return success(
    "transcode",
    {
      source: { oneOf: [textSource, byteSource] },
      targetEncoding: { type: "string", enum: ["utf-8", "utf-16le"] },
      byteRepresentation: { const: representation },
      text: string,
      [representation]: payloadSchema,
      byteLength: integer,
      lossy: boolean,
      warnings: stringArray,
      runtime
    },
    { witness: transcodeWitness }
  );
}

const indexCounts = closed(
  ["utf8Bytes", "utf16CodeUnits", "codePoints", "graphemes", "lines"],
  { utf8Bytes: integer, utf16CodeUnits: integer, codePoints: integer, graphemes: integer, lines: integer }
);

const indexDetail = closed(
  ["limit", "codePoints", "codePointsTruncated", "graphemes", "graphemesTruncated"],
  {
    limit: integer,
    codePoints: arrayOf(closed(
      ["character", "value", "grapheme", "start", "end"],
      { character: string, value: string, grapheme: integer, start: coordinate, end: coordinate }
    )),
    codePointsTruncated: boolean,
    graphemes: arrayOf(closed(
      ["index", "text", "start", "end"],
      { index: integer, text: string, start: coordinate, end: coordinate }
    )),
    graphemesTruncated: boolean
  }
);

export const index = success(
  "index",
  { counts: indexCounts, detail: indexDetail, lineEndings, runtime },
  {
    chunking: closed(
      ["maxChunkUtf8Bytes", "boundary", "chunks"],
      {
        maxChunkUtf8Bytes: integer,
        boundary: { const: "extended_grapheme_cluster" },
        chunks: arrayOf(closed(
          ["index", "text", "utf8Bytes", "start", "end"],
          { index: integer, text: string, utf8Bytes: integer, start: coordinate, end: coordinate }
        ))
      }
    )
  }
);

export { byteArray };
