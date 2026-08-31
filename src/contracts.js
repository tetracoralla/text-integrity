import { LIMITS } from "./core/limits.js";
import { OUTPUT_SCHEMAS } from "./output-schemas.js";

const text = (description = "Explicit text content.") => ({
  type: "string",
  description: `${description} Limit: ${LIMITS.maxTextBytes} UTF-8 bytes.`
});
const bytes = {
  type: "array",
  maxItems: LIMITS.maxByteInput,
  items: { type: "integer", minimum: 0, maximum: 255 }
};
const detailLimit = { type: "integer", minimum: 0, maximum: LIMITS.maxDetailItems, default: LIMITS.defaultDetailItems };
const encoding = { type: "string", enum: ["utf-8", "utf-16le"] };
const direction = { type: "string", enum: ["LTR", "RTL", "FS"] };
const profile = { type: "string", enum: ["uax31_xid", "uax31_nfkc_casefold", "uts39_general_security"] };
const annotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };

const collationOptions = {
  type: "object",
  additionalProperties: false,
  required: ["usage", "sensitivity", "ignorePunctuation", "numeric", "caseFirst", "localeMatcher", "collation"],
  properties: {
    usage: { type: "string", enum: ["sort", "search"] },
    sensitivity: { type: "string", enum: ["base", "accent", "case", "variant"] },
    ignorePunctuation: { type: "boolean" },
    numeric: { type: "boolean" },
    caseFirst: { type: "string", enum: ["upper", "lower", "false"] },
    localeMatcher: { type: "string", enum: ["lookup", "best fit"] },
    collation: { type: "string", minLength: 1, maxLength: LIMITS.maxCollationChars }
  }
};

function pairInput(extraProperties = {}, extraRequired = []) {
  return {
    type: "object",
    additionalProperties: false,
    required: ["left", "right", "locale", "options", ...extraRequired],
    properties: {
      left: text("First explicit string."),
      right: text("Second explicit string."),
      locale: { type: "string", minLength: 1, maxLength: LIMITS.maxLocaleChars },
      options: collationOptions,
      ...extraProperties
    }
  };
}

const span = {
  oneOf: [
    {
      type: "object", additionalProperties: false,
      required: ["kind", "startUtf16", "endUtf16", "scope"],
      properties: {
        kind: { const: "identifier" }, startUtf16: { type: "integer", minimum: 0 },
        endUtf16: { type: "integer", minimum: 1 },
        scope: { type: "string", minLength: 1, maxLength: LIMITS.maxScopeChars }
      }
    },
    {
      type: "object", additionalProperties: false,
      required: ["kind", "startUtf16", "endUtf16"],
      properties: {
        kind: { const: "token" }, startUtf16: { type: "integer", minimum: 0 },
        endUtf16: { type: "integer", minimum: 1 }
      }
    }
  ]
};

const uts46Options = (includeDnsLength) => ({
  type: "object",
  additionalProperties: false,
  required: [
    "checkBidi", "checkHyphens", "checkJoiners", "ignoreInvalidPunycode",
    "transitionalProcessing", "useSTD3ASCIIRules", ...(includeDnsLength ? ["verifyDNSLength"] : [])
  ],
  properties: {
    checkBidi: { type: "boolean" }, checkHyphens: { type: "boolean" }, checkJoiners: { type: "boolean" },
    ignoreInvalidPunycode: { type: "boolean" }, transitionalProcessing: { type: "boolean" },
    useSTD3ASCIIRules: { type: "boolean" }, ...(includeDnsLength ? { verifyDNSLength: { type: "boolean" } } : {})
  }
});

export const TOOL_DEFINITIONS = Object.freeze([
  {
    name: "text_inspect", title: "Inspect Unicode text",
    description: "Inspect explicit text as code points, graphemes, and UTF encodings without interpreting intent.",
    operation: "inspect",
    inputSchema: { type: "object", additionalProperties: false, required: ["text"], properties: { text: text(), detailLimit } },
    outputSchema: OUTPUT_SCHEMAS.inspect,
    annotations
  },
  {
    name: "text_normalize", title: "Normalize Unicode text",
    description: "Apply one named Unicode normalization form and report equivalence without mutating the input.",
    operation: "normalize",
    inputSchema: {
      type: "object", additionalProperties: false, required: ["text", "form"],
      properties: { text: text(), form: { type: "string", enum: ["NFC", "NFD", "NFKC", "NFKD"] } }
    },
    outputSchema: OUTPUT_SCHEMAS.normalize,
    annotations
  },
  {
    name: "text_compare", title: "Compare text with explicit collation",
    description: "Compare two strings with a locale and every supported collation option supplied explicitly.",
    operation: "compare", inputSchema: pairInput(),
    outputSchema: OUTPUT_SCHEMAS.compare,
    annotations
  },
  {
    name: "text_transcode", title: "Transcode text or bytes",
    description: "Encode text or strictly decode and re-encode bytes in the closed UTF-8/UTF-16LE set; replacement is opt-in and reported. Select one byte representation to avoid duplicated payload copies.",
    operation: "transcode",
    inputSchema: { oneOf: [
      {
        type: "object", additionalProperties: false,
        required: ["sourceKind", "text", "targetEncoding", "allowLossy", "byteRepresentation"],
        properties: {
          sourceKind: { const: "text" }, text: text(), targetEncoding: encoding,
          allowLossy: { type: "boolean" },
          byteRepresentation: { type: "string", enum: ["bytes", "hex", "base64"] }
        }
      },
      {
        type: "object", additionalProperties: false,
        required: ["sourceKind", "bytes", "sourceEncoding", "targetEncoding", "allowLossy", "byteRepresentation"],
        properties: {
          sourceKind: { const: "bytes" }, bytes, sourceEncoding: encoding, targetEncoding: encoding,
          allowLossy: { type: "boolean" },
          byteRepresentation: { type: "string", enum: ["bytes", "hex", "base64"] }
        }
      }
    ] },
    outputSchema: OUTPUT_SCHEMAS.transcode,
    annotations
  },
  {
    name: "text_security_observe", title: "Observe Unicode security properties",
    description: "Run descriptive checks, a named UAX #31/UTS #39 identifier profile, or UTS #55 diagnostics over explicit host spans. Never returns a risk score or safety verdict.",
    operation: "security",
    inputSchema: { oneOf: [
      { type: "object", additionalProperties: false, required: ["text", "mode"], properties: { text: text(), mode: { const: "free_text" }, detailLimit } },
      { type: "object", additionalProperties: false, required: ["text", "mode", "profile"], properties: { text: text(), mode: { const: "identifier" }, profile, detailLimit } },
      {
        type: "object", additionalProperties: false,
        required: ["text", "mode", "profile", "comparison", "confusableDirection"],
        properties: { text: text(), mode: { const: "identifier" }, profile, comparison: text(), confusableDirection: direction, detailLimit }
      },
      {
        type: "object", additionalProperties: false, required: ["source", "mode", "spans", "confusableDirection"],
        properties: {
          source: text("Explicit source text supplied by the host."), mode: { const: "source" },
          spans: { type: "array", maxItems: LIMITS.maxSourceSpans, items: span }, confusableDirection: direction, detailLimit
        }
      }
    ] },
    outputSchema: OUTPUT_SCHEMAS.security,
    annotations
  },
  {
    name: "text_explain_difference", title: "Explain why two strings differ",
    description: "Compare exact representation, four normalization forms, NFKC_Casefold, first differing code point/grapheme, coordinates, invisibles, line endings, collation, and identifier confusability.",
    operation: "explain_difference",
    inputSchema: pairInput({ confusableDirection: direction, detailLimit }, ["confusableDirection"]),
    outputSchema: OUTPUT_SCHEMAS.explain_difference,
    annotations
  },
  {
    name: "text_index_map", title: "Map text coordinates and safe chunks",
    description: "Map UTF-8 byte, UTF-16 unit, code point, grapheme, and line/column coordinates; optionally split without cutting an extended grapheme cluster.",
    operation: "index",
    inputSchema: {
      type: "object", additionalProperties: false, required: ["text"],
      properties: { text: text(), detailLimit, maxChunkUtf8Bytes: { type: "integer", minimum: 1, maximum: LIMITS.maxChunkBytes } }
    },
    outputSchema: OUTPUT_SCHEMAS.index,
    annotations
  },
  {
    name: "text_protocol_profile", title: "Apply a named protocol-string profile",
    description: "Apply UTS #46 domain processing or one named RFC 8265 PRECIS profile, separately from ordinary normalization.",
    operation: "protocol_profile",
    inputSchema: { oneOf: [
      {
        type: "object", additionalProperties: false, required: ["profile", "action", "text", "options"],
        properties: { profile: { const: "uts46_domain" }, action: { const: "to_ascii" }, text: text(), options: uts46Options(true) }
      },
      {
        type: "object", additionalProperties: false, required: ["profile", "action", "text", "options"],
        properties: { profile: { const: "uts46_domain" }, action: { const: "to_unicode" }, text: text(), options: uts46Options(false) }
      },
      ...["precis_username_case_mapped", "precis_username_case_preserved", "precis_opaque_string"].flatMap((value) => [
        { type: "object", additionalProperties: false, required: ["profile", "action", "text"], properties: { profile: { const: value }, action: { const: "enforce" }, text: text() } },
        { type: "object", additionalProperties: false, required: ["profile", "action", "text", "comparison"], properties: { profile: { const: value }, action: { const: "compare" }, text: text(), comparison: text() } }
      ])
    ] },
    outputSchema: OUTPUT_SCHEMAS.protocol_profile,
    annotations
  }
]);

export const TOOL_BY_NAME = new Map(TOOL_DEFINITIONS.map((tool) => [tool.name, tool]));
