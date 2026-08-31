const string = { type: "string" };
const boolean = { type: "boolean" };
const integer = { type: "integer" };
const object = { type: "object" };
const stringArray = { type: "array", items: string };
const byteArray = { type: "array", items: { type: "integer", minimum: 0, maximum: 255 } };

const error = {
  type: "object",
  additionalProperties: false,
  required: ["status", "error"],
  properties: {
    status: { const: "error" },
    error: {
      type: "object",
      additionalProperties: false,
      required: ["code", "message"],
      properties: {
        code: string,
        message: string,
        details: { type: "object" }
      }
    }
  }
};

function withError(...successSchemas) {
  return { oneOf: [...successSchemas, error] };
}

function success(operation, requiredProperties, optionalProperties = {}) {
  return {
    type: "object",
    additionalProperties: false,
    required: ["status", "operation", ...Object.keys(requiredProperties)],
    properties: {
      status: { const: "ok" },
      operation: { const: operation },
      ...requiredProperties,
      ...optionalProperties
    }
  };
}

const runtime = {
  type: "object",
  description: "Node, ICU, Unicode, and CLDR runtime versions."
};
const unicodeData = {
  type: "object",
  description: "Pinned Unicode data version, revision, manifest digest, source, license, and offline status."
};
const limitations = {
  type: "array",
  items: string,
  description: "Explicit boundaries on what the result establishes."
};

const inspect = success("inspect", {
  inputWellFormed: boolean,
  counts: object,
  encodings: object,
  detail: object,
  runtime
});

const normalize = success("normalize", {
  form: { type: "string", enum: ["NFC", "NFD", "NFKC", "NFKD"] },
  original: string,
  normalized: string,
  changed: boolean,
  canonicalEquivalent: boolean,
  compatibilityEquivalent: boolean,
  bytes: object,
  runtime
});

const compare = success("compare", {
  requestedLocale: string,
  canonicalLocale: string,
  requestedOptions: object,
  resolvedOptions: object,
  order: { type: "integer", enum: [-1, 0, 1] },
  relation: { type: "string", enum: ["before", "equal", "after"] },
  collatesEqual: boolean,
  codeUnitEqual: boolean,
  canonicalEquivalent: boolean,
  compatibilityEquivalent: boolean,
  runtime
});

const transcode = success("transcode", {
  source: object,
  targetEncoding: { type: "string", enum: ["utf-8", "utf-16le"] },
  byteRepresentation: { type: "string", enum: ["bytes", "hex", "base64"] },
  text: string,
  byteLength: integer,
  lossy: boolean,
  warnings: stringArray,
  runtime
}, {
  bytes: byteArray,
  hex: string,
  base64: string
});

const security = success(
  "security",
  {
    mode: { type: "string", enum: ["free_text", "identifier"] },
    claimScope: { const: "unicode_security_observations" },
    data: unicodeData,
    limits: object,
    observations: object,
    limitations,
    runtime
  },
  { identifierProfile: object, confusableComparison: object }
);

const sourceDiagnose = success("source_diagnose", {
  mode: { const: "source" },
  claimScope: { const: "uts55_diagnostics_over_explicit_source_and_host_spans" },
  data: unicodeData,
  spans: object,
  diagnostics: object,
  limitations,
  runtime
});

const explainDifference = success("explain_difference", {
  exact: object,
  normalization: object,
  nfkcCasefold: object,
  firstDifference: object,
  invisibleCharacters: object,
  lineEndings: object,
  collation: object,
  identifierConfusableComparison: object,
  limitations,
  data: unicodeData,
  runtime
});

const index = success(
  "index",
  { counts: object, detail: object, lineEndings: object, runtime },
  { chunking: object }
);

const uts46 = success("protocol_profile", {
  profile: { const: "uts46_domain" },
  action: { type: "string", enum: ["to_ascii", "to_unicode"] },
  output: string,
  changed: boolean,
  options: object,
  standards: object,
  runtime
});

const precisProfile = {
  type: "string",
  enum: ["precis_username_case_mapped", "precis_username_case_preserved", "precis_opaque_string"]
};

const precisEnforce = success("protocol_profile", {
  profile: precisProfile,
  action: { const: "enforce" },
  output: string,
  changed: boolean,
  standards: object,
  runtime
});

const precisCompare = success("protocol_profile", {
  profile: precisProfile,
  action: { const: "compare" },
  output: string,
  changed: boolean,
  comparisonOutput: string,
  comparisonChanged: boolean,
  equal: boolean,
  standards: object,
  runtime
});

export const OUTPUT_SCHEMAS = Object.freeze({
  inspect: withError(inspect),
  normalize: withError(normalize),
  compare: withError(compare),
  transcode: withError(transcode),
  security: withError(security, sourceDiagnose),
  explain_difference: withError(explainDifference),
  index: withError(index),
  protocol_profile: withError(uts46, precisEnforce, precisCompare)
});
