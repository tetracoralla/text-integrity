export const string = { type: "string" };
export const boolean = { type: "boolean" };
export const integer = { type: "integer" };
export const nullValue = { type: "null" };
export const stringArray = { type: "array", items: string };
export const integerArray = { type: "array", items: integer };
export const byteArray = { type: "array", items: { type: "integer", minimum: 0, maximum: 255 } };

export function deepFreezeContract(value, seen = new WeakSet()) {
  if (value === null || (typeof value !== "object" && typeof value !== "function")) return value;
  if (seen.has(value)) return value;
  seen.add(value);

  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && Object.hasOwn(descriptor, "value")) {
      deepFreezeContract(descriptor.value, seen);
    }
  }
  return Object.freeze(value);
}

export function closed(required, properties, description = undefined) {
  return {
    type: "object",
    additionalProperties: false,
    required,
    properties,
    ...(description === undefined ? {} : { description })
  };
}

export function nullable(schema) {
  return { oneOf: [schema, nullValue] };
}

export function arrayOf(items) {
  return { type: "array", items };
}

export const runtime = closed(
  ["node", "icu", "unicode", "cldr"],
  {
    node: string,
    icu: nullable(string),
    unicode: nullable(string),
    cldr: nullable(string)
  },
  "Node, ICU, Unicode, and CLDR runtime versions."
);

export const unicodeData = closed(
  ["unicodeVersion", "uts39Revision", "sourceRoot", "license", "manifestSha256", "offline"],
  {
    unicodeVersion: string,
    uts39Revision: integer,
    sourceRoot: string,
    license: string,
    manifestSha256: string,
    offline: boolean,
    uts55Revision: integer
  },
  "Pinned Unicode data version, revision, manifest digest, source, license, and offline status."
);

export const limitations = {
  type: "array",
  items: string,
  description: "Explicit boundaries on what the result establishes."
};

export const coordinate = closed(
  ["utf8Byte", "utf16CodeUnit", "codePoint", "line", "columnCodePoint", "columnUtf16CodeUnit"],
  {
    utf8Byte: integer,
    utf16CodeUnit: integer,
    codePoint: integer,
    grapheme: integer,
    line: integer,
    columnCodePoint: integer,
    columnUtf16CodeUnit: integer
  }
);

export const pairCounts = closed(["left", "right"], { left: integer, right: integer });

export const lineEndingCounts = closed(
  ["crlf", "lf", "cr", "nel", "lineSeparator", "paragraphSeparator"],
  {
    crlf: integer,
    lf: integer,
    cr: integer,
    nel: integer,
    lineSeparator: integer,
    paragraphSeparator: integer
  }
);

export const lineEndingItem = closed(
  ["kind", "start", "end"],
  {
    kind: { type: "string", enum: ["crlf", "lf", "cr", "nel", "lineSeparator", "paragraphSeparator"] },
    start: coordinate,
    end: coordinate
  }
);

export const lineEndings = closed(
  ["counts", "total", "items", "truncated"],
  {
    counts: lineEndingCounts,
    total: integer,
    items: arrayOf(lineEndingItem),
    truncated: boolean
  }
);

export const collationOptions = closed(
  ["usage", "sensitivity", "ignorePunctuation", "numeric", "caseFirst", "localeMatcher", "collation"],
  {
    usage: { type: "string", enum: ["sort", "search"] },
    sensitivity: { type: "string", enum: ["base", "accent", "case", "variant"] },
    ignorePunctuation: boolean,
    numeric: boolean,
    caseFirst: { type: "string", enum: ["upper", "lower", "false"] },
    localeMatcher: { type: "string", enum: ["lookup", "best fit"] },
    collation: string
  }
);

export const resolvedCollationOptions = closed(
  ["locale", "usage", "sensitivity", "ignorePunctuation", "collation", "numeric", "caseFirst"],
  {
    locale: string,
    usage: { type: "string", enum: ["sort", "search"] },
    sensitivity: { type: "string", enum: ["base", "accent", "case", "variant"] },
    ignorePunctuation: boolean,
    collation: string,
    numeric: boolean,
    caseFirst: { type: "string", enum: ["upper", "lower", "false"] }
  }
);

export const collationResult = {
  requestedLocale: string,
  canonicalLocale: string,
  requestedOptions: collationOptions,
  resolvedOptions: resolvedCollationOptions,
  order: { type: "integer", enum: [-1, 0, 1] },
  relation: { type: "string", enum: ["before", "equal", "after"] },
  collatesEqual: boolean,
  codeUnitEqual: boolean,
  canonicalEquivalent: boolean,
  compatibilityEquivalent: boolean
};

const errorDetails = closed([], {
  field: string,
  feature: string,
  required: string,
  actual: nullable(string),
  actualBytes: integer,
  semanticBytes: integer,
  budgetedBytes: integer,
  metadataBytes: integer,
  metadataReservationBytes: integer,
  limitBytes: integer,
  actualItems: integer,
  limitItems: integer,
  actualChars: integer,
  limitChars: integer,
  fields: stringArray,
  unknownFields: stringArray,
  missingFields: stringArray,
  allowed: stringArray,
  supported: stringArray,
  requestedType: string,
  minimum: integer,
  maximum: integer,
  index: integer,
  locale: string,
  collation: string,
  encoding: string,
  firstInvalidByte: nullable(integer),
  indexUtf16: integer,
  startUtf16: integer,
  endUtf16: integer,
  graphemeIndex: integer,
  graphemeUtf8Bytes: integer,
  maxChunkUtf8Bytes: integer,
  actualChunks: integer,
  limitChunks: integer,
  codePoint: string,
  property: string,
  rule: string,
  profile: string,
  action: string,
  expectedBytes: integer,
  expectedSha256: string,
  actualSha256: string,
  section: string,
  id: string
});

export const error = closed(
  ["status", "error"],
  {
    status: { const: "error" },
    error: closed(
      ["code", "message"],
      {
        code: {
          type: "string",
          enum: [
            "CHUNK_GRAPHEME_TOO_LARGE",
            "DECODE_FAILED",
            "DUPLICATE_ITEM_ID",
            "INTERNAL_ERROR",
            "INVALID_COLLATION",
            "INVALID_INPUT",
            "INVALID_LOCALE",
            "INVALID_SPAN",
            "INVALID_UNICODE",
            "PROTOCOL_STRING_INVALID",
            "REQUEST_TOO_LARGE",
            "RESULT_TOO_LARGE",
            "TOO_MANY_CHUNKS",
            "UNICODE_DATA_INTEGRITY",
            "UNICODE_VERSION_MISMATCH",
            "UNKNOWN_OPERATION",
            "UNSUPPORTED_ENCODING",
            "UNSUPPORTED_LOCALE"
          ]
        },
        message: string,
        details: errorDetails
      }
    )
  }
);

export function withError(...successSchemas) {
  return { oneOf: [...successSchemas, error] };
}

export function success(operation, requiredProperties, optionalProperties = {}) {
  return closed(
    ["status", "operation", ...Object.keys(requiredProperties)],
    {
      status: { const: "ok" },
      operation: { const: operation },
      ...requiredProperties,
      ...optionalProperties
    }
  );
}
