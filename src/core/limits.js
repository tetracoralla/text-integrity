import { TextIntegrityError } from "./errors.js";

export const LIMITS = Object.freeze({
  maxTextBytes: 4096,
  maxCombinedTextBytes: 8192,
  maxSecurityRequestTextBytes: 4096,
  maxByteInput: 4096,
  maxDetailItems: 128,
  defaultDetailItems: 64,
  maxLocaleChars: 128,
  maxCollationChars: 32,
  maxResultBytes: 65536,
  maxMcpResultBytes: 131072,
  maxToolCatalogBytes: 24576,
  // JSON escaping can expand otherwise valid core text (for example two
  // 4 KiB control-character strings) well beyond its UTF-8 payload size.
  // Carrier framing must therefore leave enough room for every valid tagged
  // core request, including source-span metadata.
  maxMcpMessageBytes: 131072,
  maxJsonRpcIdBytes: 256,
  maxMcpQueuedRequests: 64,
  mcpRequestDeadlineMs: 30000,
  mcpRequestsPerSlice: 256,
  maxCliInputBytes: 131072,
  maxSourceSpans: 128,
  maxScopeChars: 64,
  maxChunkBytes: 4096,
  maxChunks: 128
});

export function utf8Size(value) {
  return Buffer.byteLength(value, "utf8");
}

export function assertTextBudget(value, field) {
  const bytes = utf8Size(value);
  if (bytes > LIMITS.maxTextBytes) {
    throw new TextIntegrityError(
      "REQUEST_TOO_LARGE",
      `${field} exceeds the ${LIMITS.maxTextBytes}-byte UTF-8 limit.`,
      { field, actualBytes: bytes, limitBytes: LIMITS.maxTextBytes }
    );
  }
}

export function assertByteBudget(value) {
  if (value.length > LIMITS.maxByteInput) {
    throw new TextIntegrityError(
      "REQUEST_TOO_LARGE",
      `bytes exceeds the ${LIMITS.maxByteInput}-item limit.`,
      { field: "bytes", actualItems: value.length, limitItems: LIMITS.maxByteInput }
    );
  }
}

export function assertCombinedTextBudget(entries, limit = LIMITS.maxCombinedTextBytes) {
  const actualBytes = entries.reduce((total, [, value]) => total + utf8Size(value), 0);
  if (actualBytes > limit) {
    throw new TextIntegrityError(
      "REQUEST_TOO_LARGE",
      `Combined text fields exceed the ${limit}-byte UTF-8 limit.`,
      {
        fields: entries.map(([field]) => field),
        actualBytes,
        limitBytes: limit
      }
    );
  }
}

export function enforceResultBudget(value) {
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (bytes > LIMITS.maxResultBytes) {
    throw new TextIntegrityError(
      "RESULT_TOO_LARGE",
      `The complete result exceeds the ${LIMITS.maxResultBytes}-byte limit.`,
      { actualBytes: bytes, limitBytes: LIMITS.maxResultBytes }
    );
  }
  return value;
}
