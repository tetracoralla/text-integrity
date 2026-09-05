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
  maxChunks: 128,
  maxNamespaceItems: 512,
  maxNamespaceRelations: 5,
  maxNamespaceTextBytes: 65536,
  maxNamespaceIdChars: 128,
  maxNamespaceScopeChars: 64
});

export const RESULT_METADATA_RESERVATION_BYTES = 512;

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

function moveProjectionField(source, target, path) {
  let sourceParent = source;
  for (const key of path.slice(0, -1)) {
    if (sourceParent === null || typeof sourceParent !== "object" || !Object.hasOwn(sourceParent, key)) return;
    sourceParent[key] = { ...sourceParent[key] };
    sourceParent = sourceParent[key];
  }
  const leaf = path.at(-1);
  if (sourceParent === null || typeof sourceParent !== "object" || !Object.hasOwn(sourceParent, leaf)) return;

  let targetParent = target;
  for (const key of path.slice(0, -1)) {
    targetParent[key] ??= {};
    targetParent = targetParent[key];
  }
  targetParent[leaf] = sourceParent[leaf];
  delete sourceParent[leaf];
}

// One shared split owns the result-budget and reference-system distinction
// between measured text semantics and truthful implementation metadata. The
// input is never mutated: callers may safely retain or serialize the complete
// result after asking for either projection.
function budgetProjections(value) {
  // Copy only paths that lose metadata. Budgeting never exposes these shared
  // read-only leaves, so cloning the complete text result is unnecessary.
  const semantic = { ...value };
  const environment = {};
  moveProjectionField(semantic, environment, ["runtime"]);
  if (semantic.operation === "security") {
    moveProjectionField(semantic, environment, ["confusableComparison", "engine"]);
  }
  if (semantic.operation === "explain_difference") {
    moveProjectionField(semantic, environment, ["identifierConfusableComparison", "engine"]);
  }
  if (semantic.operation === "protocol_profile") {
    moveProjectionField(semantic, environment, ["standards", "engine"]);
    moveProjectionField(semantic, environment, ["witness", "engine"]);
  }
  if (semantic.status === "error" && semantic.error?.code === "RESULT_TOO_LARGE") {
    moveProjectionField(semantic, environment, ["error", "details", "actualBytes"]);
    moveProjectionField(semantic, environment, ["error", "details", "metadataBytes"]);
  }
  return { semantic, environment };
}

export function splitResultProjections(value) {
  return structuredClone(budgetProjections(value));
}

export function enforceResultBudget(value) {
  const { semantic, environment } = budgetProjections(value);
  const semanticBytes = Buffer.byteLength(JSON.stringify(semantic), "utf8");
  const metadataEnvelopeBytes = Buffer.byteLength(JSON.stringify(environment), "utf8");
  if (metadataEnvelopeBytes > RESULT_METADATA_RESERVATION_BYTES) {
    const actualBytes = Buffer.byteLength(JSON.stringify(value), "utf8");
    throw new TextIntegrityError(
      "INTERNAL_ERROR",
      "Non-semantic result metadata exceeds its reserved byte budget.",
      {
        actualBytes,
        semanticBytes,
        metadataBytes: actualBytes - semanticBytes,
        metadataReservationBytes: RESULT_METADATA_RESERVATION_BYTES,
        limitBytes: LIMITS.maxResultBytes
      }
    );
  }
  const budgetedBytes = semanticBytes + RESULT_METADATA_RESERVATION_BYTES;
  if (budgetedBytes > LIMITS.maxResultBytes) {
    const actualBytes = Buffer.byteLength(JSON.stringify(value), "utf8");
    throw new TextIntegrityError(
      "RESULT_TOO_LARGE",
      `The complete result cannot fit the ${LIMITS.maxResultBytes}-byte budget after reserving ${RESULT_METADATA_RESERVATION_BYTES} bytes for non-semantic metadata.`,
      {
        actualBytes,
        semanticBytes,
        budgetedBytes,
        metadataBytes: actualBytes - semanticBytes,
        metadataReservationBytes: RESULT_METADATA_RESERVATION_BYTES,
        limitBytes: LIMITS.maxResultBytes
      }
    );
  }
  return value;
}
