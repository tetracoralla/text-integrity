import { types as utilTypes } from "node:util";
import { LIMITS, splitResultProjections } from "../core/limits.js";
import { analyzeNamespaceIntegrity } from "../core/namespace-integrity.js";
import { executeOperation, SUPPORTED_OPERATIONS } from "../core/operations.js";
import { unicodeDataIdentity } from "../core/unicode-security-data.js";
import { TextIntegrityError, errorPayload } from "../core/errors.js";
import { OUTPUT_SCHEMAS } from "../output-schemas.js";
import { PRODUCT_NAME, VERSION } from "../version.js";
import { canonicalDigest, canonicalJson } from "./canonical.js";
import {
  BoundedJsonDepthError,
  DuplicateJsonKeyError,
  assertUniqueJsonObjectKeys,
  validateJsonGraph,
  valueMatchesSchema
} from "./json-validation.js";
import {
  ENVIRONMENT_PROJECTION_SCHEMA_VERSION,
  MEASUREMENT_RECORD_SCHEMA_VERSION,
  MEASUREMENT_REPLAY_SCHEMA_VERSION,
  PUBLIC_RESULT_SCHEMA_VERSION,
  SEMANTIC_PROJECTION_SCHEMA_VERSION,
  TAGGED_REQUEST_SCHEMA_VERSION
} from "./versions.js";

export const MEASUREMENT_RECORD_LIMITS = Object.freeze({
  maxInputBytes: 262144,
  maxSerializedBytes: 131072,
  maxJsonDepth: 64,
  maxJsonNodes: 65536,
  maxObjectKeys: 256,
  maxArrayItems: 32768,
  maxStringCodeUnits: 65536,
  maxIdentifierCodeUnits: 512
});
export const MEASUREMENT_REPLAY_LIMITS = Object.freeze({ maxSerializedBytes: 8192 });

const MEASUREMENT_RECORD_NON_CLAIMS = Object.freeze([
  "This generated record is not an authority for correctness, conformance, release readiness, or business acceptance.",
  "Request and result digests are identities, not anonymization; low-entropy text can be enumerated.",
  "Environment-bound measurements do not claim exact equality across runtimes."
]);

const MEASUREMENT_REPLAY_NON_CLAIMS = Object.freeze([
  "This replay is a current-runtime drift observation, not an authority for correctness, cause, conformance, release readiness, or business acceptance.",
  "Digest identities are not anonymization; low-entropy text can be enumerated.",
  "Environment and complete-result matches describe recorded metadata identity, not runtime equivalence."
]);

const measurementRecordDecoder = new TextDecoder("utf-8", { fatal: true });
const typedArrayByteLength = Object.getOwnPropertyDescriptor(
  Object.getPrototypeOf(Uint8Array.prototype),
  "byteLength"
).get;

export const REPRODUCIBILITY_TARGETS = Object.freeze({
  inspect: "cross_runtime_exact",
  normalize: "cross_runtime_exact",
  compare: "environment_bound",
  transcode: "cross_runtime_exact",
  security: "cross_runtime_exact",
  explain_difference: "environment_bound",
  index: "cross_runtime_exact",
  protocol_profile: "cross_runtime_exact",
  namespace_integrity: "relation_bound"
});

export const SUPPORTED_REFERENCE_OPERATIONS = Object.freeze([
  ...SUPPORTED_OPERATIONS,
  "namespace_integrity"
]);

function requireClosedKeys(value, allowed, required, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object.`);
  }
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new TypeError(`${field} has unknown fields: ${unknown.sort().join(", ")}.`);
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  if (missing.length > 0) throw new TypeError(`${field} is missing fields: ${missing.join(", ")}.`);
}

function requireBoundedString(value, field, maximum = MEASUREMENT_RECORD_LIMITS.maxIdentifierCodeUnits) {
  if (typeof value !== "string" || value.length > maximum || !value.isWellFormed()) {
    throw new TypeError(`${field} must be a bounded well-formed string.`);
  }
}

function requireDigest(value, field) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError(`${field} must be a lowercase SHA-256 digest.`);
  }
}

function requireCanonicalMatch(actual, expected, field) {
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new TypeError(`${field} does not match its derived value.`);
  }
}

function validateDataIdentity(value) {
  requireClosedKeys(value, [
    "unicodeVersion", "uts39Revision", "sourceManifestSha256", "compactFormatVersion",
    "compactManifestSha256", "compactDataSha256"
  ], [
    "unicodeVersion", "uts39Revision", "sourceManifestSha256", "compactFormatVersion",
    "compactManifestSha256", "compactDataSha256"
  ], "record.data");
  requireBoundedString(value.unicodeVersion, "record.data.unicodeVersion");
  if (!Number.isSafeInteger(value.uts39Revision) || value.uts39Revision < 0
    || !Number.isSafeInteger(value.compactFormatVersion) || value.compactFormatVersion < 0) {
    throw new TypeError("record.data revisions must be non-negative safe integers.");
  }
  for (const field of ["sourceManifestSha256", "compactManifestSha256", "compactDataSha256"]) {
    requireDigest(value[field], `record.data.${field}`);
  }
}

function validateFixedNonClaims(value, expected, field) {
  if (!Array.isArray(value) || value.length !== expected.length
    || value.some((item, index) => item !== expected[index])) {
    throw new TypeError(`${field} must retain the complete fixed non-claim set.`);
  }
}

function materializeTextTag(value, field) {
  requireClosedKeys(value, ["kind", "value", "units"], ["kind"], field);
  if (value.kind === "unicode_scalar_string") {
    requireClosedKeys(value, ["kind", "value"], ["kind", "value"], field);
    if (typeof value.value !== "string" || !value.value.isWellFormed()) {
      throw new TypeError(`${field}.value must be a well-formed Unicode scalar string.`);
    }
    return value.value;
  }
  if (value.kind === "utf16_code_units") {
    requireClosedKeys(value, ["kind", "units"], ["kind", "units"], field);
    if (!Array.isArray(value.units) || value.units.length > LIMITS.maxTextBytes * 2
      || value.units.some((unit) => !Number.isInteger(unit) || unit < 0 || unit > 0xffff)) {
      throw new TypeError(`${field}.units must be a bounded array of UTF-16 code units.`);
    }
    return String.fromCharCode(...value.units);
  }
  throw new TypeError(`${field}.kind is not supported.`);
}

export function materializeTaggedArguments(value, field = "arguments") {
  if (Array.isArray(value)) {
    return value.map((item, index) => materializeTaggedArguments(item, `${field}[${index}]`));
  }
  if (value !== null && typeof value === "object") {
    if (Object.hasOwn(value, "$text")) {
      requireClosedKeys(value, ["$text"], ["$text"], field);
      return materializeTextTag(value.$text, `${field}.$text`);
    }
    return Object.fromEntries(Object.entries(value)
      .map(([key, item]) => [key, materializeTaggedArguments(item, `${field}.${key}`)]));
  }
  return value;
}

export function caseReproducibilityTarget(operation, args) {
  if (operation === "namespace_integrity") {
    const relations = args !== null && typeof args === "object" && !Array.isArray(args)
      && Array.isArray(args.relations)
      ? args.relations
      : [];
    return relations.some((relation) => relation?.kind === "declared_collation")
      ? "environment_bound"
      : "cross_runtime_exact";
  }
  return REPRODUCIBILITY_TARGETS[operation];
}

export function semanticProjection(result) {
  return splitResultProjections(result).semantic;
}

export function environmentProjection(result) {
  return splitResultProjections(result).environment;
}

export function measureReferenceRequest(request) {
  requireClosedKeys(request, ["operation", "arguments"], ["operation", "arguments"], "request");
  if (!SUPPORTED_REFERENCE_OPERATIONS.includes(request.operation)) {
    throw new TypeError("request.operation is not supported.");
  }
  if (request.arguments === null || typeof request.arguments !== "object"
    || Array.isArray(request.arguments)) {
    throw new TypeError("request.arguments must be an object.");
  }
  const materializedArguments = materializeTaggedArguments(request.arguments);
  let result;
  try {
    result = request.operation === "namespace_integrity"
      ? analyzeNamespaceIntegrity(materializedArguments)
      : executeOperation(request.operation, materializedArguments);
  } catch (error) {
    if (!(error instanceof TextIntegrityError)) throw error;
    result = errorPayload(error);
  }
  const projections = splitResultProjections(result);
  return {
    operation: request.operation,
    reproducibilityTarget: caseReproducibilityTarget(request.operation, materializedArguments),
    requestSha256: canonicalDigest(request),
    semanticSha256: canonicalDigest(projections.semantic),
    environmentSha256: canonicalDigest(projections.environment),
    completeResultSha256: canonicalDigest(result),
    environment: projections.environment,
    result
  };
}

export function createMeasurementRecord(request) {
  const measured = measureReferenceRequest(request);
  const record = {
    schemaVersion: MEASUREMENT_RECORD_SCHEMA_VERSION,
    authority: "operation_measurement_observation",
    scope: "one_explicit_tagged_request",
    selfCertifying: false,
    complete: true,
    product: { name: PRODUCT_NAME, version: VERSION },
    contracts: {
      taggedRequest: TAGGED_REQUEST_SCHEMA_VERSION,
      publicResult: PUBLIC_RESULT_SCHEMA_VERSION,
      semanticProjection: SEMANTIC_PROJECTION_SCHEMA_VERSION,
      environmentProjection: ENVIRONMENT_PROJECTION_SCHEMA_VERSION
    },
    operationProfile: {
      id: `text-integrity.operation.${request.operation}/1`,
      revision: 1,
      reproducibilityTarget: measured.reproducibilityTarget
    },
    request,
    requestSha256: measured.requestSha256,
    semanticSha256: measured.semanticSha256,
    environmentSha256: measured.environmentSha256,
    completeResultSha256: measured.completeResultSha256,
    data: unicodeDataIdentity(),
    environment: measured.environment,
    result: measured.result,
    nonClaims: [...MEASUREMENT_RECORD_NON_CLAIMS]
  };
  const actualBytes = Buffer.byteLength(JSON.stringify(record), "utf8");
  if (actualBytes > MEASUREMENT_RECORD_LIMITS.maxSerializedBytes) {
    throw new TextIntegrityError(
      "RESULT_TOO_LARGE",
      `The complete measurement record exceeds ${MEASUREMENT_RECORD_LIMITS.maxSerializedBytes} bytes.`,
      { actualBytes, limitBytes: MEASUREMENT_RECORD_LIMITS.maxSerializedBytes }
    );
  }
  return record;
}

export function validateMeasurementRecord(record) {
  validateJsonGraph(record, {
    limits: MEASUREMENT_RECORD_LIMITS,
    isProxy: utilTypes.isProxy
  });
  const actualBytes = Buffer.byteLength(JSON.stringify(record), "utf8");
  if (actualBytes > MEASUREMENT_RECORD_LIMITS.maxSerializedBytes) {
    throw new RangeError(
      `record exceeds ${MEASUREMENT_RECORD_LIMITS.maxSerializedBytes} serialized bytes.`
    );
  }
  const topLevelFields = [
    "schemaVersion", "authority", "scope", "selfCertifying", "complete", "product",
    "contracts", "operationProfile", "request", "requestSha256", "semanticSha256",
    "environmentSha256", "completeResultSha256", "data", "environment", "result", "nonClaims"
  ];
  requireClosedKeys(record, topLevelFields, topLevelFields, "record");
  if (record.schemaVersion !== MEASUREMENT_RECORD_SCHEMA_VERSION
    || record.authority !== "operation_measurement_observation"
    || record.scope !== "one_explicit_tagged_request"
    || record.selfCertifying !== false
    || record.complete !== true) {
    throw new TypeError("record uses unsupported measurement contract constants.");
  }

  requireClosedKeys(record.product, ["name", "version"], ["name", "version"], "record.product");
  if (record.product.name !== PRODUCT_NAME) {
    throw new TypeError(`record.product.name must be ${PRODUCT_NAME}.`);
  }
  requireBoundedString(record.product.version, "record.product.version");

  const contractFields = [
    "taggedRequest", "publicResult", "semanticProjection", "environmentProjection"
  ];
  requireClosedKeys(record.contracts, contractFields, contractFields, "record.contracts");
  requireCanonicalMatch(record.contracts, {
    taggedRequest: TAGGED_REQUEST_SCHEMA_VERSION,
    publicResult: PUBLIC_RESULT_SCHEMA_VERSION,
    semanticProjection: SEMANTIC_PROJECTION_SCHEMA_VERSION,
    environmentProjection: ENVIRONMENT_PROJECTION_SCHEMA_VERSION
  }, "record.contracts");

  requireClosedKeys(
    record.request,
    ["operation", "arguments"],
    ["operation", "arguments"],
    "record.request"
  );
  if (!SUPPORTED_REFERENCE_OPERATIONS.includes(record.request.operation)) {
    throw new TypeError("record.request.operation is not supported.");
  }
  if (record.request.arguments === null || typeof record.request.arguments !== "object"
    || Array.isArray(record.request.arguments)) {
    throw new TypeError("record.request.arguments must be an object.");
  }
  const materializedArguments = materializeTaggedArguments(record.request.arguments);
  if (record.request.operation === "namespace_integrity"
    && !Array.isArray(materializedArguments.relations)) {
    throw new TypeError("record.request.arguments.relations must be an array.");
  }
  const target = caseReproducibilityTarget(record.request.operation, materializedArguments);
  requireClosedKeys(
    record.operationProfile,
    ["id", "revision", "reproducibilityTarget"],
    ["id", "revision", "reproducibilityTarget"],
    "record.operationProfile"
  );
  requireCanonicalMatch(record.operationProfile, {
    id: `text-integrity.operation.${record.request.operation}/1`,
    revision: 1,
    reproducibilityTarget: target
  }, "record.operationProfile");

  for (const field of [
    "requestSha256", "semanticSha256", "environmentSha256", "completeResultSha256"
  ]) requireDigest(record[field], `record.${field}`);
  validateDataIdentity(record.data);
  if (!valueMatchesSchema(record.result, OUTPUT_SCHEMAS[record.request.operation])) {
    throw new TypeError("record.result does not match the closed public result schema.");
  }
  const projections = splitResultProjections(record.result);
  requireCanonicalMatch(record.environment, projections.environment, "record.environment");
  if (record.requestSha256 !== canonicalDigest(record.request)) {
    throw new TypeError("record.requestSha256 does not match the tagged request.");
  }
  if (record.semanticSha256 !== canonicalDigest(projections.semantic)) {
    throw new TypeError("record.semanticSha256 does not match the semantic result projection.");
  }
  if (record.environmentSha256 !== canonicalDigest(projections.environment)) {
    throw new TypeError("record.environmentSha256 does not match the environment projection.");
  }
  if (record.completeResultSha256 !== canonicalDigest(record.result)) {
    throw new TypeError("record.completeResultSha256 does not match the complete result.");
  }
  validateFixedNonClaims(record.nonClaims, MEASUREMENT_RECORD_NON_CLAIMS, "record.nonClaims");
  return record;
}

export function parseMeasurementRecord(input) {
  let json;
  let actualBytes;
  if (typeof input === "string") {
    if (input.length > MEASUREMENT_RECORD_LIMITS.maxInputBytes) {
      throw new RangeError(
        `measurement record input exceeds ${MEASUREMENT_RECORD_LIMITS.maxInputBytes} bytes.`
      );
    }
    actualBytes = Buffer.byteLength(input, "utf8");
    if (actualBytes > MEASUREMENT_RECORD_LIMITS.maxInputBytes) {
      throw new RangeError(
        `measurement record input exceeds ${MEASUREMENT_RECORD_LIMITS.maxInputBytes} bytes.`
      );
    }
    json = input;
  } else if (utilTypes.isUint8Array(input)) {
    actualBytes = typedArrayByteLength.call(input);
    if (actualBytes > MEASUREMENT_RECORD_LIMITS.maxInputBytes) {
      throw new RangeError(
        `measurement record input exceeds ${MEASUREMENT_RECORD_LIMITS.maxInputBytes} bytes.`
      );
    }
    try {
      const bytes = new Uint8Array(actualBytes);
      Uint8Array.prototype.set.call(bytes, input);
      json = measurementRecordDecoder.decode(bytes);
    } catch (error) {
      throw new TypeError("measurement record bytes must be well-formed UTF-8.", { cause: error });
    }
  } else {
    throw new TypeError("measurement record input must be an explicit string or Uint8Array.");
  }

  let record;
  try {
    assertUniqueJsonObjectKeys(json, {
      maxDepth: MEASUREMENT_RECORD_LIMITS.maxJsonDepth,
      subject: "measurement record JSON"
    });
    record = JSON.parse(json);
  } catch (error) {
    if (error instanceof DuplicateJsonKeyError || error instanceof BoundedJsonDepthError) {
      throw error;
    }
    throw new TypeError("measurement record input must contain valid JSON.", { cause: error });
  }
  return validateMeasurementRecord(record);
}

export function replayMeasurementRecord(record) {
  validateMeasurementRecord(record);
  const current = createMeasurementRecord(record.request);
  const matches = {
    productIdentity: canonicalDigest(record.product) === canonicalDigest(current.product),
    dataIdentity: canonicalDigest(record.data) === canonicalDigest(current.data),
    requestIdentity: record.requestSha256 === current.requestSha256,
    semanticResult: record.semanticSha256 === current.semanticSha256,
    environmentIdentity: record.environmentSha256 === current.environmentSha256,
    completeResult: record.completeResultSha256 === current.completeResultSha256
  };
  let changeKind = "exact_match";
  if (!matches.productIdentity) changeKind = "product_identity_changed";
  else if (!matches.dataIdentity) changeKind = "data_identity_changed";
  else if (!matches.semanticResult) changeKind = "semantic_changed";
  else if (!matches.environmentIdentity || !matches.completeResult) {
    changeKind = "environment_metadata_changed";
  }
  const crossRuntimeRequired = record.operationProfile.reproducibilityTarget === "cross_runtime_exact";
  const replay = {
    schemaVersion: MEASUREMENT_REPLAY_SCHEMA_VERSION,
    authority: "current_runtime_replay_observation",
    scope: "one_supported_measurement_record",
    selfCertifying: false,
    complete: true,
    reproducibilityTarget: record.operationProfile.reproducibilityTarget,
    recorded: {
      recordSha256: canonicalDigest(record),
      product: { ...record.product },
      dataSha256: canonicalDigest(record.data),
      requestSha256: record.requestSha256,
      semanticSha256: record.semanticSha256,
      environmentSha256: record.environmentSha256,
      completeResultSha256: record.completeResultSha256
    },
    current: {
      measurementSha256: canonicalDigest(current),
      product: { ...current.product },
      dataSha256: canonicalDigest(current.data),
      requestSha256: current.requestSha256,
      semanticSha256: current.semanticSha256,
      environmentSha256: current.environmentSha256,
      completeResultSha256: current.completeResultSha256
    },
    matches,
    changeKind,
    crossRuntimeExpectation: {
      required: crossRuntimeRequired,
      met: crossRuntimeRequired ? matches.dataIdentity && matches.semanticResult : null
    },
    nonClaims: [...MEASUREMENT_REPLAY_NON_CLAIMS]
  };
  const actualBytes = Buffer.byteLength(JSON.stringify(replay), "utf8");
  if (actualBytes > MEASUREMENT_REPLAY_LIMITS.maxSerializedBytes) {
    throw new TextIntegrityError(
      "RESULT_TOO_LARGE",
      `The complete measurement replay exceeds ${MEASUREMENT_REPLAY_LIMITS.maxSerializedBytes} bytes.`,
      { actualBytes, limitBytes: MEASUREMENT_REPLAY_LIMITS.maxSerializedBytes }
    );
  }
  return replay;
}
