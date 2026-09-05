import { canonicalDigest } from "./canonical.js";
import { validateMeasurementRecord } from "./measurement.js";
import { MEASUREMENT_COMPARISON_SCHEMA_VERSION } from "./versions.js";

export { MEASUREMENT_COMPARISON_SCHEMA_VERSION };

export const MEASUREMENT_COMPARISON_LIMITS = Object.freeze({
  maxSerializedBytes: 8192
});

const MATCH_FIELDS = Object.freeze([
  ["productIdentity", "product_identity_changed"],
  ["dataIdentity", "data_identity_changed"],
  ["requestIdentity", "request_identity_changed"],
  ["semanticResult", "semantic_result_identity_changed"],
  ["environmentIdentity", "environment_identity_changed"],
  ["completeResult", "complete_result_identity_changed"]
]);

function recordSummary(record) {
  return {
    recordSha256: canonicalDigest(record),
    schemaVersion: record.schemaVersion,
    product: { ...record.product },
    contractsSha256: canonicalDigest(record.contracts),
    operationProfile: { ...record.operationProfile },
    dataSha256: canonicalDigest(record.data),
    requestSha256: record.requestSha256,
    semanticSha256: record.semanticSha256,
    environmentSha256: record.environmentSha256,
    completeResultSha256: record.completeResultSha256
  };
}

function withinResultLimit(result) {
  const serializedBytes = new TextEncoder().encode(JSON.stringify(result)).byteLength;
  if (serializedBytes > MEASUREMENT_COMPARISON_LIMITS.maxSerializedBytes) {
    throw new RangeError(
      "The complete measurement-record comparison exceeds its serialized-result limit."
    );
  }
  return result;
}

export function compareMeasurementRecords(before, after) {
  validateMeasurementRecord(before);
  validateMeasurementRecord(after);

  const matches = {
    productIdentity: canonicalDigest(before.product) === canonicalDigest(after.product),
    dataIdentity: canonicalDigest(before.data) === canonicalDigest(after.data),
    requestIdentity: before.requestSha256 === after.requestSha256,
    semanticResult: before.semanticSha256 === after.semanticSha256,
    environmentIdentity: before.environmentSha256 === after.environmentSha256,
    completeResult: before.completeResultSha256 === after.completeResultSha256
  };
  const differences = MATCH_FIELDS
    .filter(([field]) => !matches[field])
    .map(([, kind]) => kind);
  const semanticComparisonApplicable = matches.requestIdentity;
  const crossRuntimeRequired = semanticComparisonApplicable
    && before.operationProfile.reproducibilityTarget === "cross_runtime_exact";

  return withinResultLimit({
    schemaVersion: MEASUREMENT_COMPARISON_SCHEMA_VERSION,
    authority: "measurement_identity_comparison_observation",
    scope: "two_supported_measurement_records",
    selfCertifying: false,
    complete: true,
    before: recordSummary(before),
    after: recordSummary(after),
    changed: differences.length > 0,
    semanticComparisonApplicable,
    matches,
    differenceCount: differences.length,
    differences,
    crossRuntimeExpectation: {
      required: crossRuntimeRequired,
      met: crossRuntimeRequired
        ? matches.dataIdentity && matches.semanticResult
        : null
    },
    nonClaims: [
      "Identity equality is not correctness, conformance, producer honesty, or runtime equivalence.",
      "Different request identities are not one comparable semantic measurement.",
      "Environment identity equality does not establish equivalent runtime behavior.",
      "The comparison does not classify cause or authorize release, rollback, or business acceptance."
    ]
  });
}
