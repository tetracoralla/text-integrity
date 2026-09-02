import { compareUtf16CodeUnits } from "../core/string-order.js";
import { canonicalDigest } from "./canonical.js";
import { COLLATION_CALIBRATION_SCHEMA_VERSION } from "./collation-calibration.js";

export const COLLATION_COMPARISON_SCHEMA_VERSION = "text-integrity.collation-comparison/1";
export const COLLATION_COMPARISON_LIMITS = Object.freeze({
  maxConfigurations: 15,
  maxComparisons: 45,
  maxIdentifierCodeUnits: 128,
  maxRuntimeValueCodeUnits: 128,
  maxSerializedBytes: 65536
});

const SHA256_PATTERN = /^[0-9a-f]{64}$/u;

function requireBoundedString(value, maximum, field) {
  if (typeof value !== "string" || value.length > maximum || !value.isWellFormed()) {
    throw new TypeError(`${field} must be a bounded well-formed string.`);
  }
}

function requireCalibration(value, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || value.schemaVersion !== COLLATION_CALIBRATION_SCHEMA_VERSION
    || !Array.isArray(value.configurations)
    || value.configurations.length > COLLATION_COMPARISON_LIMITS.maxConfigurations) {
    throw new TypeError(`${field} must be a supported collation calibration.`);
  }
  requireBoundedString(
    value.authority,
    COLLATION_COMPARISON_LIMITS.maxRuntimeValueCodeUnits,
    `${field}.authority`
  );
  if (typeof value.environmentBound !== "boolean"
    || !SHA256_PATTERN.test(value.probeSetSha256)
    || !SHA256_PATTERN.test(value.observationSha256)
    || value.environment === null || typeof value.environment !== "object"
    || Array.isArray(value.environment)) {
    throw new TypeError(`${field} has invalid calibration identity fields.`);
  }
  if (Object.keys(value.environment).sort(compareUtf16CodeUnits).join(",")
    !== "cldr,icu,node,unicode") {
    throw new TypeError(`${field}.environment must contain exactly node, ICU, Unicode, and CLDR versions.`);
  }
  for (const key of ["node", "icu", "unicode", "cldr"]) {
    requireBoundedString(
      value.environment[key],
      COLLATION_COMPARISON_LIMITS.maxRuntimeValueCodeUnits,
      `${field}.environment.${key}`
    );
  }
  const configurationIds = new Set();
  let comparisonCount = 0;
  for (const configuration of value.configurations) {
    if (configuration === null || typeof configuration !== "object" || Array.isArray(configuration)
      || typeof configuration.id !== "string" || configuration.id === ""
      || configuration.id.length > COLLATION_COMPARISON_LIMITS.maxIdentifierCodeUnits
      || !configuration.id.isWellFormed() || configurationIds.has(configuration.id)
      || !Array.isArray(configuration.comparisons)) {
      throw new TypeError(`${field}.configurations must have unique well-formed IDs and comparison arrays.`);
    }
    configurationIds.add(configuration.id);
    requireBoundedString(
      configuration.requestedLocale,
      COLLATION_COMPARISON_LIMITS.maxRuntimeValueCodeUnits,
      `${field}.${configuration.id}.requestedLocale`
    );
    requireBoundedString(
      configuration.canonicalLocale,
      COLLATION_COMPARISON_LIMITS.maxRuntimeValueCodeUnits,
      `${field}.${configuration.id}.canonicalLocale`
    );
    const comparisonIds = new Set();
    for (const comparison of configuration.comparisons) {
      if (comparison === null || typeof comparison !== "object" || Array.isArray(comparison)
        || typeof comparison.id !== "string" || comparison.id === ""
        || comparison.id.length > COLLATION_COMPARISON_LIMITS.maxIdentifierCodeUnits
        || !comparison.id.isWellFormed() || comparisonIds.has(comparison.id)
        || typeof comparison.left !== "string" || typeof comparison.right !== "string"
        || !comparison.left.isWellFormed() || !comparison.right.isWellFormed()
        || ![-1, 0, 1].includes(comparison.order)
        || comparison.relation !== (comparison.order < 0 ? "before" : comparison.order > 0 ? "after" : "equal")) {
        throw new TypeError(`${field}.${configuration.id}.comparisons has an invalid observation.`);
      }
      comparisonIds.add(comparison.id);
      comparisonCount += 1;
      if (comparisonCount > COLLATION_COMPARISON_LIMITS.maxComparisons) {
        throw new TypeError(`${field} exceeds the comparison-count limit.`);
      }
    }
  }
  if (value.configurationCount !== value.configurations.length
    || value.comparisonCount !== comparisonCount) {
    throw new TypeError(`${field} count fields do not match its configuration matrix.`);
  }
}

function calibrationIdentity(calibration) {
  return {
    schemaVersion: calibration.schemaVersion,
    authority: calibration.authority,
    environmentBound: calibration.environmentBound,
    configurationCount: calibration.configurationCount,
    comparisonCount: calibration.comparisonCount,
    probeSetSha256: calibration.probeSetSha256,
    observationSha256: calibration.observationSha256,
    environment: {
      node: calibration.environment.node,
      icu: calibration.environment.icu,
      unicode: calibration.environment.unicode,
      cldr: calibration.environment.cldr
    }
  };
}

function byId(values) {
  return new Map(values.map((value) => [value.id, value]));
}

function sortedUnion(left, right) {
  return [...new Set([...left.keys(), ...right.keys()])].sort(compareUtf16CodeUnits);
}

function sameValue(left, right) {
  return canonicalDigest(left) === canonicalDigest(right);
}

export function compareCollationCalibrations(before, after) {
  requireCalibration(before, "before");
  requireCalibration(after, "after");

  const beforeConfigurations = byId(before.configurations);
  const afterConfigurations = byId(after.configurations);
  const configurationChanges = [];
  const comparisonChanges = [];

  for (const configurationId of sortedUnion(beforeConfigurations, afterConfigurations)) {
    const oldConfiguration = beforeConfigurations.get(configurationId);
    const newConfiguration = afterConfigurations.get(configurationId);
    if (!oldConfiguration) {
      configurationChanges.push({ configurationId, kind: "configuration_added" });
      continue;
    }
    if (!newConfiguration) {
      configurationChanges.push({ configurationId, kind: "configuration_removed" });
      continue;
    }
    const oldRequest = {
      requestedLocale: oldConfiguration.requestedLocale,
      requestedOptions: oldConfiguration.requestedOptions
    };
    const newRequest = {
      requestedLocale: newConfiguration.requestedLocale,
      requestedOptions: newConfiguration.requestedOptions
    };
    if (!sameValue(oldRequest, newRequest)) {
      configurationChanges.push({
        configurationId,
        kind: "request_changed",
        beforeSha256: canonicalDigest(oldRequest),
        afterSha256: canonicalDigest(newRequest)
      });
    }
    if (oldConfiguration.canonicalLocale !== newConfiguration.canonicalLocale) {
      configurationChanges.push({
        configurationId,
        kind: "canonical_locale_changed",
        before: oldConfiguration.canonicalLocale,
        after: newConfiguration.canonicalLocale
      });
    }
    if (!sameValue(oldConfiguration.resolvedOptions, newConfiguration.resolvedOptions)) {
      configurationChanges.push({
        configurationId,
        kind: "resolved_options_changed",
        beforeSha256: canonicalDigest(oldConfiguration.resolvedOptions),
        afterSha256: canonicalDigest(newConfiguration.resolvedOptions)
      });
    }

    const oldComparisons = byId(oldConfiguration.comparisons);
    const newComparisons = byId(newConfiguration.comparisons);
    for (const comparisonId of sortedUnion(oldComparisons, newComparisons)) {
      const oldComparison = oldComparisons.get(comparisonId);
      const newComparison = newComparisons.get(comparisonId);
      if (!oldComparison) {
        comparisonChanges.push({ configurationId, comparisonId, kind: "pair_added" });
        continue;
      }
      if (!newComparison) {
        comparisonChanges.push({ configurationId, comparisonId, kind: "pair_removed" });
        continue;
      }
      const oldInput = { left: oldComparison.left, right: oldComparison.right };
      const newInput = { left: newComparison.left, right: newComparison.right };
      if (!sameValue(oldInput, newInput)) {
        comparisonChanges.push({
          configurationId,
          comparisonId,
          kind: "pair_input_changed",
          beforeSha256: canonicalDigest(oldInput),
          afterSha256: canonicalDigest(newInput)
        });
        continue;
      }
      if (oldComparison.order !== newComparison.order
        || oldComparison.relation !== newComparison.relation) {
        comparisonChanges.push({
          configurationId,
          comparisonId,
          kind: "order_changed",
          before: { order: oldComparison.order, relation: oldComparison.relation },
          after: { order: newComparison.order, relation: newComparison.relation }
        });
      }
    }
  }

  const probeSetChanged = before.probeSetSha256 !== after.probeSetSha256;
  const observationDigestChanged = before.observationSha256 !== after.observationSha256;
  const runtimeIdentityChanged = !sameValue(before.environment, after.environment);
  const authorityChanged = before.authority !== after.authority
    || before.environmentBound !== after.environmentBound;
  const probeDetailsChanged = configurationChanges.some(({ kind }) => [
    "configuration_added", "configuration_removed", "request_changed"
  ].includes(kind)) || comparisonChanges.some(({ kind }) => [
    "pair_added", "pair_removed", "pair_input_changed"
  ].includes(kind));
  const observationDetailsChanged = probeDetailsChanged || runtimeIdentityChanged
    || configurationChanges.some(({ kind }) => [
      "canonical_locale_changed", "resolved_options_changed"
    ].includes(kind))
    || comparisonChanges.some(({ kind }) => kind === "order_changed");

  const result = {
    schemaVersion: COLLATION_COMPARISON_SCHEMA_VERSION,
    complete: true,
    before: calibrationIdentity(before),
    after: calibrationIdentity(after),
    changed: authorityChanged || probeSetChanged || observationDigestChanged
      || configurationChanges.length > 0 || comparisonChanges.length > 0,
    authorityChanged,
    probeSetChanged,
    runtimeIdentityChanged,
    observationDigestChanged,
    probeDigestChangedWithoutDetailedChange: probeSetChanged && !probeDetailsChanged,
    observationDigestChangedWithoutDetailedChange: observationDigestChanged
      && !observationDetailsChanged,
    configurationChanges,
    comparisonChanges,
    pairOrderChangedCount: comparisonChanges.filter(({ kind }) => kind === "order_changed").length
  };
  const serializedBytes = new TextEncoder().encode(JSON.stringify(result)).byteLength;
  if (serializedBytes > COLLATION_COMPARISON_LIMITS.maxSerializedBytes) {
    throw new RangeError("The complete collation comparison exceeds its serialized-result limit.");
  }
  return result;
}
