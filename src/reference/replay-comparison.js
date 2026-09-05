import { compareUtf16CodeUnits } from "../core/string-order.js";
import { canonicalDigest } from "./canonical.js";
import { PACKAGE_REPLAY_SIDECAR_LIMITS } from "./package-replay-sidecar.js";
import {
  PACKAGE_REPLAY_SIDECAR_COMPARISON_SCHEMA_VERSION,
  REPLAY_RECEIPT_COMPARISON_SCHEMA_VERSION
} from "./versions.js";
import {
  REPLAY_IDENTITY_VALIDATION_LIMITS,
  validatePackageReplaySidecar,
  validateReplayReceipt
} from "./replay-validation.js";

export {
  PACKAGE_REPLAY_SIDECAR_COMPARISON_SCHEMA_VERSION,
  REPLAY_RECEIPT_COMPARISON_SCHEMA_VERSION
};

export const REPLAY_RECEIPT_COMPARISON_LIMITS = Object.freeze({
  ...REPLAY_IDENTITY_VALIDATION_LIMITS,
  maxChanges: 128,
  maxSerializedBytes: 32768
});

export const PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS = Object.freeze({
  maxChanges: 64,
  maxSerializedBytes: 65536
});

const MISSING = Symbol("missing");

function byteLength(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function normalizeTree(value, field) {
  const fileOrder = [];
  const fileEntries = [];
  for (const file of value.files) {
    const { path, ...identity } = file;
    fileOrder.push(path);
    fileEntries.push([path, identity]);
  }
  return {
    algorithm: value.algorithm,
    sha256: value.sha256,
    fileCount: value.fileCount,
    fileOrder,
    filesByPath: Object.fromEntries(fileEntries)
  };
}

function normalizeReceipt(value, field) {
  validateReplayReceipt(value, field, REPLAY_RECEIPT_COMPARISON_LIMITS);
  return {
    ...value,
    artifacts: {
      ...value.artifacts,
      referenceSources: normalizeTree(
        value.artifacts.referenceSources,
        `${field}.artifacts.referenceSources`
      )
    },
    engines: {
      ...value.engines,
      uts46: {
        ...value.engines.uts46,
        installedRuntime: normalizeTree(
          value.engines.uts46.installedRuntime,
          `${field}.engines.uts46.installedRuntime`
        )
      }
    }
  };
}

function valueType(value) {
  if (value === MISSING) return "missing";
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value === "object" ? "object" : typeof value;
}

function pointer(path, key) {
  const escaped = String(key).replaceAll("~", "~0").replaceAll("/", "~1");
  return `${path}/${escaped}`;
}

function digestOrUndefined(value) {
  return value === MISSING ? undefined : canonicalDigest(value);
}

function pushChange(changes, path, before, after, maximum) {
  if (changes.length >= maximum) {
    throw new RangeError("The complete identity comparison exceeds its change-count limit.");
  }
  const beforeType = valueType(before);
  const afterType = valueType(after);
  changes.push({
    path: path || "/",
    kind: before === MISSING ? "added"
      : after === MISSING ? "removed"
        : beforeType === afterType ? "value_changed" : "type_changed",
    beforeType,
    afterType,
    ...(before === MISSING ? {} : { beforeSha256: digestOrUndefined(before) }),
    ...(after === MISSING ? {} : { afterSha256: digestOrUndefined(after) })
  });
}

function diffValues(before, after, path, changes, maximum) {
  if (before === MISSING || after === MISSING) {
    pushChange(changes, path, before, after, maximum);
    return;
  }
  if (canonicalDigest(before) === canonicalDigest(after)) return;
  const beforeType = valueType(before);
  const afterType = valueType(after);
  if (beforeType === "object" && afterType === "object") {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])]
      .sort(compareUtf16CodeUnits);
    for (const key of keys) {
      diffValues(
        Object.hasOwn(before, key) ? before[key] : MISSING,
        Object.hasOwn(after, key) ? after[key] : MISSING,
        pointer(path, key),
        changes,
        maximum
      );
    }
    return;
  }
  pushChange(changes, path, before, after, maximum);
}

function receiptCategory(path) {
  if (path.startsWith("/product")) return "product";
  if (path.startsWith("/contracts") || [
    "/schemaVersion", "/authority", "/scope", "/selfCertifying"
  ].includes(path)) return "contract";
  if (path.startsWith("/artifacts")) return "artifact";
  if (path.startsWith("/engines")) return "engine";
  if (path.startsWith("/sourceRerunCommands") || path.startsWith("/nonClaims")) {
    return "metadata";
  }
  return "unclassified";
}

function receiptSummary(value) {
  return {
    schemaVersion: value.schemaVersion,
    receiptSha256: canonicalDigest(value),
    productSha256: canonicalDigest(value.product)
  };
}

function enforceResultLimit(value, maximum, message) {
  if (byteLength(value) > maximum) throw new RangeError(message);
  return value;
}

export function compareReplayReceipts(before, after) {
  const normalizedBefore = normalizeReceipt(before, "before");
  const normalizedAfter = normalizeReceipt(after, "after");
  const changes = [];
  diffValues(
    normalizedBefore,
    normalizedAfter,
    "",
    changes,
    REPLAY_RECEIPT_COMPARISON_LIMITS.maxChanges
  );
  const beforeDigest = canonicalDigest(before);
  const afterDigest = canonicalDigest(after);
  if (beforeDigest !== afterDigest && changes.length === 0) {
    pushChange(
      changes,
      "/",
      before,
      after,
      REPLAY_RECEIPT_COMPARISON_LIMITS.maxChanges
    );
  }
  const categories = Object.fromEntries([
    "product", "contract", "artifact", "engine", "metadata", "unclassified"
  ].map((category) => [
    category,
    changes.filter(({ path }) => receiptCategory(path) === category).length
  ]));
  const result = {
    schemaVersion: REPLAY_RECEIPT_COMPARISON_SCHEMA_VERSION,
    authority: "identity_drift_observation",
    complete: true,
    before: receiptSummary(before),
    after: receiptSummary(after),
    changed: beforeDigest !== afterDigest,
    productIdentityChanged: categories.product > 0,
    contractIdentityChanged: categories.contract > 0,
    artifactIdentityChanged: categories.artifact > 0,
    engineIdentityChanged: categories.engine > 0,
    metadataIdentityChanged: categories.metadata > 0,
    changeCount: changes.length,
    categoryCounts: categories,
    changes,
    unclassifiedChangeCount: categories.unclassified,
    nonClaims: [
      "identity drift does not classify cause or correctness",
      "the comparison does not authorize release or publication"
    ]
  };
  return enforceResultLimit(
    result,
    REPLAY_RECEIPT_COMPARISON_LIMITS.maxSerializedBytes,
    "The complete replay-receipt comparison exceeds its serialized-result limit."
  );
}

function normalizeSidecar(value, field) {
  validatePackageReplaySidecar(
    value,
    field,
    REPLAY_RECEIPT_COMPARISON_LIMITS,
    PACKAGE_REPLAY_SIDECAR_LIMITS.maxSerializedBytes
  );
  return value;
}

export function comparePackageReplaySidecars(before, after) {
  normalizeSidecar(before, "before");
  normalizeSidecar(after, "after");
  const receiptComparison = compareReplayReceipts(before.receipt, after.receipt);
  const ownBefore = {
    schemaVersion: before.schemaVersion,
    authority: before.authority,
    selfCertifying: before.selfCertifying,
    package: before.package,
    nonClaims: before.nonClaims
  };
  const ownAfter = {
    schemaVersion: after.schemaVersion,
    authority: after.authority,
    selfCertifying: after.selfCertifying,
    package: after.package,
    nonClaims: after.nonClaims
  };
  const changes = [];
  diffValues(
    ownBefore,
    ownAfter,
    "",
    changes,
    PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS.maxChanges
  );
  const beforeDigest = canonicalDigest(before);
  const afterDigest = canonicalDigest(after);
  if (beforeDigest !== afterDigest && changes.length === 0 && !receiptComparison.changed) {
    pushChange(
      changes,
      "/",
      before,
      after,
      PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS.maxChanges
    );
  }
  const packageChangeCount = changes.filter(({ path }) => path.startsWith("/package")).length;
  const unclassifiedChangeCount = changes.filter(({ path }) => path === "/").length;
  const metadataChangeCount = changes.length - packageChangeCount - unclassifiedChangeCount;
  const result = {
    schemaVersion: PACKAGE_REPLAY_SIDECAR_COMPARISON_SCHEMA_VERSION,
    authority: "package_identity_drift_observation",
    complete: true,
    before: {
      schemaVersion: before.schemaVersion,
      sidecarSha256: beforeDigest,
      packageSha256: canonicalDigest(before.package)
    },
    after: {
      schemaVersion: after.schemaVersion,
      sidecarSha256: afterDigest,
      packageSha256: canonicalDigest(after.package)
    },
    changed: beforeDigest !== afterDigest,
    packageIdentityChanged: packageChangeCount > 0,
    receiptIdentityChanged: receiptComparison.changed,
    metadataIdentityChanged: metadataChangeCount > 0,
    changeCount: changes.length + receiptComparison.changeCount,
    changes,
    receiptComparison,
    unclassifiedChangeCount,
    nonClaims: [
      "identity drift does not classify cause or correctness",
      "the comparison does not authorize release or publication"
    ]
  };
  return enforceResultLimit(
    result,
    PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS.maxSerializedBytes,
    "The complete package-sidecar comparison exceeds its serialized-result limit."
  );
}
