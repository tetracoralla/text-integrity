import { createHash } from "node:crypto";
import { UTS46_ENGINE_IDENTITY, UTS46_RUNTIME_FILES } from "../core/protocol-engine.js";
import { compareUtf16CodeUnits } from "../core/string-order.js";
import { canonicalDigest, sha256Hex } from "./canonical.js";
import { COLLATION_CALIBRATION_SCHEMA_VERSION } from "./collation-calibration.js";
import {
  COLLATION_COMPARISON_LIMITS,
  COLLATION_COMPARISON_SCHEMA_VERSION
} from "./collation-comparison.js";
import {
  BEHAVIOR_COMPARISON_SCHEMA_VERSION,
  BEHAVIOR_CORPUS_SCHEMA_VERSION,
  BEHAVIOR_MANIFEST_SCHEMA_VERSION,
  ENVIRONMENT_PROJECTION_SCHEMA_VERSION,
  MEASUREMENT_COMPARISON_SCHEMA_VERSION,
  MEASUREMENT_RECORD_SCHEMA_VERSION,
  MEASUREMENT_REPLAY_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_COMPARISON_SCHEMA_VERSION,
  PROPERTY_VERIFICATION_SCHEMA_VERSION,
  PUBLIC_RESULT_SCHEMA_VERSION,
  REPLAY_RECEIPT_COMPARISON_SCHEMA_VERSION,
  REFERENCE_WASM_MANIFEST_SCHEMA_VERSION,
  SEMANTIC_PROJECTION_SCHEMA_VERSION,
  TAGGED_REQUEST_SCHEMA_VERSION
} from "./versions.js";
import {
  REFERENCE_WASM_MODULE_INTERFACE,
  REFERENCE_WASM_RAW_ABI
} from "./wasm.js";

export const REPLAY_RECEIPT_SCHEMA_VERSION = "text-integrity.replay-receipt/2";
export const REPLAY_INSTALLED_RUNTIME_FILES = UTS46_RUNTIME_FILES;
export const REFERENCE_SOURCE_FILES = Object.freeze([
  "src/reference/behavior.js",
  "src/reference/canonical.js",
  "src/reference/collation-calibration.js",
  "src/reference/collation-comparison.js",
  "src/reference/json-validation.js",
  "src/reference/measurement-comparison.js",
  "src/reference/measurement.js",
  "src/reference/package-replay-sidecar.js",
  "src/reference/property-verification.js",
  "src/reference/replay-receipt.js",
  "src/reference/replay-comparison.js",
  "src/reference/replay-validation.js",
  "src/reference/versions.js",
  "src/reference/wasm.js"
]);
export const REPLAY_RECEIPT_LIMITS = Object.freeze({
  maxPackageManifestBytes: 65536,
  maxBehaviorCorpusBytes: 131072,
  maxBehaviorManifestBytes: 262144,
  maxJsonManifestBytes: 65536,
  maxUnicodeDataBytes: 1048576,
  maxBidiRuntimeBytes: 131072,
  maxReferenceSourceFileBytes: 131072,
  maxReferenceSourceTreeBytes: 524288,
  maxInstalledRuntimeFileBytes: 2097152,
  maxInstalledRuntimeTreeBytes: 4194304,
  maxWasmModuleBytes: 4194304,
  maxPackageArtifactBytes: 16777216,
  maxSerializedBytes: 32768
});

const decoder = new TextDecoder("utf-8", { fatal: true });

function requireClosedKeys(value, allowed, required, field) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object.`);
  }
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw new TypeError(`${field} has unknown fields: ${unknown.sort().join(", ")}.`);
  const missing = required.filter((key) => !Object.hasOwn(value, key));
  if (missing.length > 0) throw new TypeError(`${field} is missing fields: ${missing.join(", ")}.`);
}

function explicitBytes(value, maximum, field) {
  const bytes = typeof value === "string"
    ? new TextEncoder().encode(value)
    : value instanceof Uint8Array ? value : null;
  if (bytes === null) throw new TypeError(`${field} must be an explicit string or byte array.`);
  if (bytes.byteLength > maximum) throw new RangeError(`${field} exceeds ${maximum} bytes.`);
  return bytes;
}

function parseJsonBytes(value, maximum, field) {
  const bytes = explicitBytes(value, maximum, field);
  let parsed;
  try {
    parsed = JSON.parse(decoder.decode(bytes));
  } catch (error) {
    throw new TypeError(`${field} must contain well-formed UTF-8 JSON.`, { cause: error });
  }
  return { bytes, parsed };
}

function byteIdentity(bytes) {
  return { bytes: bytes.byteLength, sha256: sha256Hex(bytes) };
}

function requireDigest(actual, expected, field) {
  if (actual !== expected) throw new TypeError(`${field} does not match its recorded SHA-256.`);
}

function requireString(value, field) {
  if (typeof value !== "string" || value.length === 0 || !value.isWellFormed()) {
    throw new TypeError(`${field} must be a non-empty well-formed string.`);
  }
}

function requireSha256(value, field) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new TypeError(`${field} must be a lowercase SHA-256 digest.`);
  }
}

function requireExactJson(actual, expected, field) {
  if (canonicalDigest(actual) !== canonicalDigest(expected)) {
    throw new TypeError(`${field} does not match the supported reference WASM contract.`);
  }
}

function validateReferenceWasmManifest(value, moduleBytes) {
  requireClosedKeys(value, [
    "schemaVersion", "rustToolchain", "rustc", "target", "sourceSha256",
    "cargoLockSha256", "rawAbi", "wasm"
  ], [
    "schemaVersion", "rustToolchain", "rustc", "target", "sourceSha256",
    "cargoLockSha256", "rawAbi", "wasm"
  ], "input.wasmManifest");
  if (value.schemaVersion !== REFERENCE_WASM_MANIFEST_SCHEMA_VERSION) {
    throw new TypeError("Reference WASM manifest uses an unsupported schema version.");
  }
  requireString(value.rustToolchain, "input.wasmManifest.rustToolchain");
  requireString(value.rustc, "input.wasmManifest.rustc");
  if (value.target !== "wasm32-unknown-unknown") {
    throw new TypeError("input.wasmManifest.target must be wasm32-unknown-unknown.");
  }
  requireSha256(value.sourceSha256, "input.wasmManifest.sourceSha256");
  requireSha256(value.cargoLockSha256, "input.wasmManifest.cargoLockSha256");

  requireClosedKeys(value.rawAbi, [
    "version", "maxInputBytes", "maxBatchRequests", "maxResultBytes", "workLimits", "statuses"
  ], [
    "version", "maxInputBytes", "maxBatchRequests", "maxResultBytes", "workLimits", "statuses"
  ], "input.wasmManifest.rawAbi");
  requireClosedKeys(value.rawAbi.workLimits, [
    "differenceAlignmentCells", "sourceDiagnosticUnits", "uts46PunycodeScanUnits"
  ], [
    "differenceAlignmentCells", "sourceDiagnosticUnits", "uts46PunycodeScanUnits"
  ], "input.wasmManifest.rawAbi.workLimits");
  requireClosedKeys(value.rawAbi.statuses, [
    "ok", "invalidInputBuffer", "inputTooLarge", "batchTooLarge", "resultTooLarge",
    "differenceAlignmentWorkTooLarge", "sourceDiagnosticWorkTooLarge",
    "uts46PunycodeWorkTooLarge"
  ], [
    "ok", "invalidInputBuffer", "inputTooLarge", "batchTooLarge", "resultTooLarge",
    "differenceAlignmentWorkTooLarge", "sourceDiagnosticWorkTooLarge",
    "uts46PunycodeWorkTooLarge"
  ], "input.wasmManifest.rawAbi.statuses");
  requireExactJson(value.rawAbi, REFERENCE_WASM_RAW_ABI, "input.wasmManifest.rawAbi");

  requireClosedKeys(value.wasm, [
    "path", "bytes", "sha256", "imports", "exports"
  ], [
    "path", "bytes", "sha256", "imports", "exports"
  ], "input.wasmManifest.wasm");
  if (value.wasm.path !== "text_integrity_reference.wasm") {
    throw new TypeError("input.wasmManifest.wasm.path does not match the package contract.");
  }
  if (!Number.isSafeInteger(value.wasm.bytes) || value.wasm.bytes < 0) {
    throw new TypeError("input.wasmManifest.wasm.bytes must be a non-negative safe integer.");
  }
  requireSha256(value.wasm.sha256, "input.wasmManifest.wasm.sha256");
  requireExactJson(
    { imports: value.wasm.imports, exports: value.wasm.exports },
    REFERENCE_WASM_MODULE_INTERFACE,
    "input.wasmManifest.wasm interface"
  );

  if (value.wasm.bytes !== moduleBytes.byteLength
    || value.wasm.sha256 !== byteIdentity(moduleBytes).sha256) {
    throw new TypeError("Reference WASM manifest and module bytes do not agree.");
  }

  let module;
  try {
    module = new WebAssembly.Module(moduleBytes);
  } catch (error) {
    throw new TypeError("input.wasmModule must contain a valid WebAssembly module.", { cause: error });
  }
  const actualInterface = {
    imports: WebAssembly.Module.imports(module),
    exports: WebAssembly.Module.exports(module).map(({ name, kind }) => ({ name, kind }))
  };
  requireExactJson(actualInterface, REFERENCE_WASM_MODULE_INTERFACE, "input.wasmModule interface");
}

function explicitFileSet(values, expectedPaths, perFileMaximum, totalMaximum, field) {
  if (!Array.isArray(values)) throw new TypeError(`${field} must be an explicit file-byte array.`);
  const entries = new Map();
  let totalBytes = 0;
  for (const [index, value] of values.entries()) {
    requireClosedKeys(value, ["path", "bytes"], ["path", "bytes"], `${field}[${index}]`);
    if (typeof value.path !== "string" || !value.path.isWellFormed() || entries.has(value.path)) {
      throw new TypeError(`${field}[${index}].path must be a unique well-formed string.`);
    }
    const bytes = explicitBytes(value.bytes, perFileMaximum, `${field}[${index}].bytes`);
    totalBytes += bytes.byteLength;
    if (totalBytes > totalMaximum) throw new RangeError(`${field} exceeds ${totalMaximum} combined bytes.`);
    entries.set(value.path, bytes);
  }
  const actualPaths = [...entries.keys()].sort(compareUtf16CodeUnits);
  const requiredPaths = [...expectedPaths].sort(compareUtf16CodeUnits);
  if (actualPaths.length !== requiredPaths.length
    || actualPaths.some((path, index) => path !== requiredPaths[index])) {
    throw new TypeError(`${field} must contain exactly the required fixed file labels.`);
  }
  return expectedPaths.map((path) => ({ path, bytes: entries.get(path) }));
}

function treeIdentity(entries) {
  const hash = createHash("sha256");
  const files = entries.map(({ path, bytes }) => {
    hash.update(path);
    hash.update(Buffer.from([0]));
    hash.update(bytes);
    hash.update(Buffer.from([0]));
    return { path, ...byteIdentity(bytes) };
  });
  return {
    algorithm: "ordered_path_nul_bytes_nul_sha256",
    sha256: hash.digest("hex"),
    fileCount: files.length,
    files
  };
}

function collationIdentity(calibration) {
  return {
    schemaVersion: calibration.schemaVersion,
    authority: calibration.authority,
    environmentBound: calibration.environmentBound,
    configurationCount: calibration.configurationCount,
    comparisonCount: calibration.comparisonCount,
    probeSetSha256: calibration.probeSetSha256,
    observationSha256: calibration.observationSha256,
    environment: calibration.environment
  };
}

export function createReplayReceipt(input) {
  requireClosedKeys(input, [
    "packageManifest", "behaviorCorpus", "behaviorManifest", "unicodeSourceManifest",
    "unicodeCompactManifest", "unicodeCompactData", "bidiManifest", "bidiRuntime",
    "referenceSources", "wasmManifest", "wasmModule", "installedRuntimeFiles",
    "packageArtifact"
  ], [
    "packageManifest", "behaviorCorpus", "behaviorManifest", "unicodeSourceManifest",
    "unicodeCompactManifest", "unicodeCompactData", "bidiManifest", "bidiRuntime",
    "referenceSources", "wasmManifest", "wasmModule", "installedRuntimeFiles"
  ], "input");

  const packageManifest = parseJsonBytes(
    input.packageManifest,
    REPLAY_RECEIPT_LIMITS.maxPackageManifestBytes,
    "input.packageManifest"
  );
  const behaviorCorpus = parseJsonBytes(
    input.behaviorCorpus,
    REPLAY_RECEIPT_LIMITS.maxBehaviorCorpusBytes,
    "input.behaviorCorpus"
  );
  const behaviorManifest = parseJsonBytes(
    input.behaviorManifest,
    REPLAY_RECEIPT_LIMITS.maxBehaviorManifestBytes,
    "input.behaviorManifest"
  );
  const unicodeSourceManifest = parseJsonBytes(
    input.unicodeSourceManifest,
    REPLAY_RECEIPT_LIMITS.maxJsonManifestBytes,
    "input.unicodeSourceManifest"
  );
  const unicodeCompactManifest = parseJsonBytes(
    input.unicodeCompactManifest,
    REPLAY_RECEIPT_LIMITS.maxJsonManifestBytes,
    "input.unicodeCompactManifest"
  );
  const bidiManifest = parseJsonBytes(
    input.bidiManifest,
    REPLAY_RECEIPT_LIMITS.maxJsonManifestBytes,
    "input.bidiManifest"
  );
  const wasmManifest = parseJsonBytes(
    input.wasmManifest,
    REPLAY_RECEIPT_LIMITS.maxJsonManifestBytes,
    "input.wasmManifest"
  );
  const unicodeCompactData = explicitBytes(
    input.unicodeCompactData,
    REPLAY_RECEIPT_LIMITS.maxUnicodeDataBytes,
    "input.unicodeCompactData"
  );
  const bidiRuntime = explicitBytes(
    input.bidiRuntime,
    REPLAY_RECEIPT_LIMITS.maxBidiRuntimeBytes,
    "input.bidiRuntime"
  );
  const wasmModule = explicitBytes(
    input.wasmModule,
    REPLAY_RECEIPT_LIMITS.maxWasmModuleBytes,
    "input.wasmModule"
  );
  const referenceSources = treeIdentity(explicitFileSet(
    input.referenceSources,
    REFERENCE_SOURCE_FILES,
    REPLAY_RECEIPT_LIMITS.maxReferenceSourceFileBytes,
    REPLAY_RECEIPT_LIMITS.maxReferenceSourceTreeBytes,
    "input.referenceSources"
  ));
  const installedRuntime = treeIdentity(explicitFileSet(
    input.installedRuntimeFiles,
    UTS46_RUNTIME_FILES,
    REPLAY_RECEIPT_LIMITS.maxInstalledRuntimeFileBytes,
    REPLAY_RECEIPT_LIMITS.maxInstalledRuntimeTreeBytes,
    "input.installedRuntimeFiles"
  ));
  const packageArtifact = input.packageArtifact === undefined || input.packageArtifact === null
    ? null
    : byteIdentity(explicitBytes(
      input.packageArtifact,
      REPLAY_RECEIPT_LIMITS.maxPackageArtifactBytes,
      "input.packageArtifact"
    ));

  const packageValue = packageManifest.parsed;
  const corpusValue = behaviorCorpus.parsed;
  const manifestValue = behaviorManifest.parsed;
  const sourceDataValue = unicodeSourceManifest.parsed;
  const compactValue = unicodeCompactManifest.parsed;
  const bidiValue = bidiManifest.parsed;
  const wasmValue = wasmManifest.parsed;

  if (corpusValue.schemaVersion !== BEHAVIOR_CORPUS_SCHEMA_VERSION
    || manifestValue.schemaVersion !== BEHAVIOR_MANIFEST_SCHEMA_VERSION
    || manifestValue.corpus?.schemaVersion !== BEHAVIOR_CORPUS_SCHEMA_VERSION
    || manifestValue.engines?.collation?.schemaVersion !== COLLATION_CALIBRATION_SCHEMA_VERSION) {
    throw new TypeError("Replay artifacts use an unsupported schema version.");
  }
  validateReferenceWasmManifest(wasmValue, wasmModule);
  if (packageValue.name !== manifestValue.product?.name
    || packageValue.version !== manifestValue.product?.version
    || packageValue.dependencies?.tr46 !== UTS46_ENGINE_IDENTITY.version
    || packageValue.dependencies?.punycode !== UTS46_ENGINE_IDENTITY.dependency.version
    || canonicalDigest(manifestValue.engines?.uts46) !== canonicalDigest(UTS46_ENGINE_IDENTITY)) {
    throw new TypeError("Package, behavior, and UTS #46 engine identities do not agree.");
  }
  for (const [subpath, target] of Object.entries({
    "./reference": "./src/reference/behavior.js",
    "./reference/replay-receipt.json": "./reference/replay-receipt.json",
    "./reference/wasm": "./src/reference/wasm.js",
    "./reference/wasm/module": "./wasm/text_integrity_reference.wasm"
  })) {
    if (packageValue.exports?.[subpath] !== target) {
      throw new TypeError(`Package export ${subpath} does not match the replay contract.`);
    }
  }
  if (manifestValue.corpus?.caseCount !== corpusValue.cases?.length
    || manifestValue.corpus?.sha256 !== canonicalDigest(corpusValue)) {
    throw new TypeError("Behavior corpus bytes do not reproduce the manifest corpus identity.");
  }
  requireDigest(
    byteIdentity(unicodeSourceManifest.bytes).sha256,
    manifestValue.data?.sourceManifestSha256,
    "Unicode source manifest"
  );
  requireDigest(
    byteIdentity(unicodeCompactManifest.bytes).sha256,
    manifestValue.data?.compactManifestSha256,
    "Unicode compact manifest"
  );
  requireDigest(
    byteIdentity(unicodeCompactData).sha256,
    manifestValue.data?.compactDataSha256,
    "Unicode compact data"
  );
  const compactDataEntry = compactValue.files?.find(({ path }) => path === "data.bin");
  if (sourceDataValue.unicodeVersion !== manifestValue.data?.unicodeVersion
    || sourceDataValue.uts39Revision !== manifestValue.data?.uts39Revision
    || compactValue.formatVersion !== manifestValue.data?.compactFormatVersion
    || compactValue.sourceManifestSha256 !== manifestValue.data?.sourceManifestSha256
    || compactDataEntry?.bytes !== unicodeCompactData.byteLength
    || compactDataEntry?.sha256 !== manifestValue.data?.compactDataSha256) {
    throw new TypeError("Unicode source, compact manifest, data, and behavior identities do not agree.");
  }
  const bidiEntry = bidiValue.files?.find(({ path }) => path === "bidi.mjs");
  if (bidiValue.unicodeVersion !== manifestValue.data?.unicodeVersion
    || bidiEntry?.bytes !== bidiRuntime.byteLength
    || bidiEntry?.sha256 !== byteIdentity(bidiRuntime).sha256) {
    throw new TypeError("Vendored Bidi manifest and runtime bytes do not agree.");
  }
  if (installedRuntime.sha256 !== manifestValue.engines.uts46.runtimeTreeSha256) {
    throw new TypeError("Installed UTS #46 runtime bytes do not match the behavior engine identity.");
  }

  const receipt = {
    schemaVersion: REPLAY_RECEIPT_SCHEMA_VERSION,
    authority: "reproduction_locator",
    scope: "named_replay_inputs_only",
    selfCertifying: false,
    product: { name: packageValue.name, version: packageValue.version },
    contracts: {
      taggedRequest: TAGGED_REQUEST_SCHEMA_VERSION,
      publicResult: PUBLIC_RESULT_SCHEMA_VERSION,
      measurementRecord: MEASUREMENT_RECORD_SCHEMA_VERSION,
      measurementReplay: MEASUREMENT_REPLAY_SCHEMA_VERSION,
      measurementComparison: MEASUREMENT_COMPARISON_SCHEMA_VERSION,
      semanticProjection: SEMANTIC_PROJECTION_SCHEMA_VERSION,
      environmentProjection: ENVIRONMENT_PROJECTION_SCHEMA_VERSION,
      behaviorCorpus: BEHAVIOR_CORPUS_SCHEMA_VERSION,
      behaviorManifest: BEHAVIOR_MANIFEST_SCHEMA_VERSION,
      behaviorComparison: BEHAVIOR_COMPARISON_SCHEMA_VERSION,
      collationCalibration: COLLATION_CALIBRATION_SCHEMA_VERSION,
      collationComparison: COLLATION_COMPARISON_SCHEMA_VERSION,
      collationComparisonLimits: COLLATION_COMPARISON_LIMITS,
      packageReplaySidecar: PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION,
      packageReplaySidecarByteVerification:
        PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_SCHEMA_VERSION,
      packageReplaySidecarComparison: PACKAGE_REPLAY_SIDECAR_COMPARISON_SCHEMA_VERSION,
      propertyVerification: PROPERTY_VERIFICATION_SCHEMA_VERSION,
      replayReceiptComparison: REPLAY_RECEIPT_COMPARISON_SCHEMA_VERSION,
      referenceWasmManifest: REFERENCE_WASM_MANIFEST_SCHEMA_VERSION
    },
    artifacts: {
      packageManifest: { path: "package.json", ...byteIdentity(packageManifest.bytes) },
      behaviorCorpus: {
        path: "reference/behavior-corpus.json",
        ...byteIdentity(behaviorCorpus.bytes),
        canonicalSha256: canonicalDigest(corpusValue),
        caseCount: corpusValue.cases.length
      },
      behaviorManifest: {
        path: "reference/behavior-manifest.json",
        ...byteIdentity(behaviorManifest.bytes),
        behaviorRootSha256: manifestValue.behaviorRootSha256
      },
      unicodeSourceManifest: {
        path: "vendor/unicode/17.0.0/MANIFEST.json",
        ...byteIdentity(unicodeSourceManifest.bytes)
      },
      unicodeCompactManifest: {
        path: "vendor/unicode/17.0.0/compact/MANIFEST.json",
        ...byteIdentity(unicodeCompactManifest.bytes)
      },
      unicodeCompactData: {
        path: "vendor/unicode/17.0.0/compact/data.bin",
        ...byteIdentity(unicodeCompactData)
      },
      bidiManifest: {
        path: "vendor/bidi-js-unicode17/MANIFEST.json",
        ...byteIdentity(bidiManifest.bytes)
      },
      bidiRuntime: {
        path: "vendor/bidi-js-unicode17/bidi.mjs",
        ...byteIdentity(bidiRuntime)
      },
      referenceSources,
      referenceWasmManifest: {
        path: "wasm/MANIFEST.json",
        ...byteIdentity(wasmManifest.bytes)
      },
      referenceWasmModule: {
        path: "wasm/text_integrity_reference.wasm",
        ...byteIdentity(wasmModule)
      },
      packageArtifact
    },
    engines: {
      uts46: {
        identity: manifestValue.engines.uts46,
        installedRuntime
      },
      collation: collationIdentity(manifestValue.engines.collation)
    },
    sourceRerunCommands: [
      "npm run replay:check",
      "npm run behavior:check",
      "npm run property:check",
      "npm run check:independent",
      "npm run check"
    ],
    nonClaims: [
      "byte identity is not semantic correctness",
      "a generated receipt does not certify itself",
      ...(packageArtifact === null
        ? ["packageArtifact is null until an external tarball is supplied explicitly"]
        : ["packageArtifact binds only the explicitly supplied external bytes"]),
      "business, experience, release, and publication acceptance remain external"
    ]
  };
  const serializedBytes = new TextEncoder().encode(JSON.stringify(receipt)).byteLength;
  if (serializedBytes > REPLAY_RECEIPT_LIMITS.maxSerializedBytes) {
    throw new RangeError("The complete replay receipt exceeds its serialized-result limit.");
  }
  return receipt;
}
