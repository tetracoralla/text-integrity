import { canonicalDigest } from "./canonical.js";
import { compareUtf16CodeUnits } from "../core/string-order.js";
import {
  REPLAY_RECEIPT_LIMITS,
  REPLAY_RECEIPT_SCHEMA_VERSION
} from "./replay-receipt.js";
import { PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION } from "./versions.js";

const UNION = Symbol("union");
const union = (...variants) => Object.freeze({ [UNION]: variants });

export const REPLAY_IDENTITY_VALIDATION_LIMITS = Object.freeze({
  maxTreeFiles: 32,
  maxObjectKeys: 64,
  maxArrayItems: 64,
  maxIdentifierCodeUnits: 512
});

const BYTE_IDENTITY = Object.freeze({ bytes: "uint", sha256: "sha256" });
const PATH_BYTE_IDENTITY = Object.freeze({
  path: "string",
  bytes: "uint",
  sha256: "sha256"
});
const TREE_IDENTITY = Object.freeze({
  algorithm: "string",
  sha256: "sha256",
  fileCount: "uint",
  files: [PATH_BYTE_IDENTITY]
});
const REPLAY_RECEIPT_SHAPE = Object.freeze({
  schemaVersion: "string",
  authority: "string",
  scope: "string",
  selfCertifying: "boolean",
  product: { name: "string", version: "string" },
  contracts: {
    taggedRequest: "string",
    publicResult: "string",
    measurementRecord: "string",
    measurementReplay: "string",
    measurementComparison: "string",
    semanticProjection: "string",
    environmentProjection: "string",
    behaviorCorpus: "string",
    behaviorManifest: "string",
    behaviorComparison: "string",
    collationCalibration: "string",
    collationComparison: "string",
    collationComparisonLimits: {
      maxConfigurations: "uint",
      maxComparisons: "uint",
      maxIdentifierCodeUnits: "uint",
      maxRuntimeValueCodeUnits: "uint",
      maxSerializedBytes: "uint"
    },
    packageReplaySidecar: "string",
    packageReplaySidecarByteVerification: "string",
    packageReplaySidecarComparison: "string",
    propertyVerification: "string",
    replayReceiptComparison: "string",
    referenceWasmManifest: "string"
  },
  artifacts: {
    packageManifest: PATH_BYTE_IDENTITY,
    behaviorCorpus: {
      path: "string",
      bytes: "uint",
      sha256: "sha256",
      canonicalSha256: "sha256",
      caseCount: "uint"
    },
    behaviorManifest: {
      path: "string",
      bytes: "uint",
      sha256: "sha256",
      behaviorRootSha256: "sha256"
    },
    unicodeSourceManifest: PATH_BYTE_IDENTITY,
    unicodeCompactManifest: PATH_BYTE_IDENTITY,
    unicodeCompactData: PATH_BYTE_IDENTITY,
    bidiManifest: PATH_BYTE_IDENTITY,
    bidiRuntime: PATH_BYTE_IDENTITY,
    referenceSources: TREE_IDENTITY,
    referenceWasmManifest: PATH_BYTE_IDENTITY,
    referenceWasmModule: PATH_BYTE_IDENTITY,
    packageArtifact: union(null, BYTE_IDENTITY)
  },
  engines: {
    uts46: {
      identity: {
        specification: "string",
        unicodeVersion: "string",
        package: "string",
        version: "string",
        packageIntegrity: "string",
        runtimeTreeSha256: "sha256",
        dependency: {
          name: "string",
          version: "string",
          packageIntegrity: "string"
        },
        conformance: {
          corpus: "string",
          compressedSha256: "sha256",
          uncompressedSha256: "sha256",
          wellFormedCaseCount: "uint",
          rerunCommand: "string"
        }
      },
      installedRuntime: TREE_IDENTITY
    },
    collation: {
      schemaVersion: "string",
      authority: "string",
      environmentBound: "boolean",
      configurationCount: "uint",
      comparisonCount: "uint",
      probeSetSha256: "sha256",
      observationSha256: "sha256",
      environment: {
        node: "string",
        icu: "string",
        unicode: "string",
        cldr: "string"
      }
    }
  },
  sourceRerunCommands: ["string"],
  nonClaims: ["string"]
});
const PACKAGE_REPLAY_SIDECAR_SHAPE = Object.freeze({
  schemaVersion: "string",
  authority: "string",
  selfCertifying: "boolean",
  package: {
    filename: "string",
    bytes: "uint",
    shasum: "sha1",
    sha256: "sha256",
    integrity: "sha512"
  },
  receipt: REPLAY_RECEIPT_SHAPE,
  nonClaims: ["string"]
});

function byteLength(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function requireString(value, field, maximum) {
  if (typeof value !== "string" || value.length > maximum || !value.isWellFormed()) {
    throw new TypeError(`${field} must be a bounded well-formed string.`);
  }
}

function validateShape(value, shape, field, limits) {
  if (shape === null) {
    if (value !== null) throw new TypeError(`${field} must be null.`);
    return;
  }
  if (shape === "string") {
    requireString(value, field, limits.maxIdentifierCodeUnits);
    return;
  }
  if (shape === "boolean") {
    if (typeof value !== "boolean") throw new TypeError(`${field} must be a boolean.`);
    return;
  }
  if (shape === "uint") {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(`${field} must be a non-negative safe integer.`);
    }
    return;
  }
  if (shape === "sha1" || shape === "sha256") {
    const length = shape === "sha1" ? 40 : 64;
    if (typeof value !== "string" || !new RegExp(`^[0-9a-f]{${length}}$`, "u").test(value)) {
      throw new TypeError(`${field} must be a lowercase ${shape.toUpperCase()} digest.`);
    }
    return;
  }
  if (shape === "sha512") {
    if (typeof value !== "string" || !/^sha512-[A-Za-z0-9+/]{86}==$/u.test(value)) {
      throw new TypeError(`${field} must be a SHA-512 SRI identity.`);
    }
    return;
  }
  if (shape?.[UNION] !== undefined) {
    if (!shape[UNION].some((variant) => {
      try {
        validateShape(value, variant, field, limits);
        return true;
      } catch {
        return false;
      }
    })) throw new TypeError(`${field} does not match a supported shape.`);
    return;
  }
  if (Array.isArray(shape)) {
    if (!Array.isArray(value) || value.length > limits.maxArrayItems) {
      throw new TypeError(`${field} must be a bounded array.`);
    }
    value.forEach((item, index) => validateShape(item, shape[0], `${field}[${index}]`, limits));
    return;
  }
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object.`);
  }
  const actual = Object.keys(value).sort(compareUtf16CodeUnits);
  const expected = Object.keys(shape).sort(compareUtf16CodeUnits);
  if (actual.length !== expected.length
    || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${field} must contain exactly the supported fields.`);
  }
  for (const key of expected) validateShape(value[key], shape[key], `${field}.${key}`, limits);
}

function validateTree(tree, field, limits) {
  if (tree.files.length > limits.maxTreeFiles || tree.fileCount !== tree.files.length) {
    throw new TypeError(`${field} must contain a complete bounded file array.`);
  }
  const paths = new Set();
  for (const file of tree.files) {
    if (paths.has(file.path)) throw new TypeError(`${field}.files must have unique paths.`);
    paths.add(file.path);
  }
}

export function validateReplayReceipt(value, field, limits) {
  validateShape(value, REPLAY_RECEIPT_SHAPE, field, limits);
  if (value.schemaVersion !== REPLAY_RECEIPT_SCHEMA_VERSION
    || byteLength(value) > REPLAY_RECEIPT_LIMITS.maxSerializedBytes) {
    throw new TypeError(`${field} must be a bounded supported replay receipt.`);
  }
  validateTree(value.artifacts.referenceSources, `${field}.artifacts.referenceSources`, limits);
  validateTree(value.engines.uts46.installedRuntime, `${field}.engines.uts46.installedRuntime`, limits);
  canonicalDigest(value);
}

export function validatePackageReplaySidecar(value, field, limits, maximumBytes) {
  validateShape(value, PACKAGE_REPLAY_SIDECAR_SHAPE, field, limits);
  if (value.schemaVersion !== PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION
    || byteLength(value) > maximumBytes) {
    throw new TypeError(`${field} must be a bounded supported package replay sidecar.`);
  }
  validateReplayReceipt(value.receipt, `${field}.receipt`, limits);
  const packageArtifact = value.receipt.artifacts.packageArtifact;
  const expectedFilename = `${value.receipt.product.name}-${value.receipt.product.version}.tgz`;
  if (packageArtifact === null
    || value.package.filename !== expectedFilename
    || value.package.bytes !== packageArtifact.bytes
    || value.package.sha256 !== packageArtifact.sha256) {
    throw new TypeError(
      `${field} package byte identity must match its nested receipt and product identity.`
    );
  }
  canonicalDigest(value);
}
