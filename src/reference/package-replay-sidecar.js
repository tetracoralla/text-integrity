import { createHash } from "node:crypto";
import { canonicalDigest, sha256Hex } from "./canonical.js";
import { createReplayReceipt, REPLAY_RECEIPT_LIMITS } from "./replay-receipt.js";
import {
  REPLAY_IDENTITY_VALIDATION_LIMITS,
  validatePackageReplaySidecar
} from "./replay-validation.js";
import {
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION
} from "./versions.js";

export {
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_SCHEMA_VERSION,
  PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION
};

export const PACKAGE_REPLAY_SIDECAR_LIMITS = Object.freeze({ maxSerializedBytes: 65536 });
export const PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS = Object.freeze({
  maxSerializedBytes: 4096
});

function explicitPackageBytes(value) {
  const bytes = typeof value === "string"
    ? new TextEncoder().encode(value)
    : value instanceof Uint8Array ? value : null;
  if (bytes === null) {
    throw new TypeError("input.packageArtifact must be an explicit string or byte array.");
  }
  if (bytes.byteLength > REPLAY_RECEIPT_LIMITS.maxPackageArtifactBytes) {
    throw new RangeError(
      `input.packageArtifact exceeds ${REPLAY_RECEIPT_LIMITS.maxPackageArtifactBytes} bytes.`
    );
  }
  return bytes;
}

function packageIdentity(packageBytes) {
  return {
    bytes: packageBytes.byteLength,
    shasum: createHash("sha1").update(packageBytes).digest("hex"),
    sha256: sha256Hex(packageBytes),
    integrity: `sha512-${createHash("sha512").update(packageBytes).digest("base64")}`
  };
}

export function createPackageReplaySidecar(input) {
  if (input?.packageArtifact === undefined || input.packageArtifact === null) {
    throw new TypeError("input.packageArtifact is required for a package replay sidecar.");
  }
  const packageBytes = explicitPackageBytes(input.packageArtifact);
  const receipt = createReplayReceipt(input);
  const sidecar = {
    schemaVersion: PACKAGE_REPLAY_SIDECAR_SCHEMA_VERSION,
    authority: "package_byte_identity_locator",
    selfCertifying: false,
    package: {
      filename: `${receipt.product.name}-${receipt.product.version}.tgz`,
      ...packageIdentity(packageBytes)
    },
    receipt,
    nonClaims: [
      "package bytes and named replay inputs are identities, not semantic correctness",
      "the sidecar does not certify itself or authorize release or publication"
    ]
  };
  const serializedBytes = new TextEncoder().encode(JSON.stringify(sidecar)).byteLength;
  if (serializedBytes > PACKAGE_REPLAY_SIDECAR_LIMITS.maxSerializedBytes) {
    throw new RangeError("The complete package replay sidecar exceeds its serialized-result limit.");
  }
  return sidecar;
}

export function verifyPackageReplaySidecarBytes(sidecar, packageArtifact) {
  validatePackageReplaySidecar(
    sidecar,
    "sidecar",
    REPLAY_IDENTITY_VALIDATION_LIMITS,
    PACKAGE_REPLAY_SIDECAR_LIMITS.maxSerializedBytes
  );
  const actualPackage = packageIdentity(explicitPackageBytes(packageArtifact));
  const matches = {
    bytes: actualPackage.bytes === sidecar.package.bytes,
    shasum: actualPackage.shasum === sidecar.package.shasum,
    sha256: actualPackage.sha256 === sidecar.package.sha256,
    integrity: actualPackage.integrity === sidecar.package.integrity
  };
  const result = {
    schemaVersion: PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_SCHEMA_VERSION,
    authority: "package_byte_match_observation",
    complete: true,
    sidecar: {
      schemaVersion: sidecar.schemaVersion,
      sha256: canonicalDigest(sidecar)
    },
    actualPackage,
    matches,
    matched: Object.values(matches).every(Boolean),
    nonClaims: [
      "matching bytes do not establish semantic correctness or conformance",
      "the observation does not authorize release, publication, or rollback"
    ]
  };
  const serializedBytes = new TextEncoder().encode(JSON.stringify(result)).byteLength;
  if (serializedBytes > PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS.maxSerializedBytes) {
    throw new RangeError(
      "The complete package-sidecar byte verification exceeds its serialized-result limit."
    );
  }
  return result;
}
