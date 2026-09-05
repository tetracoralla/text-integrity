import { createHash } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { analyzeNamespaceIntegrity } from "../src/core/namespace-integrity.js";
import { executeOperation } from "../src/core/operations.js";
import { UTS46_RUNTIME_FILES } from "../src/core/protocol-engine.js";
import { OUTPUT_SCHEMAS } from "../src/output-schemas.js";
import {
  createReferenceWasmRunner,
  REFERENCE_WASM_LIMITS,
  REFERENCE_WASM_RAW_ABI
} from "../src/reference/wasm.js";
import {
  BEHAVIOR_CORPUS_SCHEMA_VERSION,
  BEHAVIOR_MANIFEST_SCHEMA_VERSION,
  COLLATION_COMPARISON_LIMITS,
  PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS,
  PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS,
  PACKAGE_REPLAY_SIDECAR_LIMITS,
  MEASUREMENT_RECORD_LIMITS,
  MEASUREMENT_COMPARISON_LIMITS,
  MEASUREMENT_REPLAY_LIMITS,
  PROPERTY_VERIFICATION_LIMITS,
  REFERENCE_SOURCE_FILES,
  REPLAY_RECEIPT_COMPARISON_LIMITS,
  REPLAY_RECEIPT_LIMITS,
  canonicalJson,
  canonicalDigest,
  compareBehaviorManifests,
  compareCollationCalibrations,
  compareMeasurementRecords,
  comparePackageReplaySidecars,
  compareReplayReceipts,
  createBehaviorManifest,
  createCollationCalibration,
  createMeasurementRecord,
  createPackageReplaySidecar,
  createReplayReceipt,
  materializeTaggedArguments,
  environmentProjection,
  parseMeasurementRecord,
  replayMeasurementRecord,
  runPropertyVerification,
  semanticProjection,
  validateMeasurementRecord,
  verifyPackageReplaySidecarBytes
} from "../src/reference/behavior.js";

const corpus = JSON.parse(readFileSync(new URL("../reference/behavior-corpus.json", import.meta.url), "utf8"));
const committedManifest = JSON.parse(readFileSync(new URL("../reference/behavior-manifest.json", import.meta.url), "utf8"));
const committedReplayReceipt = JSON.parse(readFileSync(
  new URL("../reference/replay-receipt.json", import.meta.url),
  "utf8"
));

function replayBytes(relativePath) {
  return readFileSync(new URL(`../${relativePath}`, import.meta.url));
}

function currentReplayInputs() {
  return {
    packageManifest: replayBytes("package.json"),
    behaviorCorpus: replayBytes("reference/behavior-corpus.json"),
    behaviorManifest: replayBytes("reference/behavior-manifest.json"),
    unicodeSourceManifest: replayBytes("vendor/unicode/17.0.0/MANIFEST.json"),
    unicodeCompactManifest: replayBytes("vendor/unicode/17.0.0/compact/MANIFEST.json"),
    unicodeCompactData: replayBytes("vendor/unicode/17.0.0/compact/data.bin"),
    bidiManifest: replayBytes("vendor/bidi-js-unicode17/MANIFEST.json"),
    bidiRuntime: replayBytes("vendor/bidi-js-unicode17/bidi.mjs"),
    referenceSources: REFERENCE_SOURCE_FILES.map((path) => ({ path, bytes: replayBytes(path) })),
    wasmManifest: replayBytes("wasm/MANIFEST.json"),
    wasmModule: replayBytes("wasm/text_integrity_reference.wasm"),
    installedRuntimeFiles: UTS46_RUNTIME_FILES.map((path) => ({
      path,
      bytes: replayBytes(`node_modules/${path}`)
    }))
  };
}

function mutatedWasmManifest(inputs, mutate) {
  const manifest = JSON.parse(inputs.wasmManifest.toString("utf8"));
  mutate(manifest);
  return Buffer.from(JSON.stringify(manifest));
}

test("canonical JSON is independent of object insertion order", () => {
  assert.equal(
    canonicalJson({ z: [3, { b: true, a: "x" }], a: null }),
    canonicalJson({ a: null, z: [3, { a: "x", b: true }] })
  );
  assert.throws(() => canonicalJson({ value: Number.NaN }), /finite numbers/u);
  assert.throws(() => canonicalJson({ value: undefined }), /undefined/u);
});

test("fixed generated properties and request mutations replay as a bounded observation", () => {
  const first = runPropertyVerification();
  const second = runPropertyVerification();
  assert.deepEqual(second, first);
  assert.equal(first.schemaVersion, "text-integrity.property-verification/2");
  assert.equal(first.authority, "deterministic_check_observation");
  assert.equal(first.selfCertifying, false);
  assert.equal(first.complete, true);
  assert.equal(first.passed, true);
  assert.equal(first.generator.corpusSha256, "4f032c7ffcc39706dee7496e0ddd03e6d7d70f650c2ab556937b860080d4fd8e");
  assert.equal(first.propertyRootSha256, "5b07d40770ac9c9db051fc22a8c77a28a6ffcd74b4b964ef0f930f89f75c8e96");
  assert.deepEqual(first.totals, {
    propertyCount: 8,
    caseEvaluationCount: 1646,
    assertionCount: 15278
  });
  assert.equal(first.properties.find(({ id }) => id === "declared_collation_algebra").environmentBound, true);
  assert.equal(first.properties.every(({ passed }) => passed), true);
  assert.equal(
    Buffer.byteLength(JSON.stringify(first), "utf8") <= PROPERTY_VERIFICATION_LIMITS.maxSerializedBytes,
    true
  );
});

test("behavior case ordering is explicit UTF-16 order and rejects malformed IDs", () => {
  const argumentsValue = {
    text: { $text: { kind: "unicode_scalar_string", value: "A" } },
    form: "NFC"
  };
  const generated = createBehaviorManifest({
    schemaVersion: BEHAVIOR_CORPUS_SCHEMA_VERSION,
    cases: [
      { id: "\ue000", operation: "normalize", arguments: argumentsValue },
      { id: "𐀀", operation: "normalize", arguments: argumentsValue }
    ]
  });
  assert.deepEqual(generated.cases.map(({ id }) => id), ["𐀀", "\ue000"]);
  assert.throws(() => createBehaviorManifest({
    schemaVersion: BEHAVIOR_CORPUS_SCHEMA_VERSION,
    cases: [{ id: "\ud800", operation: "normalize", arguments: argumentsValue }]
  }), /well-formed/u);
});

test("collation calibration fingerprints the bounded ICU observation matrix", () => {
  const calibration = createCollationCalibration();
  assert.equal(calibration.schemaVersion, "text-integrity.collation-calibration/1");
  assert.equal(calibration.authority, "runtime_icu_observation");
  assert.equal(calibration.environmentBound, true);
  assert.equal(calibration.configurationCount, 15);
  assert.equal(calibration.comparisonCount, 45);
  assert.equal(calibration.probeSetSha256, "42f126f05d03846e252081939c643ec5d0db4cec481f0b65afc5f8f9775a627c");
  assert.deepEqual(calibration.environment, {
    node: process.versions.node, icu: process.versions.icu ?? null,
    unicode: process.versions.unicode ?? null, cldr: process.versions.cldr ?? null
  });
  assert.equal(calibration.observationSha256, canonicalDigest({
    environment: calibration.environment, configurations: calibration.configurations
  }));
  // A calibration identifies its actual ICU environment, including patch
  // versions. The pinned probe set and each consumer's observations are checked
  // separately; they are not a universal runtime fingerprint.
  const anotherEnvironment = { ...calibration.environment, node: "different-runtime" };
  assert.notEqual(calibration.observationSha256, canonicalDigest({
    environment: anotherEnvironment, configurations: calibration.configurations
  }));
  assert.deepEqual(
    [...new Set(calibration.configurations.map(({ requestedOptions }) => requestedOptions.sensitivity))].sort(),
    ["accent", "base", "case", "variant"]
  );
  assert.deepEqual(
    calibration.configurations.find(({ id }) => id === "de-phonebook")
      .comparisons.map(({ order }) => order),
    [1, 1, 1]
  );
  assert.deepEqual(
    calibration.configurations.find(({ id }) => id === "sv-default")
      .comparisons.map(({ order }) => order),
    [-1, 1, 1]
  );
});

test("all three collation consumers reproduce the calibrated observations", () => {
  const calibration = createCollationCalibration();
  for (const configuration of calibration.configurations) {
    for (const comparison of configuration.comparisons) {
      const request = {
        left: comparison.left,
        right: comparison.right,
        locale: configuration.requestedLocale,
        options: configuration.requestedOptions
      };
      const direct = executeOperation("compare", request);
      assert.equal(direct.order, comparison.order, `${configuration.id}/${comparison.id}: compare`);
      assert.deepEqual(direct.resolvedOptions, configuration.resolvedOptions);

      const difference = executeOperation("explain_difference", {
        ...request,
        confusableDirection: "LTR",
        detailLimit: 0
      });
      assert.equal(
        difference.collation.order,
        comparison.order,
        `${configuration.id}/${comparison.id}: explain_difference`
      );
      assert.deepEqual(difference.collation.resolvedOptions, configuration.resolvedOptions);

      const namespace = analyzeNamespaceIntegrity({
        items: [
          { id: "left", text: comparison.left, scope: "calibration" },
          { id: "right", text: comparison.right, scope: "calibration" }
        ],
        relations: [{
          kind: "declared_collation",
          locale: configuration.requestedLocale,
          options: configuration.requestedOptions
        }]
      });
      assert.equal(
        namespace.groups.length,
        comparison.order === 0 ? 1 : 0,
        `${configuration.id}/${comparison.id}: namespace_integrity`
      );
      assert.deepEqual(namespace.relations[0].definition.resolvedOptions, configuration.resolvedOptions);
    }
  }
});

test("collation comparisons report complete bounded probe and observation drift", () => {
  const calibration = createCollationCalibration();
  const identical = compareCollationCalibrations(calibration, calibration);
  assert.equal(identical.schemaVersion, "text-integrity.collation-comparison/1");
  assert.equal(identical.complete, true);
  assert.equal(identical.changed, false);
  assert.equal(identical.probeSetChanged, false);
  assert.equal(identical.runtimeIdentityChanged, false);
  assert.equal(identical.observationDigestChanged, false);
  assert.deepEqual(identical.configurationChanges, []);
  assert.deepEqual(identical.comparisonChanges, []);

  const runtimeChanged = structuredClone(calibration);
  runtimeChanged.environment.node = "24.20.0";
  runtimeChanged.observationSha256 = "a".repeat(64);
  const runtimeComparison = compareCollationCalibrations(calibration, runtimeChanged);
  assert.equal(runtimeComparison.runtimeIdentityChanged, true);
  assert.equal(runtimeComparison.observationDigestChanged, true);
  assert.equal(runtimeComparison.observationDigestChangedWithoutDetailedChange, false);

  const requestChanged = structuredClone(calibration);
  const requestConfiguration = requestChanged.configurations.find(({ id }) => id === "en-numeric");
  requestConfiguration.requestedOptions.numeric = false;
  requestChanged.probeSetSha256 = "b".repeat(64);
  requestChanged.observationSha256 = "c".repeat(64);
  const requestComparison = compareCollationCalibrations(calibration, requestChanged);
  assert.equal(requestComparison.probeSetChanged, true);
  assert.equal(requestComparison.probeDigestChangedWithoutDetailedChange, false);
  assert.equal(requestComparison.configurationChanges.length, 1);
  assert.equal(requestComparison.configurationChanges[0].configurationId, "en-numeric");
  assert.equal(requestComparison.configurationChanges[0].kind, "request_changed");
  assert.match(requestComparison.configurationChanges[0].beforeSha256, /^[0-9a-f]{64}$/u);
  assert.match(requestComparison.configurationChanges[0].afterSha256, /^[0-9a-f]{64}$/u);
  assert.notEqual(
    requestComparison.configurationChanges[0].beforeSha256,
    requestComparison.configurationChanges[0].afterSha256
  );

  const orderChanged = structuredClone(calibration);
  for (const configuration of orderChanged.configurations) {
    for (const comparison of configuration.comparisons) {
      comparison.order = comparison.order === 1 ? -1 : 1;
      comparison.relation = comparison.order === -1 ? "before" : "after";
    }
  }
  orderChanged.observationSha256 = "d".repeat(64);
  const orderComparison = compareCollationCalibrations(calibration, orderChanged);
  assert.equal(orderComparison.pairOrderChangedCount, 45);
  assert.equal(orderComparison.comparisonChanges.length, 45);
  assert.ok(orderComparison.comparisonChanges.every(({ kind }) => kind === "order_changed"));
  assert.ok(
    Buffer.byteLength(JSON.stringify(orderComparison), "utf8")
      <= COLLATION_COMPARISON_LIMITS.maxSerializedBytes
  );

  const digestOnlyChanged = structuredClone(calibration);
  digestOnlyChanged.observationSha256 = "e".repeat(64);
  const digestOnlyComparison = compareCollationCalibrations(calibration, digestOnlyChanged);
  assert.equal(digestOnlyComparison.observationDigestChangedWithoutDetailedChange, true);

  const oversized = structuredClone(calibration);
  oversized.configurations.push(structuredClone(oversized.configurations[0]));
  oversized.configurations.at(-1).id = "sixteenth";
  oversized.configurationCount += 1;
  oversized.comparisonCount += 3;
  assert.throws(
    () => compareCollationCalibrations(calibration, oversized),
    /supported collation calibration/u
  );

  const invalidObservation = structuredClone(calibration);
  invalidObservation.configurations[0].comparisons[0].relation = "equal";
  assert.throws(
    () => compareCollationCalibrations(calibration, invalidObservation),
    /invalid observation/u
  );
});

test("replay receipts bind explicit installed artifacts without certifying themselves", () => {
  const inputs = currentReplayInputs();
  const generated = createReplayReceipt(inputs);
  assert.deepEqual(generated, committedReplayReceipt);
  assert.equal(generated.schemaVersion, "text-integrity.replay-receipt/2");
  assert.equal(generated.authority, "reproduction_locator");
  assert.equal(generated.selfCertifying, false);
  assert.equal(generated.artifacts.packageArtifact, null);
  assert.equal(generated.artifacts.referenceSources.fileCount, 14);
  assert.equal(
    generated.contracts.measurementComparison,
    "text-integrity.measurement-comparison/1"
  );
  assert.equal(generated.engines.uts46.installedRuntime.fileCount, 7);
  assert.equal(
    generated.engines.uts46.installedRuntime.sha256,
    generated.engines.uts46.identity.runtimeTreeSha256
  );
  assert.ok(
    Buffer.byteLength(JSON.stringify(generated), "utf8")
      <= REPLAY_RECEIPT_LIMITS.maxSerializedBytes
  );

  const externalPackage = createReplayReceipt({
    ...inputs,
    packageArtifact: Uint8Array.from([0x1f, 0x8b, 0x08, 0x00])
  });
  assert.deepEqual(externalPackage.artifacts.packageArtifact, {
    bytes: 4,
    sha256: "fd72d30440b0bae1b1c6db6c8ad807f238ef3ca613aa7e8d5329e1e8ddf7da72"
  });
  assert.ok(externalPackage.nonClaims.includes(
    "packageArtifact binds only the explicitly supplied external bytes"
  ));
  const sidecar = createPackageReplaySidecar({
    ...inputs,
    packageArtifact: Uint8Array.from([0x1f, 0x8b, 0x08, 0x00])
  });
  assert.equal(sidecar.schemaVersion, "text-integrity.package-replay-sidecar/1");
  assert.equal(sidecar.authority, "package_byte_identity_locator");
  assert.equal(sidecar.selfCertifying, false);
  assert.equal(sidecar.package.filename, "text-integrity-1.0.0.tgz");
  assert.equal(sidecar.package.sha256, externalPackage.artifacts.packageArtifact.sha256);
  assert.match(sidecar.package.shasum, /^[0-9a-f]{40}$/u);
  assert.match(sidecar.package.integrity, /^sha512-[A-Za-z0-9+/]+=*$/u);
  assert.ok(
    Buffer.byteLength(JSON.stringify(sidecar), "utf8")
      <= PACKAGE_REPLAY_SIDECAR_LIMITS.maxSerializedBytes
  );
  const byteVerification = verifyPackageReplaySidecarBytes(
    sidecar,
    Uint8Array.from([0x1f, 0x8b, 0x08, 0x00])
  );
  assert.equal(
    byteVerification.schemaVersion,
    "text-integrity.package-replay-sidecar-byte-verification/1"
  );
  assert.equal(byteVerification.authority, "package_byte_match_observation");
  assert.equal(byteVerification.complete, true);
  assert.equal(byteVerification.matched, true);
  assert.ok(Object.values(byteVerification.matches).every(Boolean));
  assert.ok(
    Buffer.byteLength(JSON.stringify(byteVerification), "utf8")
      <= PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS.maxSerializedBytes
  );
  const changedByteVerification = verifyPackageReplaySidecarBytes(
    sidecar,
    Uint8Array.from([0x1f, 0x8b, 0x08, 0x00, 0x01])
  );
  assert.equal(changedByteVerification.matched, false);
  assert.ok(Object.values(changedByteVerification.matches).every((matched) => matched === false));
  assert.throws(
    () => createPackageReplaySidecar(inputs),
    /packageArtifact is required/u
  );

  const changedCorpus = structuredClone(corpus);
  changedCorpus.cases[0].id = `${changedCorpus.cases[0].id}-changed`;
  assert.throws(() => createReplayReceipt({
    ...inputs,
    behaviorCorpus: JSON.stringify(changedCorpus)
  }), /Behavior corpus bytes/u);

  const changedWasm = Uint8Array.from(inputs.wasmModule);
  changedWasm[0] ^= 0xff;
  assert.throws(
    () => createReplayReceipt({ ...inputs, wasmModule: changedWasm }),
    /WASM manifest and module bytes/u
  );
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      delete manifest.rawAbi;
    })
  }), /missing fields: rawAbi/u);
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      manifest.rawAbi.maxResultBytes += 1;
    })
  }), /rawAbi does not match/u);
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      manifest.rawAbi.workLimits.sourceDiagnosticUnits += 1;
    })
  }), /rawAbi does not match/u);
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      delete manifest.rawAbi.statuses.differenceAlignmentWorkTooLarge;
    })
  }), /rawAbi.statuses is missing fields/u);
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      manifest.rawAbi.futureStatus = 5;
    })
  }), /rawAbi has unknown fields/u);
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      manifest.futureContract = true;
    })
  }), /wasmManifest has unknown fields/u);
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      manifest.wasm.exports.pop();
    })
  }), /wasm interface does not match/u);

  const invalidWasm = Uint8Array.from(inputs.wasmModule);
  invalidWasm[0] ^= 0xff;
  assert.throws(() => createReplayReceipt({
    ...inputs,
    wasmModule: invalidWasm,
    wasmManifest: mutatedWasmManifest(inputs, (manifest) => {
      manifest.wasm.sha256 = createHash("sha256").update(invalidWasm).digest("hex");
    })
  }), /valid WebAssembly module/u);
  assert.throws(() => createReplayReceipt({
    ...inputs,
    installedRuntimeFiles: inputs.installedRuntimeFiles.slice(1)
  }), /exactly the required fixed file labels/u);
  assert.throws(
    () => createReplayReceipt({ ...inputs, ambientPath: "/tmp/input" }),
    /unknown fields/u
  );
});

test("replay comparisons name complete bounded identity drift without leaking values", () => {
  const inputs = currentReplayInputs();
  const receipt = createReplayReceipt(inputs);
  const identical = compareReplayReceipts(receipt, receipt);
  assert.equal(identical.schemaVersion, "text-integrity.replay-receipt-comparison/1");
  assert.equal(identical.authority, "identity_drift_observation");
  assert.equal(identical.complete, true);
  assert.equal(identical.changed, false);
  assert.equal(identical.changeCount, 0);
  assert.deepEqual(identical.changes, []);

  const changed = structuredClone(receipt);
  changed.contracts.replayReceiptComparison = "text-integrity.replay-receipt-comparison/changed";
  changed.artifacts.behaviorManifest.sha256 = "0".repeat(64);
  changed.artifacts.referenceSources.sha256 = "1".repeat(64);
  changed.artifacts.referenceSources.files[0].sha256 = "2".repeat(64);
  changed.engines.uts46.installedRuntime.sha256 = "3".repeat(64);
  changed.engines.uts46.installedRuntime.files[0].bytes += 1;
  changed.engines.collation.observationSha256 = "4".repeat(64);
  changed.nonClaims.push("SECRET_VALUE_MUST_NOT_APPEAR");
  const comparison = compareReplayReceipts(receipt, changed);
  assert.equal(comparison.changed, true);
  assert.equal(comparison.productIdentityChanged, false);
  assert.equal(comparison.contractIdentityChanged, true);
  assert.equal(comparison.artifactIdentityChanged, true);
  assert.equal(comparison.engineIdentityChanged, true);
  assert.equal(comparison.metadataIdentityChanged, true);
  assert.equal(comparison.unclassifiedChangeCount, 0);
  assert.deepEqual(comparison.changes.map(({ path }) => path), [
    "/artifacts/behaviorManifest/sha256",
    "/artifacts/referenceSources/filesByPath/src~1reference~1behavior.js/sha256",
    "/artifacts/referenceSources/sha256",
    "/contracts/replayReceiptComparison",
    "/engines/collation/observationSha256",
    "/engines/uts46/installedRuntime/filesByPath/tr46~1index.js/bytes",
    "/engines/uts46/installedRuntime/sha256",
    "/nonClaims"
  ]);
  assert.ok(comparison.changes.every((change) => {
    const keys = Object.keys(change);
    return keys.includes("path") && keys.includes("kind")
      && !keys.includes("before") && !keys.includes("after");
  }));
  assert.equal(JSON.stringify(comparison).includes("SECRET_VALUE_MUST_NOT_APPEAR"), false);
  assert.ok(
    Buffer.byteLength(JSON.stringify(comparison), "utf8")
      <= REPLAY_RECEIPT_COMPARISON_LIMITS.maxSerializedBytes
  );

  const secretProduct = structuredClone(receipt);
  secretProduct.product.name = "SECRET_PRODUCT_VALUE_MUST_NOT_APPEAR";
  const secretProductComparison = compareReplayReceipts(receipt, secretProduct);
  assert.equal(secretProductComparison.productIdentityChanged, true);
  assert.deepEqual(secretProductComparison.changes.map(({ path }) => path), ["/product/name"]);
  assert.equal(
    JSON.stringify(secretProductComparison).includes("SECRET_PRODUCT_VALUE_MUST_NOT_APPEAR"),
    false
  );
  assert.equal(Object.hasOwn(secretProductComparison.before, "product"), false);

  const reordered = structuredClone(receipt);
  reordered.artifacts.referenceSources.files.reverse();
  const reorderedComparison = compareReplayReceipts(receipt, reordered);
  assert.deepEqual(reorderedComparison.changes.map(({ path }) => path), [
    "/artifacts/referenceSources/fileOrder"
  ]);

  const packageAdded = structuredClone(receipt);
  packageAdded.artifacts.packageArtifact = { bytes: 4, sha256: "5".repeat(64) };
  assert.deepEqual(compareReplayReceipts(receipt, packageAdded).changes.map(({ path, kind }) => ({
    path,
    kind
  })), [{ path: "/artifacts/packageArtifact", kind: "type_changed" }]);

  const prototypePath = structuredClone(receipt);
  prototypePath.artifacts.referenceSources.files[0].path = "__proto__";
  const prototypeComparison = compareReplayReceipts(receipt, prototypePath);
  assert.equal(prototypeComparison.artifactIdentityChanged, true);
  assert.equal(({}).polluted, undefined);

  const beforeWide = structuredClone(receipt);
  const afterWide = structuredClone(receipt);
  for (const [index, [beforeTree, afterTree]] of [
    [beforeWide.artifacts.referenceSources, afterWide.artifacts.referenceSources],
    [beforeWide.engines.uts46.installedRuntime, afterWide.engines.uts46.installedRuntime]
  ].entries()) {
    beforeTree.files = Array.from({ length: 32 }, (_, fileIndex) => ({
      path: `before-${index}-${fileIndex}`,
      bytes: fileIndex,
      sha256: "a".repeat(64)
    }));
    afterTree.files = Array.from({ length: 32 }, (_, fileIndex) => ({
      path: `after-${index}-${fileIndex}`,
      bytes: fileIndex + 1,
      sha256: "b".repeat(64)
    }));
    beforeTree.fileCount = 32;
    afterTree.fileCount = 32;
    beforeTree.sha256 = "c".repeat(64);
    afterTree.sha256 = "d".repeat(64);
  }
  assert.throws(
    () => compareReplayReceipts(beforeWide, afterWide),
    /change-count limit/u
  );
  assert.throws(
    () => compareReplayReceipts(receipt, { ...receipt, unexpected: true }),
    /exactly the supported fields/u
  );
  assert.throws(
    () => compareReplayReceipts(receipt, { ...receipt, schemaVersion: "unsupported" }),
    /bounded supported replay receipt/u
  );
  for (const mutate of [
    (value) => { value.product.unexpected = true; },
    (value) => { value.artifacts.behaviorManifest.unexpected = true; },
    (value) => { value.engines.collation.unexpected = true; }
  ]) {
    const malformed = structuredClone(receipt);
    mutate(malformed);
    assert.throws(
      () => compareReplayReceipts(receipt, malformed),
      /exactly the supported fields/u
    );
  }

  const beforeSidecar = createPackageReplaySidecar({
    ...inputs,
    packageArtifact: Uint8Array.from([1, 2, 3])
  });
  const afterSidecar = createPackageReplaySidecar({
    ...inputs,
    packageArtifact: Uint8Array.from([1, 2, 3, 4])
  });
  const sidecarComparison = comparePackageReplaySidecars(beforeSidecar, afterSidecar);
  assert.equal(
    sidecarComparison.schemaVersion,
    "text-integrity.package-replay-sidecar-comparison/1"
  );
  assert.equal(sidecarComparison.complete, true);
  assert.equal(sidecarComparison.packageIdentityChanged, true);
  assert.equal(sidecarComparison.receiptIdentityChanged, true);
  assert.equal(sidecarComparison.unclassifiedChangeCount, 0);
  assert.ok(sidecarComparison.receiptComparison.changes.some(
    ({ path }) => path === "/artifacts/packageArtifact/sha256"
  ));
  assert.ok(
    Buffer.byteLength(JSON.stringify(sidecarComparison), "utf8")
      <= PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS.maxSerializedBytes
  );
  assert.equal(comparePackageReplaySidecars(beforeSidecar, beforeSidecar).changed, false);
  const malformedSidecar = structuredClone(beforeSidecar);
  malformedSidecar.package.unexpected = true;
  assert.throws(
    () => comparePackageReplaySidecars(beforeSidecar, malformedSidecar),
    /exactly the supported fields/u
  );
  const inconsistentSidecar = structuredClone(beforeSidecar);
  inconsistentSidecar.package.bytes += 1;
  assert.throws(
    () => comparePackageReplaySidecars(inconsistentSidecar, inconsistentSidecar),
    /package byte identity must match its nested receipt/u
  );
  assert.throws(
    () => verifyPackageReplaySidecarBytes(inconsistentSidecar, Uint8Array.from([1, 2, 3])),
    /package byte identity must match its nested receipt/u
  );
});

test("tagged text preserves scalar text and raw UTF-16 code units", () => {
  const scalar = materializeTaggedArguments({ text: { $text: { kind: "unicode_scalar_string", value: "é" } } });
  assert.equal(scalar.text, "é");
  const malformed = materializeTaggedArguments({ text: { $text: { kind: "utf16_code_units", units: [0xd800] } } });
  assert.equal(malformed.text.length, 1);
  assert.equal(malformed.text.isWellFormed(), false);
  assert.throws(
    () => materializeTaggedArguments({ text: { $text: { kind: "unicode_scalar_string", value: "\ud800" } } }),
    /well-formed Unicode scalar string/u
  );
});

test("one explicit tagged request produces a bounded replayable measurement record", () => {
  const request = {
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "e\u0301" } },
      form: "NFC"
    }
  };
  const first = createMeasurementRecord(request);
  const second = createMeasurementRecord(request);
  assert.deepEqual(second, first);
  assert.equal(first.schemaVersion, "text-integrity.measurement-record/2");
  assert.equal(first.authority, "operation_measurement_observation");
  assert.equal(first.scope, "one_explicit_tagged_request");
  assert.equal(first.selfCertifying, false);
  assert.equal(first.complete, true);
  assert.deepEqual(first.contracts, {
    taggedRequest: "text-integrity.tagged-request/1",
    publicResult: "text-integrity.public-result-contract/2",
    semanticProjection: "text-integrity.semantic-projection/1",
    environmentProjection: "text-integrity.environment-projection/1"
  });
  assert.deepEqual(first.operationProfile, {
    id: "text-integrity.operation.normalize/1",
    revision: 1,
    reproducibilityTarget: "cross_runtime_exact"
  });
  assert.deepEqual(first.request, request);
  assert.equal(first.result.normalized, "é");
  assert.equal(first.requestSha256, canonicalDigest(request));
  assert.equal(first.semanticSha256, canonicalDigest(semanticProjection(first.result)));
  assert.equal(first.environmentSha256, canonicalDigest(environmentProjection(first.result)));
  assert.equal(first.completeResultSha256, canonicalDigest(first.result));
  assert.deepEqual(first.environment, environmentProjection(first.result));
  assert.equal(first.data.unicodeVersion, "17.0.0");
  assert.equal(first.nonClaims.some((claim) => claim.includes("not anonymization")), true);
  assert.equal(
    Buffer.byteLength(JSON.stringify(first), "utf8") <= MEASUREMENT_RECORD_LIMITS.maxSerializedBytes,
    true
  );

  const rawUtf16 = createMeasurementRecord({
    operation: "inspect",
    arguments: {
      text: { $text: { kind: "utf16_code_units", units: [0xd800] } },
      detailLimit: 1
    }
  });
  assert.equal(rawUtf16.result.inputWellFormed, false);
  assert.equal(rawUtf16.result.detail.codePoints[0].character.isWellFormed(), false);
  assert.equal(validateMeasurementRecord(rawUtf16), rawUtf16);
  const receivedRawUtf16 = JSON.parse(JSON.stringify(rawUtf16));
  assert.equal(validateMeasurementRecord(receivedRawUtf16), receivedRawUtf16);
  assert.equal(replayMeasurementRecord(receivedRawUtf16).changeKind, "exact_match");

  const namespaceBase = {
    operation: "namespace_integrity",
    arguments: {
      items: [
        { id: "one", text: { $text: { kind: "unicode_scalar_string", value: "A" } }, scope: "s" },
        { id: "two", text: { $text: { kind: "unicode_scalar_string", value: "a" } }, scope: "s" }
      ],
      relations: ["nfc"]
    }
  };
  assert.equal(
    createMeasurementRecord(namespaceBase).operationProfile.reproducibilityTarget,
    "cross_runtime_exact"
  );
  const declaredCollation = structuredClone(namespaceBase);
  declaredCollation.arguments.relations = [{
    kind: "declared_collation",
    locale: "en",
    options: {
      usage: "sort", sensitivity: "base", ignorePunctuation: false, numeric: false,
      caseFirst: "false", localeMatcher: "best fit", collation: "default"
    }
  }];
  assert.equal(
    createMeasurementRecord(declaredCollation).operationProfile.reproducibilityTarget,
    "environment_bound"
  );

  assert.throws(
    () => createMeasurementRecord({ ...request, invented: true }),
    /unknown fields/u
  );
  assert.throws(
    () => createMeasurementRecord({ operation: "translate", arguments: {} }),
    /not supported/u
  );
  assert.throws(
    () => createMeasurementRecord({ operation: "normalize", arguments: null }),
    /request.arguments must be an object/u
  );
  assert.throws(
    () => createMeasurementRecord({
      operation: "normalize",
      arguments: {
        text: { $text: { kind: "not_a_text_tag", value: "a" } },
        form: "NFC"
      }
    }),
    /kind is not supported/u
  );
});

test("deterministic public errors produce validated replayable measurement records", () => {
  const options = {
    usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
    caseFirst: "false", localeMatcher: "best fit", collation: "default"
  };
  const cases = [
    ["INVALID_INPUT", {
      operation: "inspect",
      arguments: {
        text: { $text: { kind: "unicode_scalar_string", value: "error-secret-6817" } },
        unexpected: true
      }
    }],
    ["INVALID_UNICODE", {
      operation: "normalize",
      arguments: {
        text: { $text: { kind: "utf16_code_units", units: [0xd800] } },
        form: "NFC"
      }
    }],
    ["INVALID_LOCALE", {
      operation: "compare",
      arguments: {
        left: { $text: { kind: "unicode_scalar_string", value: "a" } },
        right: { $text: { kind: "unicode_scalar_string", value: "b" } },
        locale: "not_a_locale",
        options
      }
    }],
    ["DECODE_FAILED", {
      operation: "transcode",
      arguments: {
        sourceKind: "bytes", bytes: [0x61, 0xc3, 0x28], sourceEncoding: "utf-8",
        targetEncoding: "utf-8", allowLossy: false, byteRepresentation: "bytes"
      }
    }],
    ["INVALID_INPUT", {
      operation: "security",
      arguments: {
        source: { $text: { kind: "unicode_scalar_string", value: "let a" } },
        mode: "source",
        spans: [{ kind: "identifier", startUtf16: 4, endUtf16: 9, scope: "file" }],
        confusableDirection: "LTR",
        detailLimit: 1
      }
    }],
    ["INVALID_UNICODE", {
      operation: "explain_difference",
      arguments: {
        left: { $text: { kind: "utf16_code_units", units: [0xd800] } },
        right: { $text: { kind: "unicode_scalar_string", value: "a" } },
        locale: "en",
        options,
        confusableDirection: "LTR",
        detailLimit: 0
      }
    }],
    ["CHUNK_GRAPHEME_TOO_LARGE", {
      operation: "index",
      arguments: {
        text: { $text: { kind: "unicode_scalar_string", value: "👨‍👩‍👧‍👦" } },
        maxChunkUtf8Bytes: 24
      }
    }],
    ["PROTOCOL_STRING_INVALID", {
      operation: "protocol_profile",
      arguments: {
        profile: "precis_username_case_mapped",
        action: "enforce",
        text: { $text: { kind: "unicode_scalar_string", value: "a b" } }
      }
    }],
    ["DUPLICATE_ITEM_ID", {
      operation: "namespace_integrity",
      arguments: {
        items: [
          { id: "same", text: "a", scope: "x" },
          { id: "same", text: "b", scope: "x" }
        ],
        relations: ["exact"]
      }
    }]
  ];

  for (const [expectedCode, request] of cases) {
    const record = createMeasurementRecord(request);
    assert.equal(record.schemaVersion, "text-integrity.measurement-record/2");
    assert.equal(record.result.status, "error");
    assert.equal(record.result.error.code, expectedCode);
    assert.equal(validateMeasurementRecord(record), record);
    assert.equal(replayMeasurementRecord(record).changeKind, "exact_match");
    assert.equal(compareMeasurementRecords(record, structuredClone(record)).changed, false);
  }

  const secretRecord = createMeasurementRecord(cases[0][1]);
  assert.equal(JSON.stringify(secretRecord).includes("error-secret-6817"), true);
  assert.equal(JSON.stringify(replayMeasurementRecord(secretRecord)).includes("error-secret-6817"), false);
  assert.equal(
    JSON.stringify(compareMeasurementRecords(secretRecord, secretRecord)).includes("error-secret-6817"),
    false
  );

  const oversizedResult = createMeasurementRecord({
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "a".repeat(4096) } },
      form: "NFC",
      witnessMode: "full_required"
    }
  });
  assert.equal(oversizedResult.result.error.code, "RESULT_TOO_LARGE");
  assert.deepEqual(oversizedResult.environment, environmentProjection(oversizedResult.result));
  assert.equal(Object.hasOwn(semanticProjection(oversizedResult.result).error.details, "actualBytes"), false);
  assert.equal(replayMeasurementRecord(oversizedResult).changeKind, "exact_match");
});

function recomputeMeasurementResultIdentities(record) {
  record.semanticSha256 = canonicalDigest(semanticProjection(record.result));
  record.environment = environmentProjection(record.result);
  record.environmentSha256 = canonicalDigest(record.environment);
  record.completeResultSha256 = canonicalDigest(record.result);
  return record;
}

test("measurement records compare offline without copying request or result text", () => {
  const request = {
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "comparison-secret-8731" } },
      form: "NFC"
    }
  };
  const before = createMeasurementRecord(request);
  const beforeSnapshot = structuredClone(before);
  const exact = compareMeasurementRecords(before, structuredClone(before));
  assert.deepEqual(before, beforeSnapshot);
  assert.equal(exact.schemaVersion, "text-integrity.measurement-comparison/1");
  assert.equal(exact.authority, "measurement_identity_comparison_observation");
  assert.equal(exact.scope, "two_supported_measurement_records");
  assert.equal(exact.selfCertifying, false);
  assert.equal(exact.complete, true);
  assert.equal(exact.changed, false);
  assert.equal(exact.semanticComparisonApplicable, true);
  assert.deepEqual(exact.matches, {
    productIdentity: true,
    dataIdentity: true,
    requestIdentity: true,
    semanticResult: true,
    environmentIdentity: true,
    completeResult: true
  });
  assert.deepEqual(exact.differences, []);
  assert.equal(exact.differenceCount, 0);
  assert.deepEqual(exact.crossRuntimeExpectation, { required: true, met: true });
  assert.equal(exact.before.recordSha256, canonicalDigest(before));
  assert.equal(Object.hasOwn(exact.before, "request"), false);
  assert.equal(Object.hasOwn(exact.before, "result"), false);
  assert.equal(JSON.stringify(exact).includes("comparison-secret-8731"), false);
  assert.equal(
    Buffer.byteLength(JSON.stringify(exact), "utf8")
      <= MEASUREMENT_COMPARISON_LIMITS.maxSerializedBytes,
    true
  );

  const productChanged = structuredClone(before);
  productChanged.product.version = "1.0.1";
  const productComparison = compareMeasurementRecords(before, productChanged);
  assert.deepEqual(productComparison.differences, ["product_identity_changed"]);
  assert.deepEqual(productComparison.crossRuntimeExpectation, { required: true, met: true });

  const dataChanged = structuredClone(before);
  dataChanged.data.compactDataSha256 = "0".repeat(64);
  const dataComparison = compareMeasurementRecords(before, dataChanged);
  assert.deepEqual(dataComparison.differences, ["data_identity_changed"]);
  assert.deepEqual(dataComparison.crossRuntimeExpectation, { required: true, met: false });

  const semanticChanged = structuredClone(before);
  semanticChanged.result.normalized = "changed-but-schema-valid";
  semanticChanged.result.changed = true;
  recomputeMeasurementResultIdentities(semanticChanged);
  const semanticComparison = compareMeasurementRecords(before, semanticChanged);
  assert.deepEqual(semanticComparison.differences, [
    "semantic_result_identity_changed",
    "complete_result_identity_changed"
  ]);
  assert.deepEqual(semanticComparison.crossRuntimeExpectation, { required: true, met: false });

  const environmentChanged = structuredClone(before);
  environmentChanged.result.runtime.node = "different-runtime";
  recomputeMeasurementResultIdentities(environmentChanged);
  const environmentComparison = compareMeasurementRecords(before, environmentChanged);
  assert.deepEqual(environmentComparison.differences, [
    "environment_identity_changed",
    "complete_result_identity_changed"
  ]);
  assert.deepEqual(environmentComparison.crossRuntimeExpectation, { required: true, met: true });

  const otherRequest = createMeasurementRecord({
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "different-request" } },
      form: "NFC"
    }
  });
  const requestComparison = compareMeasurementRecords(before, otherRequest);
  assert.equal(requestComparison.semanticComparisonApplicable, false);
  assert.equal(requestComparison.matches.requestIdentity, false);
  assert.deepEqual(requestComparison.crossRuntimeExpectation, { required: false, met: null });

  const environmentBound = createMeasurementRecord({
    operation: "compare",
    arguments: {
      left: { $text: { kind: "unicode_scalar_string", value: "a" } },
      right: { $text: { kind: "unicode_scalar_string", value: "A" } },
      locale: "en",
      options: {
        usage: "sort", sensitivity: "base", ignorePunctuation: false, numeric: false,
        caseFirst: "false", localeMatcher: "best fit", collation: "default"
      }
    }
  });
  assert.deepEqual(
    compareMeasurementRecords(environmentBound, structuredClone(environmentBound))
      .crossRuntimeExpectation,
    { required: false, met: null }
  );

  const invalid = structuredClone(before);
  invalid.semanticSha256 = "0".repeat(64);
  assert.throws(() => compareMeasurementRecords(invalid, before), /semanticSha256/u);
});

test("measurement replay reports bounded digest-only current-runtime drift observations", () => {
  const request = {
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "replay-secret-4729" } },
      form: "NFC"
    }
  };
  const record = createMeasurementRecord(request);
  const beforeValidation = structuredClone(record);
  assert.equal(validateMeasurementRecord(record), record);
  assert.deepEqual(record, beforeValidation);

  const first = replayMeasurementRecord(record);
  const second = replayMeasurementRecord(record);
  assert.deepEqual(second, first);
  assert.equal(first.schemaVersion, "text-integrity.measurement-replay/1");
  assert.equal(first.authority, "current_runtime_replay_observation");
  assert.equal(first.scope, "one_supported_measurement_record");
  assert.equal(first.selfCertifying, false);
  assert.equal(first.complete, true);
  assert.equal(first.reproducibilityTarget, "cross_runtime_exact");
  assert.deepEqual(first.matches, {
    productIdentity: true,
    dataIdentity: true,
    requestIdentity: true,
    semanticResult: true,
    environmentIdentity: true,
    completeResult: true
  });
  assert.equal(first.changeKind, "exact_match");
  assert.deepEqual(first.crossRuntimeExpectation, { required: true, met: true });
  assert.equal(first.recorded.recordSha256, canonicalDigest(record));
  assert.equal(first.current.measurementSha256, canonicalDigest(record));
  assert.equal(Object.hasOwn(first, "request"), false);
  assert.equal(Object.hasOwn(first, "result"), false);
  assert.equal(JSON.stringify(first).includes("replay-secret-4729"), false);
  assert.equal(first.nonClaims.some((claim) => claim.includes("not an authority")), true);
  assert.equal(first.nonClaims.some((claim) => claim.includes("cause")), true);
  assert.equal(first.nonClaims.some((claim) => claim.includes("release readiness")), true);
  assert.equal(
    Buffer.byteLength(JSON.stringify(first), "utf8")
      <= MEASUREMENT_REPLAY_LIMITS.maxSerializedBytes,
    true
  );

  const environmentBound = createMeasurementRecord({
    operation: "compare",
    arguments: {
      left: { $text: { kind: "unicode_scalar_string", value: "a" } },
      right: { $text: { kind: "unicode_scalar_string", value: "A" } },
      locale: "en",
      options: {
        usage: "sort", sensitivity: "base", ignorePunctuation: false, numeric: false,
        caseFirst: "false", localeMatcher: "best fit", collation: "default"
      }
    }
  });
  assert.deepEqual(replayMeasurementRecord(environmentBound).crossRuntimeExpectation, {
    required: false,
    met: null
  });

  const environmentChanged = structuredClone(record);
  environmentChanged.result.runtime.node = "different-runtime";
  recomputeMeasurementResultIdentities(environmentChanged);
  const environmentReplay = replayMeasurementRecord(environmentChanged);
  assert.equal(environmentReplay.changeKind, "environment_metadata_changed");
  assert.equal(environmentReplay.matches.semanticResult, true);
  assert.equal(environmentReplay.matches.environmentIdentity, false);
  assert.equal(environmentReplay.matches.completeResult, false);

  const semanticChanged = structuredClone(record);
  semanticChanged.result.normalized = "changed-but-schema-valid";
  semanticChanged.result.changed = true;
  recomputeMeasurementResultIdentities(semanticChanged);
  const semanticReplay = replayMeasurementRecord(semanticChanged);
  assert.equal(semanticReplay.changeKind, "semantic_changed");
  assert.equal(semanticReplay.matches.semanticResult, false);
  assert.equal(semanticReplay.matches.environmentIdentity, true);

  const dataChanged = structuredClone(record);
  dataChanged.data.compactDataSha256 = "0".repeat(64);
  const dataReplay = replayMeasurementRecord(dataChanged);
  assert.equal(dataReplay.changeKind, "data_identity_changed");
  assert.equal(dataReplay.matches.dataIdentity, false);
  assert.equal(dataReplay.matches.semanticResult, true);

  const productChanged = structuredClone(record);
  productChanged.product.version = "0.9.0";
  const productReplay = replayMeasurementRecord(productChanged);
  assert.equal(productReplay.changeKind, "product_identity_changed");
  assert.equal(productReplay.matches.productIdentity, false);
});

test("measurement record parsing bounds raw UTF-8 JSON before allocation loses wire size", () => {
  const record = createMeasurementRecord({
    operation: "inspect",
    arguments: {
      text: { $text: { kind: "utf16_code_units", units: [0xd800] } },
      detailLimit: 1
    }
  });
  const compact = JSON.stringify(record);
  assert.deepEqual(parseMeasurementRecord(compact), JSON.parse(compact));
  assert.deepEqual(parseMeasurementRecord(Buffer.from(compact, "utf8")), JSON.parse(compact));
  assert.deepEqual(
    parseMeasurementRecord(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(compact)])),
    JSON.parse(compact)
  );
  assert.equal(parseMeasurementRecord(compact).result.inputWellFormed, false);

  const compactBytes = Buffer.byteLength(compact, "utf8");
  const maximumPadded = `${" ".repeat(
    MEASUREMENT_RECORD_LIMITS.maxInputBytes - compactBytes
  )}${compact}`;
  assert.equal(Buffer.byteLength(maximumPadded, "utf8"), MEASUREMENT_RECORD_LIMITS.maxInputBytes);
  assert.deepEqual(parseMeasurementRecord(maximumPadded), JSON.parse(compact));
  assert.throws(
    () => parseMeasurementRecord(` ${maximumPadded}`),
    /input exceeds/u
  );
  assert.throws(
    () => parseMeasurementRecord("é".repeat((MEASUREMENT_RECORD_LIMITS.maxInputBytes / 2) + 1)),
    /input exceeds/u
  );

  assert.throws(() => parseMeasurementRecord(Uint8Array.from([0xc3, 0x28])), /well-formed UTF-8/u);
  assert.throws(() => parseMeasurementRecord("{"), /valid JSON/u);
  const duplicateTopLevel = compact.replace(
    '"schemaVersion":',
    '"schemaVersion":"ignored","\\u0073chemaVersion":'
  );
  assert.equal(validateMeasurementRecord(JSON.parse(duplicateTopLevel)).schemaVersion, record.schemaVersion);
  assert.throws(() => parseMeasurementRecord(duplicateTopLevel), /duplicate object keys/u);
  const duplicateNested = compact.replace(
    '"detailLimit":1',
    '"detailLimit":2,"detail\\u004cimit":1'
  );
  assert.equal(validateMeasurementRecord(JSON.parse(duplicateNested)).request.arguments.detailLimit, 1);
  assert.throws(() => parseMeasurementRecord(duplicateNested), /duplicate object keys/u);
  const tooDeepJson = `${"[".repeat(MEASUREMENT_RECORD_LIMITS.maxJsonDepth + 2)}0${"]".repeat(
    MEASUREMENT_RECORD_LIMITS.maxJsonDepth + 2
  )}`;
  assert.throws(() => parseMeasurementRecord(tooDeepJson), /exceeds depth/u);
  assert.throws(() => parseMeasurementRecord(record), /explicit string or Uint8Array/u);
  assert.throws(
    () => parseMeasurementRecord(new Proxy(Uint8Array.from(Buffer.from(compact)), {})),
    /explicit string or Uint8Array/u
  );
  const accessorBytes = Uint8Array.from(Buffer.from(compact));
  Object.defineProperty(accessorBytes, "byteLength", {
    configurable: true,
    get: () => { throw new Error("own byteLength accessor must not execute"); }
  });
  Object.defineProperty(accessorBytes, Symbol.iterator, {
    configurable: true,
    value: () => { throw new Error("own iterator must not execute"); }
  });
  assert.deepEqual(parseMeasurementRecord(accessorBytes), JSON.parse(compact));
});

test("measurement validation rejects malformed or self-inconsistent untrusted records", () => {
  const record = createMeasurementRecord({
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "e\u0301" } },
      form: "NFC"
    }
  });

  const sharedText = { $text: { kind: "unicode_scalar_string", value: "same" } };
  const aliasedRecord = createMeasurementRecord({
    operation: "compare",
    arguments: {
      left: sharedText,
      right: sharedText,
      locale: "en",
      options: {
        usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
        caseFirst: "false", localeMatcher: "best fit", collation: "default"
      }
    }
  });
  assert.equal(validateMeasurementRecord(aliasedRecord), aliasedRecord);

  const tamperedDigest = structuredClone(record);
  tamperedDigest.semanticSha256 = "0".repeat(64);
  assert.throws(() => validateMeasurementRecord(tamperedDigest), /semanticSha256/u);

  const strippedNonClaim = structuredClone(record);
  strippedNonClaim.nonClaims.pop();
  assert.throws(() => validateMeasurementRecord(strippedNonClaim), /non-claim set/u);

  const unknownTopLevel = structuredClone(record);
  unknownTopLevel.invented = true;
  assert.throws(() => validateMeasurementRecord(unknownTopLevel), /unknown fields/u);

  const unsupportedSchema = structuredClone(record);
  unsupportedSchema.schemaVersion = "text-integrity.measurement-record/99";
  assert.throws(() => validateMeasurementRecord(unsupportedSchema), /contract constants/u);

  const malformedResult = structuredClone(record);
  malformedResult.result.invented = true;
  recomputeMeasurementResultIdentities(malformedResult);
  const normalizeSchema = OUTPUT_SCHEMAS.normalize.oneOf.find(
    (branch) => branch?.properties?.operation?.const === "normalize"
  );
  assert.throws(() => {
    normalizeSchema.additionalProperties = true;
  }, TypeError);
  assert.throws(() => validateMeasurementRecord(malformedResult), /public result schema/u);

  const malformedErrorResult = structuredClone(record);
  malformedErrorResult.result = {
    status: "error",
    error: { code: "NOT_A_PUBLIC_ERROR", message: "synthetic error result" }
  };
  recomputeMeasurementResultIdentities(malformedErrorResult);
  assert.throws(() => validateMeasurementRecord(malformedErrorResult), /public result schema/u);

  const cyclic = structuredClone(record);
  cyclic.invented = cyclic;
  assert.throws(() => validateMeasurementRecord(cyclic), /acyclic JSON/u);

  const customPrototype = structuredClone(record);
  Object.setPrototypeOf(customPrototype.request.arguments, { custom: true });
  assert.throws(() => validateMeasurementRecord(customPrototype), /standard Object prototype/u);

  assert.throws(() => validateMeasurementRecord(new Proxy(record, {})), /must not be a Proxy/u);

  const accessor = structuredClone(record);
  Object.defineProperty(accessor, "invented", { enumerable: true, get: () => true });
  assert.throws(() => validateMeasurementRecord(accessor), /enumerable data value/u);

  const tooDeep = structuredClone(record);
  let cursor = tooDeep;
  for (let depth = 0; depth < MEASUREMENT_RECORD_LIMITS.maxJsonDepth + 2; depth += 1) {
    cursor.invented = {};
    cursor = cursor.invented;
  }
  assert.throws(() => validateMeasurementRecord(tooDeep), /JSON depth/u);

  const tooLong = structuredClone(record);
  tooLong.invented = "x".repeat(MEASUREMENT_RECORD_LIMITS.maxStringCodeUnits + 1);
  assert.throws(() => validateMeasurementRecord(tooLong), /string code-unit limit/u);

  const tooManyArrayItems = structuredClone(record);
  tooManyArrayItems.invented = Array(MEASUREMENT_RECORD_LIMITS.maxArrayItems + 1).fill(null);
  assert.throws(() => validateMeasurementRecord(tooManyArrayItems), /array-item limit/u);
});

test("behavior cases reuse the single-request measurement identities", () => {
  const request = {
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "e\u0301" } },
      form: "NFC"
    }
  };
  const measurement = createMeasurementRecord(request);
  const manifest = createBehaviorManifest({
    schemaVersion: BEHAVIOR_CORPUS_SCHEMA_VERSION,
    cases: [{ id: "same-request", ...request }]
  });
  const [behaviorCase] = manifest.cases;
  assert.equal(behaviorCase.requestSha256, measurement.requestSha256);
  assert.equal(behaviorCase.semanticSha256, measurement.semanticSha256);
  assert.equal(behaviorCase.environmentSha256, measurement.environmentSha256);
  assert.equal(behaviorCase.resultSha256, measurement.completeResultSha256);
});

test("the committed manifest replays from the canonical corpus", () => {
  assert.equal(corpus.schemaVersion, BEHAVIOR_CORPUS_SCHEMA_VERSION);
  const generated = createBehaviorManifest(corpus);
  assert.equal(generated.schemaVersion, BEHAVIOR_MANIFEST_SCHEMA_VERSION);
  assert.equal(
    generated.contracts.measurementComparison,
    "text-integrity.measurement-comparison/1"
  );
  assert.equal(
    generated.contracts.measurementRecord,
    "text-integrity.measurement-record/2"
  );
  if (canonicalDigest(generated.environment) === canonicalDigest(committedManifest.environment)) {
    assert.deepEqual(generated, committedManifest);
  } else {
    const comparison = compareBehaviorManifests(committedManifest, generated);
    assert.deepEqual(generated.corpus, committedManifest.corpus);
    assert.deepEqual(generated.product, committedManifest.product);
    assert.equal(comparison.dataIdentityChanged, false);
    assert.equal(comparison.engineChanges.uts46Changed, false);
    assert.equal(comparison.verificationMetadataChanged, false);
    for (const change of comparison.changes) {
      assert.ok(["semantic_changed", "environment_metadata_changed"].includes(change.kind));
      if (change.kind === "semantic_changed") {
        const item = generated.cases.find(({ id }) => id === change.id);
        assert.equal(item.reproducibilityTarget, "environment_bound", change.id);
      }
    }
  }
  assert.equal(generated.corpus.caseCount, corpus.cases.length);
  assert.deepEqual(generated.data, {
    unicodeVersion: "17.0.0",
    uts39Revision: 32,
    sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
    compactFormatVersion: 4,
    compactManifestSha256: "3c8a54c3d74be6b11ac6458c882d86d0564da031640f90b6a6354fef0dd001c0",
    compactDataSha256: "7419b6b6af6f8184dc13c48a5ce5b10c20edd80f977d6769bc71214a9c06b564"
  });
  assert.deepEqual(generated.engines.uts46, {
    specification: "UTS #46 revision 35",
    unicodeVersion: "17.0.0",
    package: "tr46",
    version: "6.0.0",
    packageIntegrity: "sha512-bLVMLPtstlZ4iMQHpFHTR7GAGj2jxi8Dg0s2h2MafAE4uSWF98FC/3MomU51iQAMf8/qDUbKWf5GxuvvVcXEhw==",
    runtimeTreeSha256: "a4b97c0735cda47715ec66318e2f8aba66db3427fec8aa8069f87257622fdfc4",
    dependency: {
      name: "punycode",
      version: "2.3.1",
      packageIntegrity: "sha512-vYt7UD1U9Wg6138shLtLOvdAu+8DsC/ilFtEVHcH+wydcSpNE20AfSOduf6MkRFahL5FY7X1oU7nKVZFtfq8Fg=="
    },
    conformance: {
      corpus: "Unicode 17.0.0 IdnaTestV2.txt",
      compressedSha256: "9f8a1da3fee709da51a9bb80667db9b1f92df22f4577f8174ac9f1b4fec155c8",
      uncompressedSha256: "beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf",
      wellFormedCaseCount: 6389,
      rerunCommand: "npm run check"
    }
  });
  assert.deepEqual(generated.engines.collation, createCollationCalibration());
  assert.ok(Object.values(generated.operations).every((entry) => entry.caseCount > 0));
  assert.ok(generated.cases.some((entry) => entry.id === "inspect-unpaired-high-surrogate"));
  const canonicalErrors = corpus.cases.filter(({ id }) => id.includes("-error-"));
  assert.equal(canonicalErrors.length, 10);
  for (const entry of canonicalErrors) {
    const record = createMeasurementRecord({
      operation: entry.operation,
      arguments: entry.arguments
    });
    const behaviorCase = generated.cases.find(({ id }) => id === entry.id);
    assert.equal(record.result.status, "error", entry.id);
    assert.equal(behaviorCase.requestSha256, record.requestSha256, entry.id);
    assert.equal(behaviorCase.semanticSha256, record.semanticSha256, entry.id);
    assert.equal(behaviorCase.environmentSha256, record.environmentSha256, entry.id);
    assert.equal(behaviorCase.resultSha256, record.completeResultSha256, entry.id);
  }
  for (const [operation, counts] of Object.entries({
    index: {
      canonicalCaseCount: 2, additionalComparisonCaseCount: 984, totalCaseCount: 986,
      negativeRequestShapeCaseCount: 18,
      packagedReferenceWasmNegativeRequestShapeCaseCount: 18
    },
    inspect: {
      canonicalCaseCount: 3, additionalComparisonCaseCount: 1299, totalCaseCount: 1302,
      negativeRequestShapeCaseCount: 11,
      packagedReferenceWasmNegativeRequestShapeCaseCount: 11
    },
    normalize: {
      canonicalCaseCount: 5, additionalComparisonCaseCount: 80248, totalCaseCount: 80253,
      negativeRequestShapeCaseCount: 16,
      packagedReferenceWasmNegativeRequestShapeCaseCount: 16
    },
    transcode: {
      canonicalCaseCount: 4, additionalComparisonCaseCount: 1587, totalCaseCount: 1591,
      negativeRequestShapeCaseCount: 45,
      packagedReferenceWasmNegativeRequestShapeCaseCount: 45
    }
  })) {
    assert.equal(generated.operations[operation].verificationStatus, "native_wasm_parity");
    assert.deepEqual(generated.operations[operation].independentVerification, {
      command: "npm run check:independent",
      implementations: ["node", "rust_native", "rust_wasm32_unknown_unknown"],
      ...counts
    });
  }
  assert.equal(generated.operations.namespace_integrity.verificationStatus, "scoped_native_wasm_parity");
  assert.deepEqual(generated.operations.namespace_integrity.independentVerification, {
    command: "npm run check:independent",
    implementations: [
      "node_composed_unicode17_core_with_runtime_icu_collation_excluded",
      "rust_generated_unicode17_and_configurable_uts46_native",
      "rust_generated_unicode17_and_configurable_uts46_wasm32_unknown_unknown"
    ],
    canonicalCaseCount: 2,
    additionalComparisonCaseCount: 239,
    totalCaseCount: 241,
    dataAuthority: "locked_independent_uts46_engines_and_same_pinned_unicode_source_for_other_relations",
    projectionExcludedFields: ["runtime"],
    scope: {
      includedRelations: [
        "exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable",
        "protocol:uts46_domain", "protocol:precis_username_case_mapped",
        "protocol:precis_username_case_preserved", "protocol:precis_opaque_string"
      ],
      excludedRelations: ["declared_collation"],
      completeConsumerParity: false,
      deterministicUtf16Ordering: true,
      requestShapeValidationIncluded: true,
      completeResultBudgetEnforcementImplemented: true,
      runtimeDependentBudgetDiagnosticsExcluded: true
    },
    simpleDirectionCaseCount: 3,
    utf16OrderingCaseCount: 1,
    uts46ConfigurationCaseCount: 192,
    precisProfileCaseCount: 3,
    composedProtocolRelationCaseCount: 1,
    negativeCaseCount: 39
  });
  assert.equal(generated.operations.protocol_profile.verificationStatus, "native_wasm_parity");
  assert.deepEqual(generated.operations.protocol_profile.independentVerification, {
    command: "npm run check:independent",
    implementations: [
      "node_tr46_6_0_0_and_unicode17_precis_core",
      "rust_idna_adapter_1_2_1_configurable_uts46_and_generated_unicode17_precis_native",
      "rust_idna_adapter_1_2_1_configurable_uts46_and_generated_unicode17_precis_wasm32_unknown_unknown"
    ],
    canonicalCaseCount: 5,
    additionalComparisonCaseCount: 68149,
    totalCaseCount: 68154,
    officialInputCaseCount: 6389,
    officialOperationCaseCount: 19167,
    dataAuthority: "locked_independent_uts46_engines_and_same_pinned_unicode_source_for_precis",
    projectionExcludedFields: ["standards.engine", "witness.engine"],
    scope: {
      uts46: {
        profile: "uts46_domain",
        actions: ["to_ascii", "to_unicode"],
        witnessModes: ["none", "summary", "full_required"],
        implementationScope: "complete_option_space",
        requestShapeValidationIncluded: true
      },
      precis: {
        profiles: [
          "precis_username_case_mapped",
          "precis_username_case_preserved",
          "precis_opaque_string"
        ],
        actions: ["enforce", "compare"],
        witnessModes: ["none", "summary", "full_required"],
        implementationScope: "complete_profile_execution",
        requestShapeValidationIncluded: true
      }
    },
    uts46Options: {
      probeCount: 19,
      toAsciiOptionCombinationCount: 128,
      toUnicodeOptionCombinationCount: 64,
      allLegalOptionCombinationsIncluded: true,
      totalCaseCount: 3648
    },
    requestShape: {
      sharedCaseCount: 4,
      uts46CaseCount: 26,
      precisCaseCount: 14,
      totalCaseCount: 44
    },
    precis: {
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      sourceFiles: {
        derivedCore: { path: "ucd/DerivedCoreProperties.txt", sha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08" },
        propList: { path: "ucd/PropList.txt", sha256: "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd" },
        generalCategory: { path: "ucd/extracted/DerivedGeneralCategory.txt", sha256: "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e" },
        unicodeData: { path: "ucd/UnicodeData.txt", sha256: "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c" },
        specialCasing: { path: "ucd/SpecialCasing.txt", sha256: "efc25faf19de21b92c1194c111c932e03d2a5eaf18194e33f1156e96de4c9588" },
        joiningType: { path: "ucd/extracted/DerivedJoiningType.txt", sha256: "f39ebe974825d6736aee15582250307aa532b2cfab3caf3f86bd23fddc9c5c4d" },
        hangulSyllableType: { path: "ucd/HangulSyllableType.txt", sha256: "5a57450afde0d082bc5026f7458649eac3b615490cc7e3d916b0367f1593c0e3" },
        scripts: { path: "ucd/Scripts.txt", sha256: "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf" },
        scriptExtensions: { path: "ucd/ScriptExtensions.txt", sha256: "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6" },
        bidiClass: { path: "ucd/extracted/DerivedBidiClass.txt", sha256: "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4" }
      },
      propertyBoundaryCodePointCount: 7819,
      propertyBoundaryProfileCaseCount: 23457,
      widthMappingCaseCount: 226,
      lowercaseMappingCaseCount: 1488,
      normalizationConformanceSourceCaseCount: 20034,
      contextSequenceCaseCount: 48,
      bidiSequenceCaseCount: 18,
      composedSequenceCaseCount: 17,
      negativeEncodingCaseCount: 2,
      totalCaseCount: 45290
    }
  });
  assert.equal(generated.operations.security.verificationStatus, "native_wasm_parity");
  assert.deepEqual(generated.operations.security.independentVerification, {
    command: "npm run check:independent",
    implementations: [
      "node_compact_unicode17_bidi_js_1_0_3",
      "rust_generated_unicode17_unicode_bidi_0_3_18_native",
      "rust_generated_unicode17_unicode_bidi_0_3_18_wasm32_unknown_unknown"
    ],
    canonicalCaseCount: 4,
    additionalComparisonCaseCount: 39010,
    totalCaseCount: 39014,
    dataAuthority: "same_pinned_unicode_source",
    projectionExcludedFields: ["confusableComparison.engine"],
    scope: { modes: ["free_text", "identifier", "source"] },
    sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
    sourceFiles: {
      identifierStatus: { path: "security/IdentifierStatus.txt", sha256: "617228a16da13850bf8af28b6cd08f5e9b6595d2eb60404fe6eee2c85b4e4a35" },
      identifierType: { path: "security/IdentifierType.txt", sha256: "924ac63faa97ed73420d6ac48d08279d90968c7da0502ab701e08bfbb9683c22" },
      derivedCore: { path: "ucd/DerivedCoreProperties.txt", sha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08" },
      propList: { path: "ucd/PropList.txt", sha256: "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd" },
      generalCategory: { path: "ucd/extracted/DerivedGeneralCategory.txt", sha256: "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e" },
      unicodeData: { path: "ucd/UnicodeData.txt", sha256: "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c" },
      scripts: { path: "ucd/Scripts.txt", sha256: "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf" },
      scriptExtensions: { path: "ucd/ScriptExtensions.txt", sha256: "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6" },
      bidiClass: { path: "ucd/extracted/DerivedBidiClass.txt", sha256: "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4" },
      nfkcCasefold: { path: "ucd/DerivedNormalizationProps.txt", sha256: "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488" },
      confusables: { path: "security/confusables.txt", sha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a" }
    },
    propertyBoundaryCaseCount: 10034,
    freeTextBoundaryCaseCount: 58,
    xidProfileCaseCount: 5084,
    nfkcCasefoldProfileCaseCount: 10583,
    confusableEnvelopeCaseCount: 6565,
    sequenceCaseCount: 13,
    negativeCaseCount: 14,
    sourceDiagnostics: {
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      sourceFiles: {
        derivedCore: { path: "ucd/DerivedCoreProperties.txt", sha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08" },
        propList: { path: "ucd/PropList.txt", sha256: "130dcddcaadaf071008bdfce1e7743e04fdfbc910886f017d9f9ac931d8c64dd" },
        generalCategory: { path: "ucd/extracted/DerivedGeneralCategory.txt", sha256: "d62e5bab70ca74f099343f71224fa051cb1fdd61a1ab45c0488c44cfc0b6102e" },
        confusables: { path: "security/confusables.txt", sha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a" }
      },
      signalBoundaryCaseCount: 58,
      confusableEnvelopeCaseCount: 6565,
      sequenceCaseCount: 7,
      negativeCaseCount: 29,
      totalCaseCount: 6659
    }
  });
  assert.equal(generated.operations.explain_difference.verificationStatus, "scoped_native_wasm_parity");
  assert.deepEqual(generated.operations.explain_difference.independentVerification, {
    command: "npm run check:independent",
    implementations: [
      "node_composed_core_with_runtime_icu_projected_out",
      "rust_generated_unicode17_native",
      "rust_generated_unicode17_wasm32_unknown_unknown"
    ],
    canonicalCaseCount: 2,
    additionalComparisonCaseCount: 42966,
    totalCaseCount: 42968,
    dataAuthority: "same_pinned_unicode_source",
    projectionExcludedFields: [
      "collation",
      "runtime",
      "identifierConfusableComparison.engine"
    ],
    scope: {
      kind: "deterministic_spine",
      includedStages: [
        "exact_representation",
        "normalization",
      "nfkc_casefold",
      "coordinate_mapping",
      "alignment",
      "unicode_signals",
        "line_endings",
        "identifier_confusable"
      ],
      excludedStages: ["collation"],
      requiresValidNodeCollationRequest: true,
      completeConsumerParity: false
    },
    graphemeConformanceCaseCount: 766,
    normalizationConformanceCaseCount: 20034,
    nfkcCasefoldCaseCount: 11662,
    confusableComparisonCaseCount: 10433,
    signalBoundaryCaseCount: 58,
    composedSequenceCaseCount: 13
  });
  assert.deepEqual(generated.primitives.bidiSkeleton, {
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: ["explain_difference", "namespace_integrity", "security", "source_diagnostics"],
    verificationStatus: "scoped_native_wasm_parity",
    claimBoundary: "complete Unicode 17 bidiSkeleton value and paragraph levels only; X9-excluded engine diagnostics and consumer envelopes remain separately classified",
    independentVerification: {
      command: "npm run check:independent",
      implementations: [
        "node_bidi_js_1_0_3_generated_unicode17",
        "rust_unicode_bidi_0_3_18_generated_unicode17_native",
        "rust_unicode_bidi_0_3_18_generated_unicode17_wasm32_unknown_unknown"
      ],
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: [
        "engine",
        "standards.uba.algorithm",
        "standards.uba.hardcodedDataFeature",
        "standards.uba.dataSource",
        "resolvedLevels",
        "visualOrder",
        "entries",
        "reordered"
      ],
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      bidiClassSourcePath: "ucd/extracted/DerivedBidiClass.txt",
      bidiClassSourceSha256: "4867b4b7f0731ed1bfcd34cc6251211ff1542541fce0734b6fbda139ee80b3a4",
      scalarBoundaryCodePointCount: 3795,
      scalarBoundaryDirectionCaseCount: 11385,
      bidiBracketsSourcePath: "ucd/BidiBrackets.txt",
      bidiBracketsSourceSha256: "dadbaf38a0d0246e5b805bf8725cb81b7c621f93d030595635f5ba2c2f179428",
      bracketEntryCount: 128,
      bracketDirectionCaseCount: 384,
      bidiMirroringSourcePath: "ucd/BidiMirroring.txt",
      bidiMirroringSourceSha256: "a2f16fb873ab4fcdf3221cb1a8a85a134ddd6ed03603181823ff5206af3741ce",
      mirroringEntryCount: 428,
      unicodeDataSourcePath: "ucd/UnicodeData.txt",
      unicodeDataSourceSha256: "2e1efc1dcb59c575eedf5ccae60f95229f706ee6d031835247d843c11d96470c",
      combiningCodePointCount: 968,
      conformanceManifestSha256: "61c3f102afd997d929634ea5170e094a2d9808394113d6d749f8f448b1a5497d",
      bidiTestCompressedSha256: "b1e05b09dbd0a03dca1ed880f41c4002de38ef57adca88ac4052b8ef17a7249e",
      bidiTestParagraphModeCaseCount: 770241,
      bidiTestSampleCount: 2997,
      bidiCharacterTestCompressedSha256: "8b80599d288bad03ed420564ae0a6b7b92cc63027f55d51c6d55ad56ede85e54",
      bidiCharacterTestCaseCount: 91707,
      bidiCharacterTestSampleCount: 717,
      sequenceCaseCount: 42,
      totalCaseCount: 16921
    }
  });
  assert.deepEqual(generated.primitives.confusableComparison, {
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: ["explain_difference", "namespace_integrity", "security", "source_diagnostics"],
    verificationStatus: "native_wasm_parity",
    claimBoundary: "Unicode 17 resolved-script sets and complete UTS #39 confusable relation, class, paragraph levels, and skeleton digests only; consumer envelopes remain separately classified",
    independentVerification: {
      command: "npm run check:independent",
      implementations: [
        "node_compact_unicode17_bidi_js_1_0_3",
        "rust_generated_unicode17_unicode_bidi_0_3_18_native",
        "rust_generated_unicode17_unicode_bidi_0_3_18_wasm32_unknown_unknown"
      ],
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: ["engine"],
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      scriptsSourcePath: "ucd/Scripts.txt",
      scriptsSourceSha256: "9f5e50d3abaee7d6ce09480f325c706f485ae3240912527e651954d2d6b035bf",
      scriptExtensionsSourcePath: "ucd/ScriptExtensions.txt",
      scriptExtensionsSourceSha256: "ec2107e58825a1586acee8e0911ce18260394ac8b87e535ca325f1ccbeb06bc6",
      propertyValueAliasesSourcePath: "ucd/PropertyValueAliases.txt",
      propertyValueAliasesSourceSha256: "64e9a5f76f7a1e8b5a47d6a1f9a26522a251208f5276bdfa1559dac7cf2e827a",
      scriptBoundaryCaseCount: 3826,
      confusablesSourcePath: "security/confusables.txt",
      confusablesSourceSha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
      confusableMappingCaseCount: 6565,
      sequenceCaseCount: 42,
      totalCaseCount: 10433
    }
  });
  assert.deepEqual(generated.primitives.nfkcCasefold, {
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: ["explain_difference", "namespace_integrity", "security"],
    verificationStatus: "native_wasm_parity",
    claimBoundary: "NFKC_CF mapping followed by Unicode 17 NFC only; consumer operations remain separately classified",
    independentVerification: {
      command: "npm run check:independent",
      implementations: [
        "node_compact_unicode17",
        "rust_generated_unicode17_native",
        "rust_generated_unicode17_wasm32_unknown_unknown"
      ],
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: ["engine"],
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      sourceFilePath: "ucd/DerivedNormalizationProps.txt",
      sourceFileSha256: "71fd6a206a2c0cdd41feb6b7f656aa31091db45e9cedc926985d718397f9e488",
      mappingRowCount: 6183,
      mappedCodePointCaseCount: 10583,
      identityBoundaryCaseCount: 1063,
      sequenceCaseCount: 16,
      totalCaseCount: 11662
    }
  });
  assert.deepEqual(generated.primitives.uts39PostReorderSkeleton, {
    role: "shared_internal_semantic_primitive",
    publicOperation: false,
    consumers: ["explain_difference", "namespace_integrity", "security"],
    verificationStatus: "native_wasm_parity",
    claimBoundary: "post-reorder NFD, Default_Ignorable removal, confusable mapping, and final NFD only; UBA reordering and consumer operations remain separately classified",
    independentVerification: {
      command: "npm run check:independent",
      implementations: [
        "node_compact_unicode17_uts39_revision32",
        "rust_generated_unicode17_uts39_revision32_native",
        "rust_generated_unicode17_uts39_revision32_wasm32_unknown_unknown"
      ],
      dataAuthority: "same_pinned_unicode_source",
      projectionExcludedFields: ["engine"],
      sourceManifestSha256: "1e0677ee007d4b9d280c7d65209c13cc5c7ce09443fb05fa7b39cbc6652988cf",
      confusablesSourcePath: "security/confusables.txt",
      confusablesSourceSha256: "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a",
      derivedCoreSourcePath: "ucd/DerivedCoreProperties.txt",
      derivedCoreSourceSha256: "24c7fed1195c482faaefd5c1e7eb821c5ee1fb6de07ecdbaa64b56a99da22c08",
      confusableMappingRowCount: 6565,
      mappedSourceCaseCount: 6565,
      defaultIgnorableRangeCount: 27,
      defaultIgnorableCodePointCount: 4174,
      defaultIgnorableCaseCount: 4174,
      identityBoundaryCaseCount: 2607,
      sequenceCaseCount: 24,
      normalizationConformanceSourceCaseCount: 20034,
      totalCaseCount: 33404
    }
  });
  assert.ok(Object.entries(generated.operations)
    .filter(([operation]) => ![
      "explain_difference", "index", "inspect", "namespace_integrity", "normalize",
      "protocol_profile", "security", "transcode"
    ].includes(operation))
    .every(([, entry]) => entry.verificationStatus === "single_implementation"));
});

test("shared projections separate semantic facts from environment labels without mutating results", () => {
  const simple = { status: "ok", operation: "inspect", value: 1, runtime: { node: "x" } };
  const preserved = structuredClone(simple);
  assert.deepEqual(semanticProjection(simple), {
    status: "ok",
    operation: "inspect",
    value: 1
  });
  assert.deepEqual(environmentProjection(simple), { runtime: { node: "x" } });
  assert.deepEqual(simple, preserved);

  const uts46 = executeOperation("protocol_profile", {
    profile: "uts46_domain",
    action: "to_unicode",
    text: "xn--fa-hia.de",
    options: {
      checkBidi: true,
      checkHyphens: true,
      checkJoiners: true,
      ignoreInvalidPunycode: false,
      transitionalProcessing: false,
      useSTD3ASCIIRules: true
    },
    witnessMode: "summary"
  });
  const relabeledUts46 = structuredClone(uts46);
  relabeledUts46.standards.engine = "alternate-uts46-engine";
  relabeledUts46.witness.engine = "alternate-uts46-engine";
  assert.equal(
    canonicalDigest(semanticProjection(uts46)),
    canonicalDigest(semanticProjection(relabeledUts46))
  );
  assert.notEqual(
    canonicalDigest(environmentProjection(uts46)),
    canonicalDigest(environmentProjection(relabeledUts46))
  );

  const security = executeOperation("security", {
    text: "pаypal",
    mode: "identifier",
    profile: "uts39_general_security",
    comparison: "paypal",
    confusableDirection: "LTR",
    detailLimit: 0
  });
  const relabeledSecurity = structuredClone(security);
  relabeledSecurity.confusableComparison.engine.name = "alternate-bidi-engine";
  assert.equal(
    canonicalDigest(semanticProjection(security)),
    canonicalDigest(semanticProjection(relabeledSecurity))
  );
  assert.notEqual(
    canonicalDigest(environmentProjection(security)),
    canonicalDigest(environmentProjection(relabeledSecurity))
  );

  const difference = executeOperation("explain_difference", {
    left: "pаypal",
    right: "paypal",
    locale: "en",
    options: {
      usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
      caseFirst: "false", localeMatcher: "best fit", collation: "default"
    },
    confusableDirection: "LTR",
    detailLimit: 0
  });
  const relabeledDifference = structuredClone(difference);
  relabeledDifference.identifierConfusableComparison.engine.name = "alternate-bidi-engine";
  assert.equal(
    canonicalDigest(semanticProjection(difference)),
    canonicalDigest(semanticProjection(relabeledDifference))
  );
  assert.notEqual(
    canonicalDigest(environmentProjection(difference)),
    canonicalDigest(environmentProjection(relabeledDifference))
  );

  const changedSemantic = structuredClone(security);
  changedSemantic.confusableComparison.relation = "not_confusable";
  assert.notEqual(
    canonicalDigest(semanticProjection(security)),
    canonicalDigest(semanticProjection(changedSemantic))
  );

  const oversizedError = {
    status: "error",
    error: {
      code: "RESULT_TOO_LARGE",
      message: "bounded",
      details: {
        actualBytes: 70000,
        semanticBytes: 66000,
        budgetedBytes: 66512,
        metadataBytes: 400,
        metadataReservationBytes: 512,
        limitBytes: 65536
      }
    }
  };
  assert.equal(Object.hasOwn(semanticProjection(oversizedError).error.details, "actualBytes"), false);
  assert.deepEqual(environmentProjection(oversizedError), {
    error: { details: { actualBytes: 70000, metadataBytes: 400 } }
  });
});

test("behavior comparisons report drift without classifying causes", () => {
  const changed = structuredClone(committedManifest);
  const target = changed.cases.find((entry) => entry.reproducibilityTarget === "cross_runtime_exact");
  target.semanticSha256 = "0".repeat(64);
  const comparison = compareBehaviorManifests(committedManifest, changed);
  assert.equal(comparison.schemaVersion, "text-integrity.behavior-comparison/12");
  assert.equal(comparison.changed, true);
  assert.equal(comparison.dataIdentityChanged, false);
  assert.equal(comparison.engineIdentityChanged, false);
  assert.equal(comparison.verificationMetadataChanged, false);
  assert.equal(comparison.engineChanges.uts46Changed, false);
  assert.equal(comparison.engineChanges.collation.changed, false);
  assert.equal(Object.hasOwn(comparison.before.engines.collation, "configurations"), false);
  assert.ok(Buffer.byteLength(JSON.stringify(comparison), "utf8") < 8192);
  assert.equal(comparison.unclassifiedSemanticChanges, 1);
  assert.deepEqual(comparison.changes, [{ id: target.id, kind: "semantic_changed", operation: target.operation }]);

  const environmentChanged = structuredClone(committedManifest);
  const environmentTarget = environmentChanged.cases.find(
    (entry) => entry.reproducibilityTarget === "environment_bound"
  );
  environmentTarget.environmentSha256 = "1".repeat(64);
  const environmentComparison = compareBehaviorManifests(committedManifest, environmentChanged);
  assert.deepEqual(environmentComparison.changes, [{
    id: environmentTarget.id,
    kind: "environment_metadata_changed",
    operation: environmentTarget.operation
  }]);
  assert.equal(environmentComparison.unclassifiedSemanticChanges, 0);

  const dataChanged = structuredClone(committedManifest);
  dataChanged.data.compactDataSha256 = "f".repeat(64);
  const dataComparison = compareBehaviorManifests(committedManifest, dataChanged);
  assert.equal(dataComparison.changed, true);
  assert.equal(dataComparison.dataIdentityChanged, true);

  const contractChanged = structuredClone(committedManifest);
  contractChanged.contracts.measurementComparison = "text-integrity.measurement-comparison/99";
  const contractComparison = compareBehaviorManifests(committedManifest, contractChanged);
  assert.equal(contractComparison.changed, true);
  assert.equal(contractComparison.verificationMetadataChanged, true);
  assert.deepEqual(contractComparison.changes, []);
  assert.equal(dataComparison.engineIdentityChanged, false);
  assert.equal(dataComparison.verificationMetadataChanged, false);
  assert.deepEqual(dataComparison.changes, []);

  const engineChanged = structuredClone(committedManifest);
  engineChanged.engines.uts46.runtimeTreeSha256 = "a".repeat(64);
  const engineComparison = compareBehaviorManifests(committedManifest, engineChanged);
  assert.equal(engineComparison.changed, true);
  assert.equal(engineComparison.dataIdentityChanged, false);
  assert.equal(engineComparison.engineIdentityChanged, true);
  assert.equal(engineComparison.engineChanges.uts46Changed, true);
  assert.equal(engineComparison.engineChanges.collation.changed, false);
  assert.equal(engineComparison.verificationMetadataChanged, false);
  assert.deepEqual(engineComparison.changes, []);

  const calibrationChanged = structuredClone(committedManifest);
  calibrationChanged.engines.collation.observationSha256 = "b".repeat(64);
  const calibrationComparison = compareBehaviorManifests(committedManifest, calibrationChanged);
  assert.equal(calibrationComparison.changed, true);
  assert.equal(calibrationComparison.dataIdentityChanged, false);
  assert.equal(calibrationComparison.engineIdentityChanged, true);
  assert.equal(calibrationComparison.engineChanges.uts46Changed, false);
  assert.equal(calibrationComparison.engineChanges.collation.observationDigestChanged, true);
  assert.equal(
    calibrationComparison.engineChanges.collation.observationDigestChangedWithoutDetailedChange,
    true
  );
  assert.equal(calibrationComparison.verificationMetadataChanged, false);
  assert.deepEqual(calibrationComparison.changes, []);

  const verificationChanged = structuredClone(committedManifest);
  verificationChanged.primitives.nfkcCasefold.independentVerification.totalCaseCount -= 1;
  const verificationComparison = compareBehaviorManifests(committedManifest, verificationChanged);
  assert.equal(verificationComparison.changed, true);
  assert.equal(verificationComparison.dataIdentityChanged, false);
  assert.equal(verificationComparison.engineIdentityChanged, false);
  assert.equal(verificationComparison.verificationMetadataChanged, true);
  assert.deepEqual(verificationComparison.changes, []);

  const projectionChanged = structuredClone(committedManifest);
  projectionChanged.semanticProjection.resultBudget.metadataReservationBytes -= 1;
  const projectionComparison = compareBehaviorManifests(committedManifest, projectionChanged);
  assert.equal(projectionComparison.changed, true);
  assert.equal(projectionComparison.verificationMetadataChanged, true);
  assert.deepEqual(projectionComparison.changes, []);
});

test("the reference WASM loader static module graph stays browser-compatible", () => {
  const entry = new URL("../src/reference/wasm.js", import.meta.url);
  const pending = [entry];
  const visited = new Set();
  while (pending.length > 0) {
    const url = pending.pop();
    if (visited.has(url.href)) continue;
    visited.add(url.href);
    const source = readFileSync(url, "utf8");
    assert.doesNotMatch(source, /(?:^|["'])node:/mu, url.pathname);
    assert.doesNotMatch(source, /\bBuffer\b|\bprocess\./u, url.pathname);
    const staticImport = /\b(?:import|export)\s+(?:[^"'`;]*?\sfrom\s*)?["']([^"']+)["']/gu;
    for (const match of source.matchAll(staticImport)) {
      const specifier = match[1];
      assert.equal(specifier.startsWith("node:"), false, `${url.pathname}: ${specifier}`);
      if (specifier.startsWith(".")) pending.push(new URL(specifier, url));
    }
  }
  assert.equal(visited.has(new URL("../src/reference/json-validation.js", import.meta.url).href), true);
  assert.equal(visited.has(new URL("../src/output-schemas.js", import.meta.url).href), true);
});

test("the packaged reference WASM is bounded and preserves tagged UTF-16 semantics", async () => {
  const runner = await createReferenceWasmRunner(
    readFileSync(new URL("../wasm/text_integrity_reference.wasm", import.meta.url))
  );
  assert.deepEqual(runner.supportedOperations, [
    "index", "inspect", "normalize", "protocol_profile", "security", "transcode"
  ]);
  assert.deepEqual(REFERENCE_WASM_LIMITS, {
    maxRequestBytes: 131072,
    maxResultBytes: 65536,
    maxJsonDepth: 64,
    maxJsonNodes: 65536,
    maxObjectKeys: 256,
    maxArrayItems: 32768,
    maxStringCodeUnits: 65536,
    maxIdentifierCodeUnits: 512
  });
  const malformed = runner.run({
    operation: "inspect",
    arguments: { text: { $text: { kind: "utf16_code_units", units: [0xd800] } }, detailLimit: 4 }
  });
  assert.equal(malformed.inputWellFormed, false);
  assert.equal(malformed.detail.codePoints[0].character.isWellFormed(), false);
  const normalized = runner.run({
    operation: "normalize",
    arguments: { text: { $text: { kind: "unicode_scalar_string", value: "e\u0301" } }, form: "NFC" }
  });
  assert.equal(normalized.normalized, "é");
  const witnessed = runner.run({
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "①A\u0315\u0300" } },
      form: "NFKC",
      witnessMode: "full_required"
    }
  });
  assert.deepEqual(witnessed.witness.stages.canonicalOrdered, ["U+0031", "U+0041", "U+0300", "U+0315"]);
  const sourceSecurity = runner.run({
    operation: "security",
    arguments: {
      source: { $text: { kind: "unicode_scalar_string", value: "pаypal paypal\u202E" } },
      mode: "source",
      spans: [
        { kind: "identifier", startUtf16: 0, endUtf16: 6, scope: "file" },
        { kind: "identifier", startUtf16: 7, endUtf16: 13, scope: "file" }
      ],
      confusableDirection: "LTR",
      detailLimit: 8
    }
  });
  assert.equal(sourceSecurity.operation, "source_diagnose");
  assert.equal(sourceSecurity.diagnostics.confusableIdentifiers.count, 1);
  assert.equal(sourceSecurity.diagnostics.hiddenCharacters.count, 1);
  const protocol = runner.run({
    operation: "protocol_profile",
    arguments: {
      profile: "precis_username_case_mapped",
      action: "enforce",
      text: { $text: { kind: "unicode_scalar_string", value: "Ｕser" } },
      witnessMode: "summary"
    }
  });
  assert.equal(protocol.output, "user");
  assert.equal(protocol.witness.sides[0].passCount, 2);
  const uts46 = runner.run({
    operation: "protocol_profile",
    arguments: {
      profile: "uts46_domain",
      action: "to_ascii",
      text: { $text: { kind: "unicode_scalar_string", value: "Example.COM" } },
      options: {
        checkBidi: true,
        checkHyphens: true,
        checkJoiners: true,
        ignoreInvalidPunycode: false,
        transitionalProcessing: false,
        useSTD3ASCIIRules: false,
        verifyDNSLength: true
      }
    }
  });
  assert.equal(uts46.output, "example.com");
  assert.equal(Object.hasOwn(uts46.standards, "engine"), false);
  const identifierSecurityCase = corpus.cases.find(
    ({ id }) => id === "security-identifier-confusable"
  );
  const identifierSecurity = runner.run({
    operation: identifierSecurityCase.operation,
    arguments: identifierSecurityCase.arguments
  });
  assert.equal(identifierSecurity.confusableComparison.uts39Confusable, true);
  assert.equal(Object.hasOwn(identifierSecurity.confusableComparison, "engine"), false);
  const indexed = runner.run({
    operation: "index",
    arguments: { text: { $text: { kind: "unicode_scalar_string", value: "A😀" } } }
  });
  assert.equal(indexed.counts.codePoints, 2);
  const transcoded = runner.run({
    operation: "transcode",
    arguments: {
      sourceKind: "text",
      text: { $text: { kind: "unicode_scalar_string", value: "A" } },
      targetEncoding: "utf-8",
      allowLossy: false,
      byteRepresentation: "hex"
    }
  });
  assert.equal(transcoded.hex, "41");
  const deterministicError = runner.run({
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "utf16_code_units", units: [0xd800] } },
      form: "NFC"
    }
  });
  assert.equal(deterministicError.error.code, "INVALID_UNICODE");
  for (const operation of [
    "namespace_integrity",
    "reference_bidi_skeleton",
    "reference_confusable_comparison",
    "reference_nfkc_casefold",
    "reference_uts39_post_reorder_skeleton"
  ]) {
    assert.throws(
      () => runner.run({
        operation,
        arguments: { text: { $text: { kind: "unicode_scalar_string", value: "A" } } }
      }),
      /not publicly supported/u
    );
  }
  assert.throws(() => runner.run([]), /one explicit request object/u);
});

test("the raw reference WASM ABI bounds allocation, batches, aggregate output, cumulative work, and recovery", async () => {
  const { instance } = await WebAssembly.instantiate(
    readFileSync(new URL("../wasm/text_integrity_reference.wasm", import.meta.url)),
    {}
  );
  const { exports } = instance;
  assert.deepEqual(REFERENCE_WASM_RAW_ABI, {
    version: 2,
    maxInputBytes: 1048576,
    maxBatchRequests: 1024,
    maxResultBytes: 8388608,
    workLimits: {
      differenceAlignmentCells: 33554432,
      sourceDiagnosticUnits: 1576960,
      uts46PunycodeScanUnits: 16777216
    },
    statuses: {
      ok: 0,
      invalidInputBuffer: 1,
      inputTooLarge: 2,
      batchTooLarge: 3,
      resultTooLarge: 4,
      differenceAlignmentWorkTooLarge: 5,
      sourceDiagnosticWorkTooLarge: 6,
      uts46PunycodeWorkTooLarge: 7
    }
  });
  assert.equal(exports.ti_abi_version(), REFERENCE_WASM_RAW_ABI.version);
  assert.equal(exports.ti_max_input_len(), REFERENCE_WASM_RAW_ABI.maxInputBytes);
  assert.equal(exports.ti_max_batch_len(), REFERENCE_WASM_RAW_ABI.maxBatchRequests);
  assert.equal(exports.ti_max_result_len(), REFERENCE_WASM_RAW_ABI.maxResultBytes);
  assert.equal(
    exports.ti_max_difference_alignment_cells(),
    REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells
  );
  assert.equal(
    exports.ti_max_source_diagnostic_units(),
    REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits
  );
  assert.equal(
    exports.ti_max_uts46_punycode_scan_units(),
    REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits
  );

  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const readResult = () => {
    const pointer = exports.ti_result_ptr();
    const length = exports.ti_result_len();
    return JSON.parse(decoder.decode(
      new Uint8Array(exports.memory.buffer, pointer, length).slice()
    ));
  };
  const runRaw = (input) => {
    const pointer = exports.ti_alloc(input.length);
    assert.notEqual(pointer, 0);
    try {
      new Uint8Array(exports.memory.buffer, pointer, input.length).set(input);
      const status = exports.ti_run(pointer, input.length);
      return { status, resultLength: exports.ti_result_len() };
    } finally {
      exports.ti_dealloc(pointer, input.length);
    }
  };

  const memoryBeforeRejectedAllocation = exports.memory.buffer.byteLength;
  assert.equal(exports.ti_alloc(0), 0);
  assert.equal(exports.ti_alloc(REFERENCE_WASM_RAW_ABI.maxInputBytes + 1), 0);
  assert.equal(exports.memory.buffer.byteLength, memoryBeforeRejectedAllocation);
  assert.equal(
    exports.ti_run(0, REFERENCE_WASM_RAW_ABI.maxInputBytes + 1),
    REFERENCE_WASM_RAW_ABI.statuses.inputTooLarge
  );
  assert.equal(exports.ti_result_len(), 0);

  const valid = encoder.encode(JSON.stringify({
    operation: "inspect",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "A" } },
      detailLimit: 1
    }
  }));
  const ownedPointer = exports.ti_alloc(valid.length);
  assert.notEqual(ownedPointer, 0);
  new Uint8Array(exports.memory.buffer, ownedPointer, valid.length).set(valid);
  assert.equal(exports.ti_alloc(1), 0);
  exports.ti_dealloc(ownedPointer, valid.length - 1);
  assert.equal(exports.ti_alloc(1), 0);
  assert.equal(
    exports.ti_run(ownedPointer, valid.length - 1),
    REFERENCE_WASM_RAW_ABI.statuses.invalidInputBuffer
  );
  assert.equal(exports.ti_result_len(), 0);
  assert.equal(exports.ti_run(ownedPointer, valid.length), REFERENCE_WASM_RAW_ABI.statuses.ok);
  assert.equal(readResult().operation, "inspect");
  assert.equal(exports.ti_alloc(REFERENCE_WASM_RAW_ABI.maxInputBytes + 1), 0);
  assert.equal(exports.ti_result_len(), 0);
  assert.equal(exports.ti_run(ownedPointer, valid.length), REFERENCE_WASM_RAW_ABI.statuses.ok);
  assert.equal(readResult().operation, "inspect");
  exports.ti_dealloc(ownedPointer, valid.length);
  const releasedPointer = exports.ti_alloc(1);
  assert.notEqual(releasedPointer, 0);
  exports.ti_dealloc(releasedPointer, 1);

  const malformed = encoder.encode("{");
  const malformedRun = runRaw(malformed);
  assert.equal(malformedRun.status, REFERENCE_WASM_RAW_ABI.statuses.ok);
  assert.ok(malformedRun.resultLength > 0 && malformedRun.resultLength < 256);
  assert.equal(readResult().error.code, "INVALID_INPUT");

  const oversizedBatch = encoder.encode(JSON.stringify(Array.from(
    { length: REFERENCE_WASM_RAW_ABI.maxBatchRequests + 1 },
    () => ({ operation: "inspect", arguments: null })
  )));
  assert.ok(oversizedBatch.length < REFERENCE_WASM_RAW_ABI.maxInputBytes);
  assert.deepEqual(runRaw(oversizedBatch), {
    status: REFERENCE_WASM_RAW_ABI.statuses.batchTooLarge,
    resultLength: 0
  });

  const amplifyingRequest = {
    operation: "inspect",
    arguments: {
      text: {
        $text: { kind: "unicode_scalar_string", value: "A".repeat(64) }
      },
      detailLimit: 64
    }
  };
  const amplifyingBatch = encoder.encode(JSON.stringify(Array.from(
    { length: REFERENCE_WASM_RAW_ABI.maxBatchRequests },
    () => amplifyingRequest
  )));
  assert.ok(amplifyingBatch.length < REFERENCE_WASM_RAW_ABI.maxInputBytes);
  assert.deepEqual(runRaw(amplifyingBatch), {
    status: REFERENCE_WASM_RAW_ABI.statuses.resultTooLarge,
    resultLength: 0
  });

  const differenceRequest = {
    operation: "reference_explain_difference_spine",
    arguments: {
      left: { $text: { kind: "unicode_scalar_string", value: "A".repeat(4096) } },
      right: { $text: { kind: "unicode_scalar_string", value: "B".repeat(4096) } },
      locale: "en",
      options: {
        usage: "sort",
        sensitivity: "variant",
        ignorePunctuation: false,
        numeric: false,
        caseFirst: "false",
        localeMatcher: "lookup",
        collation: "default"
      },
      confusableDirection: "LTR",
      detailLimit: 0,
      witnessMode: "summary"
    }
  };
  const differenceWorkBatch = encoder.encode(JSON.stringify([
    differenceRequest, differenceRequest
  ]));
  assert.deepEqual(runRaw(differenceWorkBatch), {
    status: REFERENCE_WASM_RAW_ABI.statuses.differenceAlignmentWorkTooLarge,
    resultLength: 0
  });

  const sourceRequest = {
    operation: "security",
    arguments: {
      source: { $text: { kind: "unicode_scalar_string", value: "A".repeat(4096) } },
      mode: "source",
      spans: Array.from({ length: 128 }, () => ({
        kind: "identifier", startUtf16: 0, endUtf16: 4096, scope: "same"
      })),
      confusableDirection: "LTR",
      detailLimit: 128
    }
  };
  const sourceWorkBatch = encoder.encode(JSON.stringify([sourceRequest, sourceRequest]));
  assert.deepEqual(runRaw(sourceWorkBatch), {
    status: REFERENCE_WASM_RAW_ABI.statuses.sourceDiagnosticWorkTooLarge,
    resultLength: 0
  });

  const punycodeText = Array.from(
    { length: 1365 },
    (_, index) => String.fromCodePoint(0x4e00 + index)
  ).join("");
  const punycodeRequest = {
    operation: "protocol_profile",
    arguments: {
      profile: "uts46_domain",
      action: "to_ascii",
      text: { $text: { kind: "unicode_scalar_string", value: punycodeText } },
      options: {
        checkBidi: false,
        checkHyphens: true,
        checkJoiners: true,
        ignoreInvalidPunycode: false,
        transitionalProcessing: false,
        useSTD3ASCIIRules: true,
        verifyDNSLength: false
      },
      witnessMode: "full_required"
    }
  };
  const punycodeWorkBatch = encoder.encode(JSON.stringify(Array.from(
    { length: 10 }, () => punycodeRequest
  )));
  assert.deepEqual(runRaw(punycodeWorkBatch), {
    status: REFERENCE_WASM_RAW_ABI.statuses.uts46PunycodeWorkTooLarge,
    resultLength: 0
  });

  assert.equal(runRaw(valid).status, REFERENCE_WASM_RAW_ABI.statuses.ok);
  assert.equal(readResult().operation, "inspect");
});

test("the packaged reference WASM rejects non-JSON request graphs before serialization", async () => {
  const runner = await createReferenceWasmRunner(
    readFileSync(new URL("../wasm/text_integrity_reference.wasm", import.meta.url))
  );
  const valid = {
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "A" } },
      form: "NFC"
    }
  };
  assert.throws(
    () => runner.run({ ...valid, z: true, a: true }),
    /unknown fields: a, z/u
  );
  assert.throws(
    () => runner.run({ operation: "normalize" }),
    /missing fields: arguments/u
  );
  assert.equal(
    runner.run({ operation: "normalize", arguments: null }).error.code,
    "INVALID_INPUT"
  );

  const cyclic = structuredClone(valid);
  cyclic.arguments.cycle = cyclic.arguments;
  assert.throws(() => runner.run(cyclic), /acyclic JSON value/u);

  let getterCalled = false;
  const accessor = { arguments: {} };
  Object.defineProperty(accessor, "operation", {
    enumerable: true,
    get() {
      getterCalled = true;
      return "normalize";
    }
  });
  assert.throws(() => runner.run(accessor), /operation must be an enumerable data value/u);
  assert.equal(getterCalled, false);

  const customPrototype = structuredClone(valid);
  Object.setPrototypeOf(customPrototype.arguments, { inherited: true });
  assert.throws(() => runner.run(customPrototype), /standard Object prototype/u);

  const sparse = structuredClone(valid);
  sparse.arguments.items = new Array(1);
  assert.throws(() => runner.run(sparse), /dense JSON array/u);

  const nonFinite = structuredClone(valid);
  nonFinite.arguments.value = Number.NaN;
  assert.throws(() => runner.run(nonFinite), /finite JSON number/u);

  const unsupported = structuredClone(valid);
  unsupported.arguments.value = 1n;
  assert.throws(() => runner.run(unsupported), /not JSON-safe/u);

  const proxy = new Proxy(valid, {});
  assert.throws(() => runner.run(proxy), /structured-cloneable JSON value/u);

  const oversizedString = structuredClone(valid);
  oversizedString.arguments.value = "a".repeat(REFERENCE_WASM_LIMITS.maxStringCodeUnits + 1);
  assert.throws(() => runner.run(oversizedString), /string code-unit limit/u);

  const oversizedRequest = {
    operation: "security",
    arguments: {
      text: "a".repeat(REFERENCE_WASM_LIMITS.maxStringCodeUnits),
      comparison: "b".repeat(REFERENCE_WASM_LIMITS.maxStringCodeUnits)
    }
  };
  assert.throws(() => runner.run(oversizedRequest), /request exceeds 131072 bytes/u);
});

test("the packaged reference WASM validates untrusted result bytes and semantic operation shape", async (t) => {
  const memory = new WebAssembly.Memory({ initial: 2 });
  const inputPointer = 1024;
  const resultPointer = 32768;
  let output = new TextEncoder().encode("{}");
  let rawStatus = REFERENCE_WASM_RAW_ABI.statuses.ok;
  const instance = {
    exports: {
      memory,
      ti_alloc: () => inputPointer,
      ti_dealloc: () => {},
      ti_abi_version: () => REFERENCE_WASM_RAW_ABI.version,
      ti_max_input_len: () => REFERENCE_WASM_RAW_ABI.maxInputBytes,
      ti_max_batch_len: () => REFERENCE_WASM_RAW_ABI.maxBatchRequests,
      ti_max_result_len: () => REFERENCE_WASM_RAW_ABI.maxResultBytes,
      ti_max_difference_alignment_cells: () =>
        REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells,
      ti_max_source_diagnostic_units: () =>
        REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits,
      ti_max_uts46_punycode_scan_units: () =>
        REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits,
      ti_run: () => {
        new Uint8Array(memory.buffer, resultPointer, output.length).set(output);
        return rawStatus;
      },
      ti_result_len: () => output.length,
      ti_result_ptr: () => resultPointer
    }
  };
  t.mock.method(WebAssembly, "instantiate", async () => ({ instance }));
  const runner = await createReferenceWasmRunner(new Uint8Array());
  const request = {
    operation: "normalize",
    arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "A" } },
      form: "NFC"
    }
  };

  output = new TextEncoder().encode('{"status":"error","status":"ok"}');
  assert.throws(() => runner.run(request), /duplicate object keys/u);

  output = Uint8Array.from([0xff]);
  assert.throws(() => runner.run(request), /well-formed UTF-8/u);

  output = new TextEncoder().encode("not-json");
  assert.throws(() => runner.run(request), /contain valid JSON/u);

  output = new TextEncoder().encode(JSON.stringify(
    semanticProjection(executeOperation("inspect", { text: "A" }))
  ));
  assert.throws(
    () => runner.run(request),
    /normalize result does not match its closed semantic public result schema/u
  );

  output = new TextEncoder().encode(JSON.stringify({
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "bounded deterministic error",
      details: { field: "text" }
    }
  }));
  assert.deepEqual(runner.run(request), {
    status: "error",
    error: {
      code: "INVALID_INPUT",
      message: "bounded deterministic error",
      details: { field: "text" }
    }
  });

  rawStatus = REFERENCE_WASM_RAW_ABI.statuses.invalidInputBuffer;
  assert.throws(() => runner.run(request), /unowned or mismatched request buffer/u);
  rawStatus = REFERENCE_WASM_RAW_ABI.statuses.differenceAlignmentWorkTooLarge;
  assert.throws(() => runner.run(request), /difference-alignment cells \(status 5\)/u);
  rawStatus = REFERENCE_WASM_RAW_ABI.statuses.sourceDiagnosticWorkTooLarge;
  assert.throws(() => runner.run(request), /source-diagnostic units \(status 6\)/u);
  rawStatus = REFERENCE_WASM_RAW_ABI.statuses.uts46PunycodeWorkTooLarge;
  assert.throws(() => runner.run(request), /UTS #46 Punycode scan units \(status 7\)/u);
  rawStatus = 99;
  assert.throws(() => runner.run(request), /unknown raw ABI status 99/u);

  instance.exports.ti_max_input_len = () => 1;
  await assert.rejects(
    createReferenceWasmRunner(new Uint8Array()),
    /ti_max_input_len returned 1; expected 1048576/u
  );
});
