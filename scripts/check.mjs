import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = new URL("../", import.meta.url);
const ROOT_PATH = fileURLToPath(ROOT);
const NPM_EXEC_PATH = process.env.npm_execpath;
const packageManifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const packageLock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
const pluginManifest = JSON.parse(readFileSync(new URL("../.codex-plugin/plugin.json", import.meta.url), "utf8"));
const mcpManifest = JSON.parse(readFileSync(new URL("../.mcp.json", import.meta.url), "utf8"));
const agentToolManifest = JSON.parse(readFileSync(new URL("../agent-tool.json", import.meta.url), "utf8"));
const agentHostIntegration = JSON.parse(readFileSync(
  new URL("../packaging/agent-host-integration.json", import.meta.url),
  "utf8"
));
const unicodeManifest = JSON.parse(readFileSync(new URL("../vendor/unicode/17.0.0/MANIFEST.json", import.meta.url), "utf8"));
const conformanceManifest = JSON.parse(readFileSync(new URL("../vendor/unicode/17.0.0/CONFORMANCE_MANIFEST.json", import.meta.url), "utf8"));
const bidiManifest = JSON.parse(readFileSync(new URL("../vendor/bidi-js-unicode17/MANIFEST.json", import.meta.url), "utf8"));
const { VERSION } = await import("../src/version.js");
const { UTS46_ENGINE_IDENTITY, UTS46_RUNTIME_FILES } = await import("../src/core/protocol-engine.js");

function runNpm(args, options) {
  if (NPM_EXEC_PATH) return spawnSync(process.execPath, [NPM_EXEC_PATH, ...args], options);
  return spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", args, {
    ...options,
    shell: process.platform === "win32"
  });
}

function childFailure(result, fallback) {
  return result.stderr || result.error?.message || `${fallback}\n`;
}

if (VERSION !== packageManifest.version || pluginManifest.version !== packageManifest.version) {
  process.stderr.write("version drift: package.json, src/version.js, and the plugin manifest must agree\n");
  process.exit(1);
}
if (pluginManifest.name !== "text-integrity"
  || pluginManifest.mcpServers !== "./.mcp.json"
  || mcpManifest.mcpServers?.["text-integrity"]?.args?.[0] !== "./bin/text-integrity-mcp.js"
  || mcpManifest.mcpServers?.["text-integrity"]?.cwd !== ".") {
  process.stderr.write("product-local plugin manifest does not match the packaged MCP entry\n");
  process.exit(1);
}
const expectedToolNames = [
  "text_inspect",
  "text_normalize",
  "text_compare",
  "text_transcode",
  "text_security_observe",
  "text_explain_difference",
  "text_index_map",
  "text_protocol_profile"
];
if (agentToolManifest.id !== "text-integrity"
  || agentToolManifest.version !== packageManifest.version
  || agentToolManifest.package?.componentId !== "text-integrity"
  || agentToolManifest.package?.integration !== "packaging/agent-host-integration.json"
  || agentToolManifest.package?.legal?.sbom !== "packaging/agent-host-sbom.spdx.json"
  || agentHostIntegration.schemaVersion !== "openadam.agent-host-tool-integration.v0.2"
  || agentHostIntegration.runtime?.command !== "marketplace/plugins/text-integrity/bin/text-integrity-mcp.js"
  || JSON.stringify(agentHostIntegration.runtime?.expectedTools) !== JSON.stringify(expectedToolNames)
  || !agentHostIntegration.codex?.identityFiles?.includes("skills/text-integrity/SKILL.md")) {
  process.stderr.write("Agent Host declaration does not match the packaged product identity and tool set\n");
  process.exit(1);
}

const tr46Lock = packageLock.packages?.["node_modules/tr46"];
const punycodeLock = packageLock.packages?.["node_modules/punycode"];
if (packageManifest.dependencies?.tr46 !== UTS46_ENGINE_IDENTITY.version
  || packageManifest.dependencies?.punycode !== UTS46_ENGINE_IDENTITY.dependency.version
  || tr46Lock?.version !== UTS46_ENGINE_IDENTITY.version
  || tr46Lock?.integrity !== UTS46_ENGINE_IDENTITY.packageIntegrity
  || punycodeLock?.version !== UTS46_ENGINE_IDENTITY.dependency.version
  || punycodeLock?.integrity !== UTS46_ENGINE_IDENTITY.dependency.packageIntegrity) {
  process.stderr.write("UTS #46 runtime dependencies do not match the calibrated engine identity\n");
  process.exit(1);
}
const tr46Package = JSON.parse(readFileSync(path.join(ROOT_PATH, "node_modules/tr46/package.json"), "utf8"));
if (tr46Package.version !== UTS46_ENGINE_IDENTITY.version
  || tr46Package.unicodeVersion !== UTS46_ENGINE_IDENTITY.unicodeVersion) {
  process.stderr.write("installed tr46 package metadata does not match the calibrated engine identity\n");
  process.exit(1);
}
const uts46RuntimeTree = createHash("sha256");
for (const file of UTS46_RUNTIME_FILES) {
  uts46RuntimeTree.update(file);
  uts46RuntimeTree.update(Buffer.from([0]));
  uts46RuntimeTree.update(readFileSync(path.join(ROOT_PATH, "node_modules", file)));
  uts46RuntimeTree.update(Buffer.from([0]));
}
if (uts46RuntimeTree.digest("hex") !== UTS46_ENGINE_IDENTITY.runtimeTreeSha256) {
  process.stderr.write("installed UTS #46 runtime tree failed its calibrated content check\n");
  process.exit(1);
}
const idnaCorpus = conformanceManifest.files.find((entry) => entry.path === "conformance/IdnaTestV2.txt.gz");
if (idnaCorpus?.sha256 !== UTS46_ENGINE_IDENTITY.conformance.compressedSha256
  || idnaCorpus?.uncompressedSha256 !== UTS46_ENGINE_IDENTITY.conformance.uncompressedSha256) {
  process.stderr.write("IdnaTestV2 corpus identity does not match the calibrated UTS #46 engine record\n");
  process.exit(1);
}

for (const entry of bidiManifest.files) {
  const bytes = readFileSync(new URL(`../vendor/bidi-js-unicode17/${entry.path}`, import.meta.url));
  const actualSha256 = createHash("sha256").update(bytes).digest("hex");
  if (bytes.length !== entry.bytes || actualSha256 !== entry.sha256) {
    process.stderr.write(`vendored UBA file failed integrity check: ${entry.path}\n`);
    process.exit(1);
  }
}

const compactCheck = spawnSync(process.execPath, ["scripts/build-unicode-data.mjs", "--check"], {
  cwd: ROOT,
  encoding: "utf8"
});
if (compactCheck.status !== 0) {
  process.stderr.write(compactCheck.stderr);
  process.stderr.write(compactCheck.stdout);
  process.exit(compactCheck.status ?? 1);
}

const nativeNfkcCasefoldCheck = spawnSync(
  process.execPath,
  ["scripts/build-native-nfkc-casefold.mjs", "--check"],
  { cwd: ROOT, encoding: "utf8" }
);
if (nativeNfkcCasefoldCheck.status !== 0) {
  process.stderr.write(nativeNfkcCasefoldCheck.stderr);
  process.stderr.write(nativeNfkcCasefoldCheck.stdout);
  process.exit(nativeNfkcCasefoldCheck.status ?? 1);
}

const nativeUts39SkeletonCheck = spawnSync(
  process.execPath,
  ["scripts/build-native-uts39-skeleton.mjs", "--check"],
  { cwd: ROOT, encoding: "utf8" }
);
if (nativeUts39SkeletonCheck.status !== 0) {
  process.stderr.write(nativeUts39SkeletonCheck.stderr);
  process.stderr.write(nativeUts39SkeletonCheck.stdout);
  process.exit(nativeUts39SkeletonCheck.status ?? 1);
}

const nativeBidiDataCheck = spawnSync(
  process.execPath,
  ["scripts/build-native-bidi-data.mjs", "--check"],
  { cwd: ROOT, encoding: "utf8" }
);
if (nativeBidiDataCheck.status !== 0) {
  process.stderr.write(nativeBidiDataCheck.stderr);
  process.stderr.write(nativeBidiDataCheck.stdout);
  process.exit(nativeBidiDataCheck.status ?? 1);
}

const nativeScriptDataCheck = spawnSync(
  process.execPath,
  ["scripts/build-native-script-data.mjs", "--check"],
  { cwd: ROOT, encoding: "utf8" }
);
if (nativeScriptDataCheck.status !== 0) {
  process.stderr.write(nativeScriptDataCheck.stderr);
  process.stderr.write(nativeScriptDataCheck.stdout);
  process.exit(nativeScriptDataCheck.status ?? 1);
}

const nativeSecurityDataCheck = spawnSync(
  process.execPath,
  ["scripts/build-native-security-data.mjs", "--check"],
  { cwd: ROOT, encoding: "utf8" }
);
if (nativeSecurityDataCheck.status !== 0) {
  process.stderr.write(nativeSecurityDataCheck.stderr);
  process.stderr.write(nativeSecurityDataCheck.stdout);
  process.exit(nativeSecurityDataCheck.status ?? 1);
}

const nativePrecisDataCheck = spawnSync(
  process.execPath,
  ["scripts/build-native-precis-data.mjs", "--check"],
  { cwd: ROOT, encoding: "utf8" }
);
if (nativePrecisDataCheck.status !== 0) {
  process.stderr.write(nativePrecisDataCheck.stderr);
  process.stderr.write(nativePrecisDataCheck.stdout);
  process.exit(nativePrecisDataCheck.status ?? 1);
}

const behaviorCheck = spawnSync(process.execPath, ["scripts/behavior-manifest.mjs", "--check"], {
  cwd: ROOT,
  encoding: "utf8"
});
if (behaviorCheck.status !== 0) {
  process.stderr.write(behaviorCheck.stderr);
  process.stderr.write(behaviorCheck.stdout);
  process.exit(behaviorCheck.status ?? 1);
}

const propertyCheck = spawnSync(process.execPath, ["scripts/verify-properties.mjs"], {
  cwd: ROOT,
  encoding: "utf8"
});
if (propertyCheck.status !== 0) {
  process.stderr.write(propertyCheck.stderr);
  process.stderr.write(propertyCheck.stdout);
  process.exit(propertyCheck.status ?? 1);
}

const replayReceiptCheck = spawnSync(process.execPath, ["scripts/replay-receipt.mjs", "--check"], {
  cwd: ROOT,
  encoding: "utf8"
});
if (replayReceiptCheck.status !== 0) {
  process.stderr.write(replayReceiptCheck.stderr);
  process.stderr.write(replayReceiptCheck.stdout);
  process.exit(replayReceiptCheck.status ?? 1);
}

function sourceFiles(directory) {
  const files = [];
  for (const entry of readdirSync(directory)) {
    if (entry === ".git" || entry === "node_modules") continue;
    const absolute = path.join(directory, entry);
    if (statSync(absolute).isDirectory()) files.push(...sourceFiles(absolute));
    else if (entry.endsWith(".js") || entry.endsWith(".mjs")) files.push(absolute);
  }
  return files;
}

for (const file of sourceFiles(ROOT_PATH)) {
  const syntax = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" });
  if (syntax.status !== 0) {
    process.stderr.write(syntax.stderr);
    process.exit(syntax.status ?? 1);
  }
}

const tests = spawnSync(process.execPath, ["--test"], { cwd: ROOT, stdio: "inherit" });
if (tests.status !== 0) process.exit(tests.status ?? 1);

const pack = runNpm(["pack", "--dry-run", "--json"], { cwd: ROOT, encoding: "utf8" });
if (pack.status !== 0) {
  process.stderr.write(childFailure(pack, "npm pack dry run failed"));
  process.exit(pack.status ?? 1);
}
const packageFiles = JSON.parse(pack.stdout)[0].files.map((entry) => entry.path);
for (const required of [
  ".codex-plugin/plugin.json",
  ".mcp.json",
  "skills/text-integrity/SKILL.md",
  "LICENSE",
  "NOTICE",
  "THIRD_PARTY_NOTICES.md",
  "src/contracts.js",
  "src/mcp-output-schemas.js",
  "src/namespace-contract.js",
  "src/output-schemas.js",
  "src/schemas/basic.js",
  "src/schemas/common.js",
  "src/schemas/difference.js",
  "src/schemas/namespace.js",
  "src/schemas/protocol.js",
  "src/schemas/security.js",
  "src/core/errors.js",
  "src/core/grapheme.js",
  "src/core/limits.js",
  "src/core/namespace-integrity.js",
  "src/core/normalization.js",
  "src/core/operations.js",
  "src/core/bidi.js",
  "src/core/collation.js",
  "src/core/difference.js",
  "src/core/difference-witness.js",
  "src/core/protocol.js",
  "src/core/protocol-engine.js",
  "src/core/protocol-witness.js",
  "src/core/security.js",
  "src/core/source-diagnostics.js",
  "src/core/string-order.js",
  "src/core/text-position.js",
  "src/core/transcode-codec.js",
  "src/core/transcode-witness.js",
  "src/core/unicode-case.js",
  "src/core/unicode-security-data.js",
  "src/library.js",
  "src/transport-json.js",
  "src/reference/behavior.js",
  "src/reference/canonical.js",
  "src/reference/collation-calibration.js",
  "src/reference/collation-comparison.js",
  "src/reference/measurement.js",
  "src/reference/package-replay-sidecar.js",
  "src/reference/property-verification.js",
  "src/reference/replay-comparison.js",
  "src/reference/replay-receipt.js",
  "src/reference/replay-validation.js",
  "src/reference/versions.js",
  "src/reference/wasm.js",
  "src/mcp/server.js",
  "src/mcp/summary.js",
  "src/version.js",
  "reference/behavior-corpus.json",
  "reference/behavior-manifest.json",
  "reference/replay-receipt.json",
  "reference/README.md",
  "wasm/MANIFEST.json",
  "wasm/text_integrity_reference.wasm",
  "vendor/unicode/17.0.0/compact/data.bin",
  "vendor/unicode/17.0.0/compact/MANIFEST.json",
  "vendor/unicode/17.0.0/MANIFEST.json",
  "vendor/bidi-js-unicode17/bidi.mjs",
  "vendor/bidi-js-unicode17/LICENSE.txt",
  "vendor/bidi-js-unicode17/MANIFEST.json",
  "vendor/bidi-js-unicode17/PROVENANCE.md",
  "vendor/unicode/17.0.0/license/LICENSE.txt"
]) {
  if (!packageFiles.includes(required)) {
    process.stderr.write(`package is missing required runtime file: ${required}\n`);
    process.exit(1);
  }
}
const runtimeExcluded = [
  ...unicodeManifest.files.filter((entry) => entry.path !== "license/LICENSE.txt")
    .map((entry) => `vendor/unicode/17.0.0/${entry.path}`),
  ...conformanceManifest.files.map((entry) => `vendor/unicode/17.0.0/${entry.path}`)
];
const leaked = packageFiles.filter(
  (file) => runtimeExcluded.includes(file) || file.startsWith("vendor/unicode/17.0.0/conformance")
);
if (leaked.length > 0) {
  process.stderr.write(`runtime package must not ship source-only Unicode corpora: ${leaked.join(", ")}\n`);
  process.exit(1);
}
if (packageFiles.some((file) => file.startsWith(".playwright-cli/"))) {
  process.stderr.write("package contains Playwright review artifacts\n");
  process.exit(1);
}

const smokeRoot = mkdtempSync(path.join(tmpdir(), "text-integrity-package-"));
try {
  const packed = runNpm(["pack", "--json", "--pack-destination", smokeRoot], {
    cwd: ROOT,
    encoding: "utf8"
  });
  if (packed.status !== 0) {
    process.stderr.write(childFailure(packed, "npm pack failed"));
    process.exit(packed.status ?? 1);
  }
  const packedMetadata = JSON.parse(packed.stdout)[0];
  const filename = packedMetadata.filename;
  const tarball = path.join(smokeRoot, filename);
  const project = path.join(smokeRoot, "consumer");
  mkdirSync(project);
  writeFileSync(path.join(project, "package.json"), '{"name":"text-integrity-smoke","private":true,"type":"module"}\n');
  const installed = runNpm(["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], {
    cwd: project,
    encoding: "utf8"
  });
  if (installed.status !== 0) {
    process.stderr.write(childFailure(installed, "npm install smoke failed"));
    process.exit(installed.status ?? 1);
  }

  const librarySmoke = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { analyzeNamespaceIntegrity, executeOperation, LIBRARY_INFO } from "text-integrity";
    import {
      COLLATION_COMPARISON_LIMITS,
      MEASUREMENT_RECORD_LIMITS,
      MEASUREMENT_COMPARISON_LIMITS,
      MEASUREMENT_REPLAY_LIMITS,
      PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS,
      PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS,
      PROPERTY_VERIFICATION_LIMITS,
      REFERENCE_SOURCE_FILES,
      REPLAY_INSTALLED_RUNTIME_FILES,
      REPLAY_RECEIPT_COMPARISON_LIMITS,
      compareCollationCalibrations,
      compareMeasurementRecords,
      comparePackageReplaySidecars,
      compareReplayReceipts,
      createCollationCalibration,
      createMeasurementRecord,
      createPackageReplaySidecar,
      createReplayReceipt,
      parseMeasurementRecord,
      replayMeasurementRecord,
      runPropertyVerification,
      verifyPackageReplaySidecarBytes
    } from "text-integrity/reference";
    import { createReferenceWasmRunner } from "text-integrity/reference/wasm";
    import { readFileSync } from "node:fs";
    const result = executeOperation("normalize", { text: "e\\u0301", form: "NFC" });
    const difference = executeOperation("explain_difference", {
      left: "Aé🙂Z",
      right: "Axe\\u0301🙂Y",
      locale: "en",
      options: {
        usage: "sort", sensitivity: "variant", ignorePunctuation: false,
        numeric: false, caseFirst: "false", localeMatcher: "lookup", collation: "default"
      },
      confusableDirection: "LTR",
      witnessMode: "full_required"
    });
    const measurement = createMeasurementRecord({
      operation: "normalize",
      arguments: {
        text: { $text: { kind: "unicode_scalar_string", value: "e\\u0301" } }, form: "NFC"
      }
    });
    const receivedMeasurement = parseMeasurementRecord(Buffer.from(JSON.stringify(measurement), "utf8"));
    const measurementReplay = replayMeasurementRecord(receivedMeasurement);
    const measurementComparison = compareMeasurementRecords(
      receivedMeasurement,
      structuredClone(receivedMeasurement)
    );
    const errorMeasurement = createMeasurementRecord({
      operation: "normalize",
      arguments: {
        text: { $text: { kind: "utf16_code_units", units: [0xd800] } }, form: "NFC"
      }
    });
    const receivedErrorMeasurement = parseMeasurementRecord(
      Buffer.from(JSON.stringify(errorMeasurement), "utf8")
    );
    const errorMeasurementReplay = replayMeasurementRecord(receivedErrorMeasurement);
    const errorMeasurementComparison = compareMeasurementRecords(
      receivedErrorMeasurement,
      structuredClone(receivedErrorMeasurement)
    );
    const calibration = createCollationCalibration();
    const calibrationComparison = compareCollationCalibrations(calibration, calibration);
    const propertyVerification = runPropertyVerification();
    const receiptUrl = new URL(import.meta.resolve("text-integrity/reference/replay-receipt.json"));
    const installedPackageRoot = new URL("../", receiptUrl);
    const packageBytes = (relativePath) => readFileSync(new URL(relativePath, installedPackageRoot));
    const installedReceipt = JSON.parse(packageBytes("reference/replay-receipt.json"));
    const installedReplayInputs = {
      packageManifest: packageBytes("package.json"),
      behaviorCorpus: packageBytes("reference/behavior-corpus.json"),
      behaviorManifest: packageBytes("reference/behavior-manifest.json"),
      unicodeSourceManifest: packageBytes("vendor/unicode/17.0.0/MANIFEST.json"),
      unicodeCompactManifest: packageBytes("vendor/unicode/17.0.0/compact/MANIFEST.json"),
      unicodeCompactData: packageBytes("vendor/unicode/17.0.0/compact/data.bin"),
      bidiManifest: packageBytes("vendor/bidi-js-unicode17/MANIFEST.json"),
      bidiRuntime: packageBytes("vendor/bidi-js-unicode17/bidi.mjs"),
      referenceSources: REFERENCE_SOURCE_FILES.map((path) => ({ path, bytes: packageBytes(path) })),
      wasmManifest: packageBytes("wasm/MANIFEST.json"),
      wasmModule: packageBytes("wasm/text_integrity_reference.wasm"),
      installedRuntimeFiles: REPLAY_INSTALLED_RUNTIME_FILES.map((path) => ({
        path,
        bytes: readFileSync(new URL("../" + path, installedPackageRoot))
      }))
    };
    const regeneratedReceipt = createReplayReceipt(installedReplayInputs);
    const installedReceiptComparison = compareReplayReceipts(
      installedReceipt,
      regeneratedReceipt
    );
    const packageArtifactBytes = readFileSync(${JSON.stringify(tarball)});
    const packageSidecar = createPackageReplaySidecar({
      ...installedReplayInputs,
      packageArtifact: packageArtifactBytes
    });
    const packageSidecarByteVerification = verifyPackageReplaySidecarBytes(
      packageSidecar,
      packageArtifactBytes
    );
    const packageSidecarComparison = comparePackageReplaySidecars(
      packageSidecar,
      packageSidecar
    );
    const namespace = analyzeNamespaceIntegrity({
      items: [{ id: "a", text: "é", scope: "s" }, { id: "b", text: "e\\u0301", scope: "s" }],
      relations: ["nfc"]
    });
    const wasm = await createReferenceWasmRunner(readFileSync(new URL(
      import.meta.resolve("text-integrity/reference/wasm/module")
    )));
    const wasmResult = wasm.run({ operation: "normalize", arguments: {
      text: { $text: { kind: "unicode_scalar_string", value: "e\u0301" } }, form: "NFC"
    } });
    const wasmSecurity = wasm.run({ operation: "security", arguments: {
      source: { $text: { kind: "unicode_scalar_string", value: "pаypal paypal\u202E" } },
      mode: "source",
      spans: [
        { kind: "identifier", startUtf16: 0, endUtf16: 6, scope: "file" },
        { kind: "identifier", startUtf16: 7, endUtf16: 13, scope: "file" }
      ],
      confusableDirection: "LTR",
      detailLimit: 8
    } });
    const wasmError = wasm.run({ operation: "normalize", arguments: {
      text: { $text: { kind: "utf16_code_units", units: [0xd800] } }, form: "NFC"
    } });
    let closedWasmWrapperRejected = false;
    try {
      wasm.run({ operation: "normalize", arguments: {}, extra: true });
    } catch (error) {
      closedWasmWrapperRejected = /unknown fields: extra/u.test(error.message);
    }
    let wasmAccessorCalled = false;
    const accessorRequest = { arguments: {} };
    Object.defineProperty(accessorRequest, "operation", {
      enumerable: true,
      get() {
        wasmAccessorCalled = true;
        return "normalize";
      }
    });
    let wasmAccessorRejected = false;
    try {
      wasm.run(accessorRequest);
    } catch (error) {
      wasmAccessorRejected = /enumerable data value/u.test(error.message);
    }
    let hiddenRoutesRejected = true;
    for (const operation of [
      "namespace_integrity",
      "reference_bidi_skeleton",
      "reference_confusable_comparison",
      "reference_nfkc_casefold",
      "reference_uts39_post_reorder_skeleton"
    ]) {
      try {
        wasm.run({ operation, arguments: {
          text: { $text: { kind: "unicode_scalar_string", value: "A" } }
        } });
        hiddenRoutesRejected = false;
      } catch (error) {
        hiddenRoutesRejected &&= /not publicly supported/u.test(error.message);
      }
    }
    if (result.normalized !== "é" || LIBRARY_INFO.version !== ${JSON.stringify(VERSION)}
      || measurement.schemaVersion !== "text-integrity.measurement-record/2"
      || measurement.complete !== true || measurement.result.normalized !== "é"
      || measurement.contracts.semanticProjection !== "text-integrity.semantic-projection/1"
      || measurement.contracts.environmentProjection !== "text-integrity.environment-projection/1"
      || measurement.contracts.publicResult !== "text-integrity.public-result-contract/2"
      || JSON.stringify(receivedMeasurement) !== JSON.stringify(measurement)
      || Buffer.byteLength(JSON.stringify(measurement), "utf8")
        > MEASUREMENT_RECORD_LIMITS.maxSerializedBytes
      || measurementReplay.schemaVersion !== "text-integrity.measurement-replay/1"
      || measurementReplay.changeKind !== "exact_match"
      || measurementReplay.matches.semanticResult !== true
      || measurementReplay.crossRuntimeExpectation.required !== true
      || measurementReplay.crossRuntimeExpectation.met !== true
      || Object.hasOwn(measurementReplay, "request") || Object.hasOwn(measurementReplay, "result")
      || Buffer.byteLength(JSON.stringify(measurementReplay), "utf8")
        > MEASUREMENT_REPLAY_LIMITS.maxSerializedBytes
      || measurementComparison.schemaVersion !== "text-integrity.measurement-comparison/1"
      || measurementComparison.changed !== false
      || measurementComparison.semanticComparisonApplicable !== true
      || measurementComparison.crossRuntimeExpectation.required !== true
      || measurementComparison.crossRuntimeExpectation.met !== true
      || Object.hasOwn(measurementComparison.before, "request")
      || Object.hasOwn(measurementComparison.before, "result")
      || Buffer.byteLength(JSON.stringify(measurementComparison), "utf8")
        > MEASUREMENT_COMPARISON_LIMITS.maxSerializedBytes
      || errorMeasurement.schemaVersion !== "text-integrity.measurement-record/2"
      || errorMeasurement.result.status !== "error"
      || errorMeasurement.result.error.code !== "INVALID_UNICODE"
      || JSON.stringify(receivedErrorMeasurement) !== JSON.stringify(errorMeasurement)
      || errorMeasurementReplay.changeKind !== "exact_match"
      || errorMeasurementReplay.matches.semanticResult !== true
      || errorMeasurementComparison.changed !== false
      || errorMeasurementComparison.matches.semanticResult !== true
      || namespace.groups.length !== 1
      || calibration.configurationCount !== 15 || calibration.comparisonCount !== 45
      || calibration.probeSetSha256 !== "42f126f05d03846e252081939c643ec5d0db4cec481f0b65afc5f8f9775a627c"
      || calibrationComparison.complete !== true || calibrationComparison.changed !== false
      || Buffer.byteLength(JSON.stringify(calibrationComparison), "utf8")
        > COLLATION_COMPARISON_LIMITS.maxSerializedBytes
      || JSON.stringify(installedReceipt) !== JSON.stringify(regeneratedReceipt)
      || installedReceiptComparison.complete !== true
      || installedReceiptComparison.changed !== false
      || Buffer.byteLength(JSON.stringify(installedReceiptComparison), "utf8")
        > REPLAY_RECEIPT_COMPARISON_LIMITS.maxSerializedBytes
      || packageSidecarComparison.complete !== true
      || packageSidecarComparison.changed !== false
      || Buffer.byteLength(JSON.stringify(packageSidecarComparison), "utf8")
        > PACKAGE_REPLAY_SIDECAR_COMPARISON_LIMITS.maxSerializedBytes
      || packageSidecarByteVerification.complete !== true
      || packageSidecarByteVerification.matched !== true
      || Buffer.byteLength(JSON.stringify(packageSidecarByteVerification), "utf8")
        > PACKAGE_REPLAY_SIDECAR_BYTE_VERIFICATION_LIMITS.maxSerializedBytes
      || propertyVerification.complete !== true
      || propertyVerification.passed !== true
      || propertyVerification.schemaVersion !== "text-integrity.property-verification/2"
      || propertyVerification.totals.propertyCount !== 8
      || propertyVerification.totals.caseEvaluationCount !== 1646
      || propertyVerification.totals.assertionCount !== 15278
      || propertyVerification.generator.corpusSha256
        !== "4f032c7ffcc39706dee7496e0ddd03e6d7d70f650c2ab556937b860080d4fd8e"
      || propertyVerification.propertyRootSha256
        !== "5b07d40770ac9c9db051fc22a8c77a28a6ffcd74b4b964ef0f930f89f75c8e96"
      || Buffer.byteLength(JSON.stringify(propertyVerification), "utf8")
        > PROPERTY_VERIFICATION_LIMITS.maxSerializedBytes
      || packageSidecar.package.filename !== ${JSON.stringify(packedMetadata.filename)}
      || packageSidecar.package.bytes !== ${JSON.stringify(packedMetadata.size)}
      || packageSidecar.package.shasum !== ${JSON.stringify(packedMetadata.shasum)}
      || packageSidecar.package.integrity !== ${JSON.stringify(packedMetadata.integrity)}
      || difference.witness.alignment.codePoint.segments.length !== 4
      || difference.witness.alignment.grapheme.segments.length !== 4
      || wasmResult.normalized !== "é"
      || wasmSecurity.operation !== "source_diagnose"
      || wasmSecurity.diagnostics.confusableIdentifiers.count !== 1
      || wasmSecurity.diagnostics.hiddenCharacters.count !== 1
      || wasmError.error.code !== "INVALID_UNICODE"
      || !closedWasmWrapperRejected
      || !wasmAccessorRejected
      || wasmAccessorCalled
      || !hiddenRoutesRejected) process.exit(1);
  `], { cwd: project, encoding: "utf8" });
  if (librarySmoke.status !== 0) {
    process.stderr.write(librarySmoke.stderr);
    process.exit(librarySmoke.status ?? 1);
  }

  const packageRoot = path.join(project, "node_modules", packageManifest.name);
  const cliSmoke = spawnSync(process.execPath, [path.join(packageRoot, "bin", "text-integrity.js"), "normalize", "--text", "e\u0301", "--form", "NFC"], {
    cwd: project,
    encoding: "utf8"
  });
  if (cliSmoke.status !== 0 || JSON.parse(cliSmoke.stdout).normalized !== "é") {
    process.stderr.write(cliSmoke.stderr || "installed CLI smoke failed\n");
    process.exit(cliSmoke.status || 1);
  }

  const mcpSmoke = spawnSync(process.execPath, [path.join(packageRoot, "bin", "text-integrity-mcp.js")], {
    cwd: project,
    encoding: "utf8",
    input: `${JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" },
        name: "text_explain_difference",
        arguments: {
          left: "Aé🙂Z", right: "Axe\u0301🙂Y", locale: "en",
          options: {
            usage: "sort", sensitivity: "variant", ignorePunctuation: false,
            numeric: false, caseFirst: "false", localeMatcher: "lookup", collation: "default"
          },
          confusableDirection: "LTR", witnessMode: "full_required"
        }
      }
    })}\n`
  });
  const mcpValue = mcpSmoke.status === 0 ? JSON.parse(mcpSmoke.stdout) : null;
  if (mcpSmoke.status !== 0
    || mcpValue?.result?.structuredContent?.witness?.alignment?.codePoint?.segments?.length !== 4
    || mcpValue?.result?.structuredContent?.witness?.alignment?.grapheme?.segments?.length !== 4) {
    process.stderr.write(mcpSmoke.stderr || "installed MCP smoke failed\n");
    process.exit(mcpSmoke.status || 1);
  }
} finally {
  rmSync(smokeRoot, { recursive: true, force: true });
}

process.stdout.write("check: syntax, full test suite, compact-data/receipt reproducibility, package inventory, and installed artifact smoke passed\n");
