import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  REFERENCE_SOURCE_FILES,
  createReplayReceipt
} from "../src/reference/replay-receipt.js";
import {
  createPackageReplaySidecar,
  verifyPackageReplaySidecarBytes
} from "../src/reference/package-replay-sidecar.js";
import { UTS46_RUNTIME_FILES } from "../src/core/protocol-engine.js";
import {
  assessReplayReceiptState,
  atomicReplaceReplayReceipt,
  readReplayReceiptState
} from "./replay-receipt-file.mjs";

const ROOT = new URL("../", import.meta.url);
const RECEIPT_PATH = new URL("../reference/replay-receipt.json", import.meta.url);
const NPM_EXEC_PATH = process.env.npm_execpath;

function runNpm(args, options) {
  if (NPM_EXEC_PATH) return spawnSync(process.execPath, [NPM_EXEC_PATH, ...args], options);
  return spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", args, {
    ...options,
    shell: process.platform === "win32"
  });
}

function artifactInputs(packageRoot, runtimeRoot, packageArtifact) {
  const bytes = (relativePath) => readFileSync(new URL(relativePath, packageRoot));
  return {
    packageManifest: bytes("package.json"),
    behaviorCorpus: bytes("reference/behavior-corpus.json"),
    behaviorManifest: bytes("reference/behavior-manifest.json"),
    unicodeSourceManifest: bytes("vendor/unicode/17.0.0/MANIFEST.json"),
    unicodeCompactManifest: bytes("vendor/unicode/17.0.0/compact/MANIFEST.json"),
    unicodeCompactData: bytes("vendor/unicode/17.0.0/compact/data.bin"),
    bidiManifest: bytes("vendor/bidi-js-unicode17/MANIFEST.json"),
    bidiRuntime: bytes("vendor/bidi-js-unicode17/bidi.mjs"),
    referenceSources: REFERENCE_SOURCE_FILES.map((file) => ({ path: file, bytes: bytes(file) })),
    wasmManifest: bytes("wasm/MANIFEST.json"),
    wasmModule: bytes("wasm/text_integrity_reference.wasm"),
    installedRuntimeFiles: UTS46_RUNTIME_FILES.map((file) => ({
      path: file,
      bytes: readFileSync(new URL(file, runtimeRoot))
    })),
    ...(packageArtifact === undefined ? {} : { packageArtifact })
  };
}

function render(value) {
  return `${JSON.stringify(value, null, 2)}\n`;
}

function packageSidecar() {
  const temporaryRoot = mkdtempSync(path.join(tmpdir(), "text-integrity-sidecar-"));
  try {
    const packed = runNpm(["pack", "--json", "--pack-destination", temporaryRoot], {
      cwd: ROOT,
      encoding: "utf8"
    });
    if (packed.status !== 0) throw new Error(packed.stderr || "npm pack failed");
    const metadata = JSON.parse(packed.stdout)[0];
    const tarballPath = path.join(temporaryRoot, metadata.filename);
    const project = path.join(temporaryRoot, "consumer");
    mkdirSync(project);
    writeFileSync(
      path.join(project, "package.json"),
      '{"name":"text-integrity-sidecar-smoke","private":true,"type":"module"}\n'
    );
    const installed = runNpm([
      "install", "--ignore-scripts", "--no-audit", "--no-fund", tarballPath
    ], { cwd: project, encoding: "utf8" });
    if (installed.status !== 0) throw new Error(installed.stderr || "npm install failed");
    const packageRoot = pathToFileURL(
      `${path.join(project, "node_modules", "text-integrity")}${path.sep}`
    );
    const runtimeRoot = pathToFileURL(`${path.join(project, "node_modules")}${path.sep}`);
    const sidecar = createPackageReplaySidecar(artifactInputs(
      packageRoot,
      runtimeRoot,
      readFileSync(tarballPath)
    ));
    const byteVerification = verifyPackageReplaySidecarBytes(
      sidecar,
      readFileSync(tarballPath)
    );
    if (sidecar.package.filename !== metadata.filename
      || byteVerification.matched !== true
      || byteVerification.actualPackage.bytes !== metadata.size
      || byteVerification.actualPackage.shasum !== metadata.shasum
      || byteVerification.actualPackage.integrity !== metadata.integrity) {
      throw new Error("npm package metadata does not match the explicit tarball bytes");
    }
    return sidecar;
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
}

const mode = process.argv[2] ?? "--check";
if (mode === "--package") {
  process.stdout.write(render(packageSidecar()));
} else {
  const rendered = render(createReplayReceipt(artifactInputs(ROOT, new URL("node_modules/", ROOT))));
  if (mode === "--write") {
    atomicReplaceReplayReceipt(RECEIPT_PATH, rendered);
    process.stdout.write("replay receipt updated\n");
  } else if (mode === "--stdout") {
    process.stdout.write(rendered);
  } else if (mode === "--check") {
    const committed = readReplayReceiptState(RECEIPT_PATH);
    const assessment = assessReplayReceiptState(committed, rendered);
    if (assessment.stdout) process.stdout.write(assessment.stdout);
    if (assessment.stderr) process.stderr.write(assessment.stderr);
    if (!assessment.matched) process.exitCode = 1;
  } else {
    process.stderr.write(
      "usage: node scripts/replay-receipt.mjs [--check|--write|--stdout|--package]\n"
    );
    process.exitCode = 2;
  }
}
