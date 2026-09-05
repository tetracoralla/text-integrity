import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { nativeSourceDigest } from "./native-source-identity.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const NATIVE_ROOT = path.join(ROOT, "native");
const PACKAGE_ROOT = path.join(ROOT, "wasm");
const PACKAGE_WASM = path.join(PACKAGE_ROOT, "text_integrity_reference.wasm");
const PACKAGE_MANIFEST = path.join(PACKAGE_ROOT, "MANIFEST.json");
const BUILT_WASM = path.join(
  NATIVE_ROOT,
  "target",
  "wasm32-unknown-unknown",
  "release",
  "text_integrity_reference.wasm"
);
const TOOLCHAIN = "1.89.0";
const BUILD_HOST = "x86_64-unknown-linux-gnu";
const mode = process.argv[2] ?? "--check";
if (!new Set(["--check", "--write"]).has(mode)) {
  process.stderr.write("usage: node scripts/build-independent-wasm.mjs [--check|--write]\n");
  process.exit(2);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

// Panic locations retain Cargo registry paths even in a stripped release.
// Normalize both source roots so another machine reproduces the same bytes
// without embedding its account name or accepting ambient compiler flags.
const cargoHome = realpathSync(process.env.CARGO_HOME ?? path.join(homedir(), ".cargo"));
const environment = {
  ...process.env,
  RUSTUP_TOOLCHAIN: TOOLCHAIN,
  CARGO_ENCODED_RUSTFLAGS: [
    `--remap-path-prefix=${cargoHome}=/cargo-home`,
    `--remap-path-prefix=${realpathSync(ROOT)}=/text-integrity`
  ].join("\x1f")
};
delete environment.RUSTFLAGS;
const compiler = spawnSync("rustc", ["--verbose", "--version"], { cwd: ROOT, env: environment, encoding: "utf8" });
const buildHost = compiler.stdout?.match(/^host: (.+)$/m)?.[1];
if (compiler.status !== 0 || buildHost !== BUILD_HOST) {
  process.stderr.write(`Release WASM byte reproduction requires Rust ${TOOLCHAIN} on ${BUILD_HOST}; observed ${buildHost ?? "unavailable"}. Use the Linux release environment. Native/WASM semantic checks remain available on other hosts.\n`);
  process.exit(2);
}
const build = spawnSync(
  "cargo",
  ["build", "--manifest-path", path.join(NATIVE_ROOT, "Cargo.toml"), "--locked", "--release", "--target", "wasm32-unknown-unknown"],
  { cwd: ROOT, env: environment, encoding: "utf8", maxBuffer: 16 << 20 }
);
if (build.status !== 0) {
  process.stderr.write(build.stdout);
  process.stderr.write(build.stderr);
  process.exit(build.status ?? 1);
}
const rustc = spawnSync("rustc", ["--version"], { cwd: ROOT, env: environment, encoding: "utf8" });
if (rustc.status !== 0) process.exit(rustc.status ?? 1);
const bytes = readFileSync(BUILT_WASM);
const module = new WebAssembly.Module(bytes);
const imports = WebAssembly.Module.imports(module);
const exports = WebAssembly.Module.exports(module).map(({ name, kind }) => ({ name, kind }));
if (imports.length !== 0) {
  process.stderr.write(`independent WASM must remain import-free: ${JSON.stringify(imports)}\n`);
  process.exit(1);
}
const instance = new WebAssembly.Instance(module, {});
const rawAbi = {
  version: instance.exports.ti_abi_version(),
  maxInputBytes: instance.exports.ti_max_input_len(),
  maxBatchRequests: instance.exports.ti_max_batch_len(),
  maxResultBytes: instance.exports.ti_max_result_len(),
  workLimits: {
    differenceAlignmentCells: instance.exports.ti_max_difference_alignment_cells(),
    sourceDiagnosticUnits: instance.exports.ti_max_source_diagnostic_units(),
    uts46PunycodeScanUnits: instance.exports.ti_max_uts46_punycode_scan_units()
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
};
if (rawAbi.version !== 2
  || rawAbi.maxInputBytes !== 1048576
  || rawAbi.maxBatchRequests !== 1024
  || rawAbi.maxResultBytes !== 8388608
  || rawAbi.workLimits.differenceAlignmentCells !== 33554432
  || rawAbi.workLimits.sourceDiagnosticUnits !== 1576960
  || rawAbi.workLimits.uts46PunycodeScanUnits !== 16777216) {
  process.stderr.write(`independent WASM exposes an unsupported raw ABI: ${JSON.stringify(rawAbi)}\n`);
  process.exit(1);
}
const manifest = {
  schemaVersion: "text-integrity.reference-wasm/3",
  rustToolchain: `${TOOLCHAIN}-${BUILD_HOST}`,
  rustc: rustc.stdout.trim(),
  target: "wasm32-unknown-unknown",
  sourceSha256: nativeSourceDigest(NATIVE_ROOT),
  cargoLockSha256: sha256(readFileSync(path.join(NATIVE_ROOT, "Cargo.lock"))),
  rawAbi,
  wasm: {
    path: "text_integrity_reference.wasm",
    bytes: bytes.length,
    sha256: sha256(bytes),
    imports,
    exports
  }
};
const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);

if (mode === "--write") {
  mkdirSync(PACKAGE_ROOT, { recursive: true });
  writeFileSync(PACKAGE_WASM, bytes);
  writeFileSync(PACKAGE_MANIFEST, manifestBytes);
  process.stdout.write(`independent WASM package artifact updated (${bytes.length} bytes)\n`);
} else {
  let packagedWasm;
  let packagedManifest;
  try {
    packagedWasm = readFileSync(PACKAGE_WASM);
    packagedManifest = readFileSync(PACKAGE_MANIFEST);
  } catch {
    process.stderr.write("independent WASM package artifact is missing; run with --write\n");
    process.exit(1);
  }
  if (!packagedWasm.equals(bytes) || !packagedManifest.equals(manifestBytes)) {
    let packaged;
    try {
      packaged = JSON.parse(packagedManifest.toString("utf8"));
    } catch {
      packaged = { invalidManifest: true };
    }
    process.stderr.write(`${JSON.stringify({
      error: "independent WASM package artifact does not reproduce from pinned source/toolchain",
      wasmBytesMatch: packagedWasm.equals(bytes),
      packaged: {
        sourceSha256: packaged.sourceSha256,
        cargoLockSha256: packaged.cargoLockSha256,
        wasm: packaged.wasm && { bytes: packaged.wasm.bytes, sha256: packaged.wasm.sha256 }
      },
      rebuilt: {
        sourceSha256: manifest.sourceSha256,
        cargoLockSha256: manifest.cargoLockSha256,
        wasm: { bytes: manifest.wasm.bytes, sha256: manifest.wasm.sha256 }
      }
    })}\n`);
    process.exit(1);
  }
  process.stdout.write(`independent WASM package artifact matches (${bytes.length} bytes)\n`);
}
