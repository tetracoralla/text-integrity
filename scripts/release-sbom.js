import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const CARGO_MANIFEST = path.join(ROOT, "native", "Cargo.toml");
const CARGO_LOCK = path.join(ROOT, "native", "Cargo.lock");
const WASM_MANIFEST = path.join(ROOT, "wasm", "MANIFEST.json");
const WASM_MODULE = path.join(ROOT, "wasm", "text_integrity_reference.wasm");
const TARGET = "wasm32-unknown-unknown";
const REQUIRED_CARGO_COMPONENTS = Object.freeze([
  "idna", "idna_adapter", "serde", "serde_json", "sha2",
  "unicode-bidi", "unicode-normalization", "unicode-segmentation"
]);

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function cargoRef(package_) {
  return `pkg:cargo/${encodeURIComponent(package_.name)}@${encodeURIComponent(package_.version)}`;
}

function compareCodeUnits(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function parseCargoLock(value) {
  const checksums = new Map();
  for (const section of value.split(/\n\[\[package\]\]\n/u).slice(1)) {
    const name = section.match(/^name = "([^"]+)"$/mu)?.[1];
    const version = section.match(/^version = "([^"]+)"$/mu)?.[1];
    const checksum = section.match(/^checksum = "([0-9a-f]{64})"$/mu)?.[1];
    if (name !== undefined && version !== undefined && checksum !== undefined) {
      checksums.set(`${name}@${version}`, checksum);
    }
  }
  return checksums;
}

function cargoMetadata() {
  const child = spawnSync("cargo", [
    "metadata", "--manifest-path", CARGO_MANIFEST, "--locked", "--format-version", "1",
    "--filter-platform", TARGET
  ], {
    cwd: ROOT,
    env: { ...process.env, RUSTUP_TOOLCHAIN: process.env.RUSTUP_TOOLCHAIN ?? "1.89.0" },
    encoding: "utf8",
    maxBuffer: 32 << 20
  });
  if (child.status !== 0) {
    throw new Error(child.stderr || child.stdout || "cargo metadata failed");
  }
  return JSON.parse(child.stdout);
}

function isArtifactDependency(edge) {
  return edge.dep_kinds.length === 0 || edge.dep_kinds.some(({ kind }) => kind !== "dev");
}

function artifactClosure(metadata) {
  const nodes = new Map(metadata.resolve.nodes.map((node) => [node.id, node]));
  const reachable = new Set();
  const pending = [metadata.resolve.root];
  while (pending.length > 0) {
    const id = pending.pop();
    if (reachable.has(id)) continue;
    reachable.add(id);
    for (const edge of nodes.get(id)?.deps ?? []) {
      if (isArtifactDependency(edge)) pending.push(edge.pkg);
    }
  }
  return { nodes, reachable };
}

function componentFor(package_, checksums) {
  const checksum = checksums.get(`${package_.name}@${package_.version}`);
  return {
    type: "library",
    "bom-ref": cargoRef(package_),
    name: package_.name,
    version: package_.version,
    ...(package_.license === null ? {} : { licenses: [{ expression: package_.license }] }),
    purl: cargoRef(package_),
    ...(checksum === undefined ? {} : { hashes: [{ alg: "SHA-256", content: checksum }] }),
    ...(package_.source === null ? {} : {
      externalReferences: [{
        type: "distribution",
        url: `https://crates.io/api/v1/crates/${encodeURIComponent(package_.name)}/${encodeURIComponent(package_.version)}/download`
      }]
    })
  };
}

export function generateCargoWasmSbom() {
  const packageManifest = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const wasmManifest = JSON.parse(readFileSync(WASM_MANIFEST, "utf8"));
  const wasmBytes = readFileSync(WASM_MODULE);
  const lockBytes = readFileSync(CARGO_LOCK);
  const lockSha256 = sha256(lockBytes);
  const wasmSha256 = sha256(wasmBytes);
  if (wasmManifest.cargoLockSha256 !== lockSha256
    || wasmManifest.wasm?.bytes !== wasmBytes.length
    || wasmManifest.wasm?.sha256 !== wasmSha256
    || wasmManifest.target !== TARGET) {
    throw new Error("packaged WASM manifest is not bound to the current Cargo lock and module bytes");
  }

  const metadata = cargoMetadata();
  const packages = new Map(metadata.packages.map((package_) => [package_.id, package_]));
  const { nodes, reachable } = artifactClosure(metadata);
  const checksums = parseCargoLock(lockBytes.toString("utf8"));
  const includedPackages = [...reachable]
    .map((id) => packages.get(id))
    .filter((package_) => package_ !== undefined)
    .sort((left, right) => compareCodeUnits(cargoRef(left), cargoRef(right)));
  const rootPackage = packages.get(metadata.resolve.root);
  if (rootPackage === undefined) throw new Error("cargo metadata did not identify the root package");

  const wasmRef = `urn:text-integrity:reference-wasm:${wasmSha256}`;
  const components = includedPackages.map((package_) => componentFor(package_, checksums));
  const dependencies = [{ ref: wasmRef, dependsOn: [cargoRef(rootPackage)] }];
  for (const package_ of includedPackages) {
    const dependsOn = (nodes.get(package_.id)?.deps ?? [])
      .filter((edge) => isArtifactDependency(edge) && reachable.has(edge.pkg))
      .map((edge) => cargoRef(packages.get(edge.pkg)))
      .sort();
    dependencies.push({ ref: cargoRef(package_), dependsOn });
  }

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      tools: {
        components: [{
          type: "application",
          name: "text-integrity Cargo/WASM SBOM generator",
          version: packageManifest.version
        }]
      },
      component: {
        type: "library",
        "bom-ref": wasmRef,
        name: "text-integrity-reference-wasm",
        version: packageManifest.version,
        hashes: [{ alg: "SHA-256", content: wasmSha256 }],
        properties: [
          { name: "text-integrity:wasm:target", value: TARGET },
          { name: "text-integrity:cargo:root", value: `${rootPackage.name}@${rootPackage.version}` },
          { name: "text-integrity:cargo:lockSha256", value: lockSha256 },
          { name: "text-integrity:wasm:sourceSha256", value: wasmManifest.sourceSha256 }
        ]
      }
    },
    components,
    dependencies,
    compositions: [{ aggregate: "complete", assemblies: [wasmRef] }]
  };
}

function validateDependencyReferences(bom) {
  const refs = new Set([
    bom.metadata?.component?.["bom-ref"],
    ...(bom.components ?? []).map((component) => component["bom-ref"])
  ]);
  for (const dependency of bom.dependencies ?? []) {
    if (!refs.has(dependency.ref)
      || dependency.dependsOn.some((reference) => !refs.has(reference))) {
      throw new Error("SBOM dependency graph contains an unknown component reference");
    }
  }
}

function validateCycloneDx(bom, label) {
  if (bom?.bomFormat !== "CycloneDX" || typeof bom.specVersion !== "string"
    || !Array.isArray(bom.components) || !Array.isArray(bom.dependencies)) {
    throw new Error(`${label} is not a complete CycloneDX JSON document`);
  }
  validateDependencyReferences(bom);
}

export function validateNpmSbom(bom) {
  validateCycloneDx(bom, "npm SBOM");
  const names = new Set(bom.components.map((component) => component.name));
  for (const name of ["punycode", "tr46"]) {
    if (!names.has(name)) throw new Error(`npm SBOM is missing ${name}`);
  }
  return { componentCount: bom.components.length };
}

export function validateCargoWasmSbom(bom) {
  validateCycloneDx(bom, "Cargo/WASM SBOM");
  const expected = generateCargoWasmSbom();
  if (JSON.stringify(bom) !== JSON.stringify(expected)) {
    throw new Error("Cargo/WASM SBOM does not match the current locked artifact dependency graph");
  }
  const names = new Set(bom.components.map((component) => component.name));
  for (const name of REQUIRED_CARGO_COMPONENTS) {
    if (!names.has(name)) throw new Error(`Cargo/WASM SBOM is missing ${name}`);
  }
  return { componentCount: bom.components.length };
}
