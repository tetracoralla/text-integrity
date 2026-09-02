import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { generateCargoWasmSbom } from "./release-sbom.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const OUTPUT = path.join(ROOT, "packaging", "agent-host-sbom.spdx.json");
const packageManifest = JSON.parse(readFileSync(path.join(ROOT, "package.json"), "utf8"));

function runNpmSbom() {
  const args = ["sbom", "--sbom-format", "cyclonedx"];
  const child = process.env.npm_execpath
    ? spawnSync(process.execPath, [process.env.npm_execpath, ...args], { cwd: ROOT, encoding: "utf8", maxBuffer: 16 << 20 })
    : spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", args, {
      cwd: ROOT, encoding: "utf8", maxBuffer: 16 << 20, shell: process.platform === "win32"
    });
  if (child.status !== 0) throw new Error(child.stderr || child.stdout || "npm sbom failed");
  return JSON.parse(child.stdout);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function spdxId(name, reference) {
  const safeName = name.replaceAll(/[^A-Za-z0-9.-]/gu, "-").replaceAll(/-+/gu, "-");
  return `SPDXRef-Package-${safeName}-${sha256(reference).slice(0, 12)}`;
}

function licenseExpression(component) {
  const license = component.licenses?.[0];
  return license?.expression ?? license?.license?.id ?? "NOASSERTION";
}

function checksum(component) {
  const digest = component.hashes?.find(({ alg }) => alg === "SHA-256");
  return digest === undefined ? [] : [{ algorithm: "SHA256", checksumValue: digest.content }];
}

function distribution(component) {
  return component.externalReferences?.find(({ type }) => type === "distribution")?.url ?? "NOASSERTION";
}

function spdxPackage(component) {
  const reference = component["bom-ref"];
  const purl = component.purl;
  return {
    name: component.name,
    SPDXID: spdxId(component.name, reference),
    versionInfo: component.version,
    downloadLocation: distribution(component),
    filesAnalyzed: false,
    licenseConcluded: licenseExpression(component),
    licenseDeclared: licenseExpression(component),
    copyrightText: "NOASSERTION",
    checksums: checksum(component),
    ...(purl === undefined ? {} : {
      externalRefs: [{
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: purl
      }]
    })
  };
}

function createdAt() {
  if (!existsSync(OUTPUT)) return new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
  try {
    const existing = JSON.parse(readFileSync(OUTPUT, "utf8"));
    if (existing.name === `text-integrity-agent-host-${packageManifest.version}`
      && typeof existing.creationInfo?.created === "string") return existing.creationInfo.created;
  } catch {
    // A malformed existing file is replaced only through the explicit --write route.
  }
  return new Date().toISOString().replace(/\.\d{3}Z$/u, "Z");
}

function generate() {
  const npm = runNpmSbom();
  const cargo = generateCargoWasmSbom();
  const rootReference = `urn:openadam:agent-host-component:text-integrity:${packageManifest.version}`;
  const rootPackage = {
    name: "text-integrity-agent-host",
    SPDXID: spdxId("text-integrity-agent-host", rootReference),
    versionInfo: packageManifest.version,
    downloadLocation: "NOASSERTION",
    filesAnalyzed: false,
    licenseConcluded: packageManifest.license,
    licenseDeclared: packageManifest.license,
    copyrightText: "NOASSERTION"
  };
  const cyclonedxComponents = [
    npm.metadata.component,
    cargo.metadata.component,
    ...npm.components,
    ...cargo.components
  ];
  const referenceToSpdx = new Map(cyclonedxComponents.map((component) => [
    component["bom-ref"],
    spdxId(component.name, component["bom-ref"])
  ]));
  if (referenceToSpdx.size !== cyclonedxComponents.length) {
    throw new Error("Agent Host SBOM contains duplicate component references");
  }
  const packages = [rootPackage, ...cyclonedxComponents.map(spdxPackage)]
    .sort((left, right) => left.SPDXID.localeCompare(right.SPDXID, "en"));
  const relationships = [{
    spdxElementId: "SPDXRef-DOCUMENT",
    relationshipType: "DESCRIBES",
    relatedSpdxElement: rootPackage.SPDXID
  }, {
    spdxElementId: rootPackage.SPDXID,
    relationshipType: "DEPENDS_ON",
    relatedSpdxElement: referenceToSpdx.get(npm.metadata.component["bom-ref"])
  }, {
    spdxElementId: rootPackage.SPDXID,
    relationshipType: "DEPENDS_ON",
    relatedSpdxElement: referenceToSpdx.get(cargo.metadata.component["bom-ref"])
  }];
  for (const dependency of [...npm.dependencies, ...cargo.dependencies]) {
    const source = referenceToSpdx.get(dependency.ref);
    if (source === undefined) throw new Error("Agent Host SBOM contains an unknown dependency source");
    for (const target of dependency.dependsOn) {
      const related = referenceToSpdx.get(target);
      if (related === undefined) throw new Error("Agent Host SBOM contains an unknown dependency target");
      relationships.push({
        spdxElementId: source,
        relationshipType: "DEPENDS_ON",
        relatedSpdxElement: related
      });
    }
  }
  relationships.sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right), "en"));
  const identity = sha256(Buffer.concat([
    readFileSync(path.join(ROOT, "package-lock.json")),
    readFileSync(path.join(ROOT, "native", "Cargo.lock")),
    readFileSync(path.join(ROOT, "wasm", "MANIFEST.json"))
  ]));
  return {
    spdxVersion: "SPDX-2.3",
    dataLicense: "CC0-1.0",
    SPDXID: "SPDXRef-DOCUMENT",
    name: `text-integrity-agent-host-${packageManifest.version}`,
    documentNamespace: `https://github.com/tetracoralla/text-integrity/sbom/agent-host/${packageManifest.version}/${identity}`,
    creationInfo: {
      created: createdAt(),
      creators: [`Tool: text-integrity Agent Host SBOM generator-${packageManifest.version}`]
    },
    packages,
    relationships
  };
}

const rendered = `${JSON.stringify(generate(), null, 2)}\n`;
if (process.argv.includes("--write")) {
  const temporary = `${OUTPUT}.${process.pid}.tmp`;
  writeFileSync(temporary, rendered);
  renameSync(temporary, OUTPUT);
  process.stdout.write(`wrote ${path.relative(ROOT, OUTPUT)}\n`);
} else if (process.argv.includes("--check")) {
  if (readFileSync(OUTPUT, "utf8") !== rendered) {
    process.stderr.write("Agent Host SBOM is stale; run npm run sbom:agent-host:write\n");
    process.exitCode = 1;
  }
} else {
  process.stdout.write(rendered);
}
