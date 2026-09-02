import { copyFile, cp, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const stageInput = process.env.OPENADAM_COMPONENT_STAGE;
if (typeof stageInput !== "string" || stageInput.length === 0) {
  throw new Error("OPENADAM_COMPONENT_STAGE is required; run this command through openadam-dev pack");
}
const stage = path.resolve(stageInput);
const stageInfo = await stat(stage);
if (!stageInfo.isDirectory() || (await readdir(stage)).length !== 0) {
  throw new Error("OPENADAM_COMPONENT_STAGE must be one empty directory");
}

function runNpm(args) {
  if (process.env.npm_execpath) {
    return spawnSync(process.execPath, [process.env.npm_execpath, ...args], {
      cwd: ROOT, encoding: "utf8", maxBuffer: 16 << 20
    });
  }
  return spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", args, {
    cwd: ROOT, encoding: "utf8", maxBuffer: 16 << 20, shell: process.platform === "win32"
  });
}

async function copy(source, destination) {
  await mkdir(path.dirname(destination), { recursive: true });
  await copyFile(source, destination);
}

const packageManifest = JSON.parse(await readFile(path.join(ROOT, "package.json"), "utf8"));
const packageLock = JSON.parse(await readFile(path.join(ROOT, "package-lock.json"), "utf8"));
const packed = runNpm(["pack", "--dry-run", "--json"]);
if (packed.status !== 0) throw new Error(packed.stderr || packed.stdout || "npm pack dry run failed");
const packageFiles = JSON.parse(packed.stdout)[0]?.files;
if (!Array.isArray(packageFiles) || packageFiles.length === 0) throw new Error("npm pack returned no package files");

const marketplaceRoot = path.join(stage, "marketplace");
const pluginRoot = path.join(marketplaceRoot, "plugins", "text-integrity");
for (const { path: relativePath } of packageFiles) {
  await copy(path.join(ROOT, relativePath), path.join(pluginRoot, relativePath));
}

for (const [name, requestedVersion] of Object.entries(packageManifest.dependencies ?? {})) {
  const installedRoot = path.join(ROOT, "node_modules", name);
  const installedManifest = JSON.parse(await readFile(path.join(installedRoot, "package.json"), "utf8"));
  const lockedVersion = packageLock.packages?.[`node_modules/${name}`]?.version;
  if (installedManifest.name !== name || installedManifest.version !== requestedVersion || lockedVersion !== requestedVersion) {
    throw new Error(`installed dependency ${name} does not match its exact package and lock version`);
  }
  await cp(installedRoot, path.join(pluginRoot, "node_modules", name), {
    recursive: true,
    preserveTimestamps: false
  });
}

await mkdir(path.join(marketplaceRoot, ".agents", "plugins"), { recursive: true });
await writeFile(path.join(marketplaceRoot, ".agents", "plugins", "marketplace.json"), `${JSON.stringify({
  name: "private-text-integrity",
  interface: { displayName: "Text Integrity" },
  plugins: [{
    name: "text-integrity",
    source: { source: "local", path: "./plugins/text-integrity" },
    policy: { installation: "AVAILABLE", authentication: "ON_INSTALL" },
    category: "Developer Tools"
  }]
}, null, 2)}\n`);

for (const relativePath of [
  "LICENSE",
  "NOTICE",
  "THIRD_PARTY_NOTICES.md",
  "packaging/agent-host-sbom.spdx.json"
]) {
  await copy(path.join(ROOT, relativePath), path.join(stage, relativePath));
}

process.stdout.write("Staged Text Integrity Agent Host component payload\n");
