import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = new URL("../", import.meta.url);
const ROOT_PATH = fileURLToPath(ROOT);
const packageManifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const pluginManifest = JSON.parse(readFileSync(new URL("../.codex-plugin/plugin.json", import.meta.url), "utf8"));
const mcpManifest = JSON.parse(readFileSync(new URL("../.mcp.json", import.meta.url), "utf8"));
const unicodeManifest = JSON.parse(readFileSync(new URL("../vendor/unicode/17.0.0/MANIFEST.json", import.meta.url), "utf8"));
const conformanceManifest = JSON.parse(readFileSync(new URL("../vendor/unicode/17.0.0/CONFORMANCE_MANIFEST.json", import.meta.url), "utf8"));
const bidiManifest = JSON.parse(readFileSync(new URL("../vendor/bidi-js-unicode17/MANIFEST.json", import.meta.url), "utf8"));
const { VERSION } = await import("../src/version.js");

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

const pack = spawnSync("npm", ["pack", "--dry-run", "--json"], { cwd: ROOT, encoding: "utf8" });
if (pack.status !== 0) {
  process.stderr.write(pack.stderr);
  process.exit(pack.status ?? 1);
}
const packageFiles = JSON.parse(pack.stdout)[0].files.map((entry) => entry.path);
for (const required of [
  ".codex-plugin/plugin.json",
  ".mcp.json",
  "LICENSE",
  "NOTICE",
  "THIRD_PARTY_NOTICES.md",
  "src/contracts.js",
  "src/output-schemas.js",
  "src/core/errors.js",
  "src/core/limits.js",
  "src/core/operations.js",
  "src/core/bidi.js",
  "src/core/collation.js",
  "src/core/difference.js",
  "src/core/protocol.js",
  "src/core/security.js",
  "src/core/source-diagnostics.js",
  "src/core/text-position.js",
  "src/core/unicode-security-data.js",
  "src/library.js",
  "src/mcp/server.js",
  "src/mcp/summary.js",
  "src/version.js",
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
  const packed = spawnSync("npm", ["pack", "--json", "--pack-destination", smokeRoot], {
    cwd: ROOT,
    encoding: "utf8"
  });
  if (packed.status !== 0) {
    process.stderr.write(packed.stderr);
    process.exit(packed.status ?? 1);
  }
  const filename = JSON.parse(packed.stdout)[0].filename;
  const tarball = path.join(smokeRoot, filename);
  const project = path.join(smokeRoot, "consumer");
  mkdirSync(project);
  writeFileSync(path.join(project, "package.json"), '{"name":"text-integrity-smoke","private":true,"type":"module"}\n');
  const installed = spawnSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], {
    cwd: project,
    encoding: "utf8"
  });
  if (installed.status !== 0) {
    process.stderr.write(installed.stderr);
    process.exit(installed.status ?? 1);
  }

  const librarySmoke = spawnSync(process.execPath, ["--input-type=module", "-e", `
    import { executeOperation, LIBRARY_INFO } from "text-integrity";
    const result = executeOperation("normalize", { text: "e\\u0301", form: "NFC" });
    if (result.normalized !== "é" || LIBRARY_INFO.version !== ${JSON.stringify(VERSION)}) process.exit(1);
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
        name: "text_normalize",
        arguments: { text: "e\u0301", form: "NFC" }
      }
    })}\n`
  });
  const mcpValue = mcpSmoke.status === 0 ? JSON.parse(mcpSmoke.stdout) : null;
  if (mcpSmoke.status !== 0 || mcpValue?.result?.structuredContent?.normalized !== "é") {
    process.stderr.write(mcpSmoke.stderr || "installed MCP smoke failed\n");
    process.exit(mcpSmoke.status || 1);
  }
} finally {
  rmSync(smokeRoot, { recursive: true, force: true });
}

process.stdout.write("check: syntax, full test suite, compact-data reproducibility, package inventory, and installed artifact smoke passed\n");
