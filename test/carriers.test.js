import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { createUiServer } from "../src/ui/server.js";
import { createMcpSession, runMcpServer } from "../src/mcp/server.js";
import { TOOL_BY_NAME, TOOL_DEFINITIONS } from "../src/contracts.js";
import { executeOperation } from "../src/core/operations.js";
import { LIMITS } from "../src/core/limits.js";
import { analyzeNamespaceIntegrity } from "../src/core/namespace-integrity.js";
import { MCP_OUTPUT_SCHEMAS } from "../src/mcp-output-schemas.js";
import { OUTPUT_SCHEMAS } from "../src/output-schemas.js";
import { NAMESPACE_INPUT_SCHEMA } from "../src/namespace-contract.js";
import { createTranscodeSourceDrafts } from "../src/ui/public/transcode-source-drafts.js";
import {
  PUBLIC_RESULT_SCHEMA_VERSION,
  RESULT_SCHEMA_RESOURCE_LIST,
  RESULT_SCHEMA_RESOURCES
} from "../src/result-contract.js";

const ROOT = new URL("../", import.meta.url);
const COLLATION_FLAGS = [
  "--locale", "en", "--usage", "sort", "--sensitivity", "variant",
  "--ignore-punctuation", "false", "--numeric", "false", "--case-first", "false",
  "--locale-matcher", "best fit", "--collation", "default"
];
const COLLATION_OPTIONS = Object.freeze({
  usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
  caseFirst: "false", localeMatcher: "best fit", collation: "default"
});

test("transcode source modes preserve separate compatible drafts", () => {
  const drafts = createTranscodeSourceDrafts("text", "hello");
  assert.equal(drafts.switchTo("bytes", "hello"), "");
  assert.equal(drafts.switchTo("text", "72, 105"), "hello");
  assert.equal(drafts.switchTo("bytes", "updated"), "72, 105");
  assert.throws(() => drafts.switchTo("path", "ignored"), TypeError);
});

test("the tag release binds native/WASM source and both dependency ecosystems", () => {
  const packageManifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const releaseWorkflow = readFileSync(new URL("../.github/workflows/release.yml", import.meta.url), "utf8");
  assert.match(packageManifest.scripts["release:check"], /check:independent/u);
  assert.match(packageManifest.scripts["release:check"], /bench\.mjs --slo/u);
  assert.match(packageManifest.scripts["release:check"], /sbom:check/u);
  assert.match(releaseWorkflow, /npm run release:check/u);
  assert.match(releaseWorkflow, /text-integrity-npm-sbom\.cdx\.json/u);
  assert.match(releaseWorkflow, /text-integrity-cargo-wasm-sbom\.cdx\.json/u);
  assert.equal((releaseWorkflow.match(/sbom-path:/gu) ?? []).length, 2);
});

test("the Agent Host component stages the exact packed runtime and product Skill", () => {
  const stage = mkdtempSync(path.join(tmpdir(), "text-integrity-agent-host-test-"));
  try {
    const packaged = spawnSync(process.execPath, ["scripts/package-agent-host-component.mjs"], {
      cwd: ROOT,
      env: { ...process.env, OPENADAM_COMPONENT_STAGE: stage },
      encoding: "utf8",
      maxBuffer: 16 << 20
    });
    assert.equal(packaged.status, 0, packaged.stderr);
    const pluginRoot = path.join(stage, "marketplace", "plugins", "text-integrity");
    for (const relativePath of [
      ".codex-plugin/plugin.json",
      ".mcp.json",
      "skills/text-integrity/SKILL.md",
      "bin/text-integrity-mcp.js",
      "src/transport-json.js",
      "node_modules/punycode/package.json",
      "node_modules/tr46/package.json"
    ]) {
      assert.equal(existsSync(path.join(pluginRoot, relativePath)), true, relativePath);
    }
    const componentSbomPath = path.join(stage, "packaging", "agent-host-sbom.spdx.json");
    assert.equal(existsSync(componentSbomPath), true);
    const componentSbom = JSON.parse(readFileSync(componentSbomPath, "utf8"));
    assert.equal(componentSbom.spdxVersion, "SPDX-2.3");
    assert.equal(componentSbom.dataLicense, "CC0-1.0");
    assert.equal(componentSbom.name, "text-integrity-agent-host-1.0.0");
    const componentNames = new Set(componentSbom.packages.map((component) => component.name));
    for (const name of ["text-integrity", "text-integrity-reference-wasm", "punycode", "tr46", "serde", "unicode-normalization"]) {
      assert.equal(componentNames.has(name), true, `component SBOM must include ${name}`);
    }
    const componentRefs = new Set(componentSbom.packages.map((component) => component.SPDXID));
    for (const relationship of componentSbom.relationships) {
      if (relationship.spdxElementId === "SPDXRef-DOCUMENT") continue;
      assert.equal(componentRefs.has(relationship.spdxElementId), true, relationship.spdxElementId);
      assert.equal(componentRefs.has(relationship.relatedSpdxElement), true, relationship.relatedSpdxElement);
    }
    assert.equal(existsSync(path.join(
      pluginRoot,
      "vendor",
      "unicode",
      "17.0.0",
      "conformance",
      "NormalizationTest.txt.gz"
    )), false);

    const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
    const runtime = spawnSync(process.execPath, [path.join(pluginRoot, "bin", "text-integrity-mcp.js")], {
      cwd: pluginRoot,
      encoding: "utf8",
      input: [
        { jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: meta } },
        {
          jsonrpc: "2.0", id: 2, method: "tools/call",
          params: { _meta: meta, name: "text_inspect", arguments: { text: "A👩‍💻é" } }
        },
        {
          jsonrpc: "2.0", id: 3, method: "tools/call",
          params: { _meta: meta, name: "text_inspect", arguments: {} }
        }
      ].map(JSON.stringify).join("\n") + "\n",
      maxBuffer: 16 << 20
    });
    assert.equal(runtime.status, 0, runtime.stderr);
    const messages = runtime.stdout.trim().split("\n").map(JSON.parse);
    assert.equal(messages[0].result.tools.length, 8);
    assert.equal(messages[1].result.structuredContent.counts.graphemes, 3);
    assert.equal(messages[2].error.code, -32602);
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
});

function cli(args, input) {
  return spawnSync(process.execPath, ["bin/text-integrity.js", ...args], { cwd: ROOT, encoding: "utf8", input, maxBuffer: 1 << 20 });
}

function invalidUtf8Json(prefix, suffix) {
  return Buffer.concat([Buffer.from(prefix), Buffer.from([0xff]), Buffer.from(suffix)]);
}

function validateSchemaNode(schema, path = "$", requireClosedObjects = false) {
  assert.notDeepEqual(schema, {}, `${path} must not be an unconstrained schema`);
  if (schema.oneOf) {
    for (const [index, branch] of schema.oneOf.entries()) {
      validateSchemaNode(branch, `${path}.oneOf[${index}]`, requireClosedObjects);
    }
  }
  if (schema.type === "object") {
    if (requireClosedObjects) {
      assert.equal(schema.additionalProperties, false, `${path} must reject unknown object fields`);
      assert.ok(Object.keys(schema.properties ?? {}).length > 0, `${path} must declare its object properties`);
    }
    for (const [name, property] of Object.entries(schema.properties ?? {})) {
      validateSchemaNode(property, `${path}.properties.${name}`, requireClosedObjects);
    }
  }
  if (schema.type === "array") {
    validateSchemaNode(schema.items, `${path}.items`, requireClosedObjects);
    if (schema.contains) validateSchemaNode(schema.contains, `${path}.contains`, requireClosedObjects);
  }
}

function assertDeepFrozen(value, path = "$", seen = new WeakSet()) {
  if (value === null || (typeof value !== "object" && typeof value !== "function") || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true, `${path} must be frozen`);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && Object.hasOwn(descriptor, "value")) {
      assertDeepFrozen(descriptor.value, `${path}.${String(key)}`, seen);
    }
  }
}

function valueMatchesSchema(value, schema) {
  if (schema.oneOf) return schema.oneOf.filter((branch) => valueMatchesSchema(value, branch)).length === 1;
  if (Object.hasOwn(schema, "const") && value !== schema.const) return false;
  if (schema.enum && !schema.enum.includes(value)) return false;
  if (schema.type === "null") return value === null;
  if (schema.type === "string") {
    return typeof value === "string"
      && (schema.minLength === undefined || value.length >= schema.minLength)
      && (schema.maxLength === undefined || value.length <= schema.maxLength);
  }
  if (schema.type === "boolean") return typeof value === "boolean";
  if (schema.type === "integer") {
    return Number.isInteger(value)
      && (schema.minimum === undefined || value >= schema.minimum)
      && (schema.maximum === undefined || value <= schema.maximum);
  }
  if (schema.type === "number") return typeof value === "number" && Number.isFinite(value);
  if (schema.type === "array") {
    return Array.isArray(value)
      && (schema.minItems === undefined || value.length >= schema.minItems)
      && (schema.maxItems === undefined || value.length <= schema.maxItems)
      && (schema.uniqueItems !== true || new Set(value.map((item) => JSON.stringify(item))).size === value.length)
      && (schema.contains === undefined || value.some((item) => valueMatchesSchema(item, schema.contains)))
      && value.every((item) => valueMatchesSchema(item, schema.items));
  }
  if (schema.type === "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
    if ((schema.required ?? []).some((name) => !Object.hasOwn(value, name))) return false;
    if (schema.additionalProperties === false
      && Object.keys(value).some((name) => !Object.hasOwn(schema.properties ?? {}, name))) return false;
    return Object.entries(value).every(([name, item]) => {
      const property = schema.properties?.[name];
      return property === undefined || valueMatchesSchema(item, property);
    });
  }
  return true;
}

test("CLI carries all operations, raw JSON, help, schemas, literal -- values, and strict errors", () => {
  const cases = [
    ["inspect", "--text=--literal"],
    ["normalize", "--text", "e\u0301", "--form", "NFC", "--witness-mode", "summary"],
    ["compare", "--left", "A", "--right", "a", ...COLLATION_FLAGS],
    ["explain_difference", "--left", "é", "--right", "e\u0301", ...COLLATION_FLAGS, "--confusable-direction", "LTR", "--witness-mode", "summary"],
    ["index", "--text", "A😀B", "--max-chunk-utf8-bytes", "4"],
    ["security", "--text", "pаypаl", "--mode", "identifier", "--profile", "uts39_general_security", "--comparison", "paypal", "--confusable-direction", "LTR"],
    ["protocol_profile", "--profile", "precis_username_case_mapped", "--action", "enforce", "--text", "User", "--witness-mode", "summary"],
    ["transcode", "--source-kind", "bytes", "--bytes", "[65,0]", "--source-encoding", "utf-16le", "--target-encoding", "utf-8", "--allow-lossy", "false", "--byte-representation", "hex", "--witness-mode", "summary"]
  ];
  for (const args of cases) {
    const child = cli(args);
    assert.equal(child.status, 0, child.stderr);
    assert.equal(JSON.parse(child.stdout).status, "ok");
  }

  const raw = cli(["--json"], '{"operation":"inspect","arguments":{"text":"\\ud800"}}');
  assert.equal(raw.status, 0, raw.stderr);
  assert.equal(JSON.parse(raw.stdout).inputWellFormed, false);
  const invalidUtf8 = cli(["--json"], invalidUtf8Json(
    '{"operation":"inspect","arguments":{"text":"',
    '"}}'
  ));
  assert.equal(invalidUtf8.status, 2);
  assert.equal(JSON.parse(invalidUtf8.stderr).error.code, "INVALID_INPUT");
  assert.match(cli(["--help"]).stdout, /Raw JSON preserves escaped unpaired surrogates/u);
  const schema = JSON.parse(cli(["--schema"]).stdout);
  assert.equal(schema.tools.length, 8);
  assert.equal(schema.publicResultContract, PUBLIC_RESULT_SCHEMA_VERSION);
  assert.equal(schema.strictOutputSchemaResources.length, 9);
  assert.ok(schema.tools.every((tool) => tool.inputSchema && tool.outputSchema));
  const fullSchema = JSON.parse(cli(["--schema-full", "normalize"]).stdout);
  assert.equal(fullSchema.$schema, "https://json-schema.org/draft/2020-12/schema");
  assert.equal(fullSchema["x-text-integrity-contract"], PUBLIC_RESULT_SCHEMA_VERSION);
  validateSchemaNode(fullSchema, "cli.normalize.fullOutputSchema", true);
  const unknownFullSchema = cli(["--schema-full", "missing"]);
  assert.equal(unknownFullSchema.status, 2);
  assert.equal(JSON.parse(unknownFullSchema.stderr).error.code, "UNKNOWN_OPERATION");

  for (const [args, code] of [
    [["transcode", "--source-kind", "bytes", "--bytes", "65,,66", "--source-encoding", "utf-8", "--target-encoding", "utf-8", "--allow-lossy", "false", "--byte-representation", "hex"], "INVALID_INPUT"],
    [["transcode", "--source-kind", "text", "--text", "hello", "--target-encoding", "latin1", "--allow-lossy", "false", "--byte-representation", "hex"], "UNSUPPORTED_ENCODING"]
  ]) {
    const child = cli(args);
    assert.equal(child.status, 2);
    assert.equal(JSON.parse(child.stderr).error.code, code);
  }
});

test("MCP publishes eight direct closed contracts across both protocol eras", () => {
  assert.deepEqual(TOOL_DEFINITIONS.map((tool) => tool.name), [
    "text_inspect", "text_normalize", "text_compare", "text_transcode",
    "text_security_observe", "text_explain_difference", "text_index_map", "text_protocol_profile"
  ]);
  for (const tool of TOOL_DEFINITIONS) {
    assert.ok(tool.outputSchema);
    assert.equal(tool.inputSchema.type, "object");
    assert.equal(tool.outputSchema.type, "object");
    validateSchemaNode(tool.outputSchema, `${tool.name}.outputSchema`);
    const outputBranches = tool.outputSchema.oneOf ?? [tool.outputSchema];
    for (const branch of outputBranches) assert.equal(branch.additionalProperties, false);
    const branches = tool.inputSchema.oneOf ?? [tool.inputSchema];
    for (const branch of branches) assert.equal(branch.additionalProperties, false);
  }

  const legacy = createMcpSession();
  assert.equal(legacy.handleMessage({ jsonrpc: "2.0", id: 1, method: "ping" }).error.code, -32002);
  const initialized = legacy.handleMessage({
    jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "2025-06-18" }
  });
  assert.equal(initialized.result.protocolVersion, "2025-06-18");
  assert.equal(initialized.result.serverInfo.version, "1.0.0");
  assert.equal(legacy.handleMessage({
    jsonrpc: "2.0", id: 3, method: "initialize", params: { protocolVersion: "1999-01-01" }
  }).result.protocolVersion, "2025-11-25");
  const legacyPing = legacy.handleMessage({ jsonrpc: "2.0", id: 4, method: "ping" });
  assert.deepEqual(legacyPing.result, {});
  const listed = legacy.handleMessage({ jsonrpc: "2.0", id: 5, method: "tools/list" });
  assert.equal(listed.result.tools.length, 8);
  assert.ok(Buffer.byteLength(JSON.stringify(listed), "utf8") <= LIMITS.maxToolCatalogBytes);
  const legacyResources = legacy.handleMessage({ jsonrpc: "2.0", id: "resources", method: "resources/list" });
  assert.equal(legacyResources.result.resources.length, 9);
  const legacyNormalizeSchema = legacy.handleMessage({
    jsonrpc: "2.0", id: "normalize-schema", method: "resources/read",
    params: { uri: RESULT_SCHEMA_RESOURCES.normalize.uri }
  });
  assert.equal(
    JSON.parse(legacyNormalizeSchema.result.contents[0].text)["x-text-integrity-contract"],
    PUBLIC_RESULT_SCHEMA_VERSION
  );
  const called = legacy.handleMessage({
    jsonrpc: "2.0", id: 6, method: "tools/call",
    params: { name: "text_normalize", arguments: { text: "e\u0301", form: "NFC" } }
  });
  assert.equal(called.result.isError, false);
  assert.deepEqual(JSON.parse(called.result.content[0].text), called.result.structuredContent);
  const normalizedWitness = legacy.handleMessage({
    jsonrpc: "2.0", id: "normalize-witness", method: "tools/call",
    params: {
      name: "text_normalize",
      arguments: { text: "①A\u0315\u0300", form: "NFKC", witnessMode: "full_required" }
    }
  });
  assert.equal(normalizedWitness.result.isError, false);
  assert.deepEqual(normalizedWitness.result.structuredContent.witness.stages.compositions, [{
    starter: "U+0041", current: "U+0300", composite: "U+00C0", outputIndexCodePoint: 1
  }]);
  const protocolWitness = legacy.handleMessage({
    jsonrpc: "2.0", id: "protocol-witness", method: "tools/call",
    params: {
      name: "text_protocol_profile",
      arguments: {
        profile: "precis_username_case_mapped", action: "enforce", text: "Ｕser",
        witnessMode: "full_required"
      }
    }
  });
  assert.equal(protocolWitness.result.isError, false);
  assert.equal(protocolWitness.result.structuredContent.witness.sides[0].stabilizedAfterPass, 2);
  const differenceWitness = legacy.handleMessage({
    jsonrpc: "2.0", id: "difference-witness", method: "tools/call",
    params: {
      name: "text_explain_difference",
      arguments: {
        left: "e\u0301", right: "é", locale: "en", options: COLLATION_OPTIONS,
        confusableDirection: "LTR", witnessMode: "full_required"
      }
    }
  });
  assert.equal(differenceWitness.result.isError, false);
  assert.equal(differenceWitness.result.structuredContent.witness.transformations.normalization.NFC.leftOutput, "é");
  assert.equal(differenceWitness.result.structuredContent.witness.alignment.codePoint.segments[0].kind, "replace");
  assert.equal(differenceWitness.result.structuredContent.witness.alignment.grapheme.segments[0].kind, "replace");
  const witnessed = legacy.handleMessage({
    jsonrpc: "2.0", id: "legacy-witness", method: "tools/call",
    params: {
      name: "text_transcode",
      arguments: {
        sourceKind: "bytes", bytes: [0x61, 0xe1, 0x80, 0x41, 0x80], sourceEncoding: "utf-8",
        targetEncoding: "utf-8", allowLossy: true, byteRepresentation: "hex", witnessMode: "full_required"
      }
    }
  });
  assert.equal(witnessed.result.isError, false);
  assert.deepEqual(
    witnessed.result.structuredContent.witness.segments
      .filter((segment) => segment.kind === "replacement")
      .map(({ sourceStart, sourceEnd }) => [sourceStart, sourceEnd]),
    [[1, 3], [4, 5]]
  );
  const invalid = legacy.handleMessage({
    jsonrpc: "2.0", id: 7, method: "tools/call",
    params: { name: "text_inspect", arguments: { text: "ok", invented: true } }
  });
  assert.equal(invalid.error.code, -32602);
  const semanticError = legacy.handleMessage({
    jsonrpc: "2.0", id: "semantic-error", method: "tools/call",
    params: { name: "text_normalize", arguments: { text: "\ud800", form: "NFC" } }
  });
  assert.equal(semanticError.result.isError, true);
  assert.equal(semanticError.result.structuredContent.error.code, "INVALID_UNICODE");
  assert.equal(legacy.handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" }), null);

  const oldLegacy = createMcpSession();
  oldLegacy.handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05" } });
  const oldCall = oldLegacy.handleMessage({
    jsonrpc: "2.0", id: 2, method: "tools/call",
    params: { name: "text_normalize", arguments: { text: "a", form: "NFC" } }
  });
  assert.equal("structuredContent" in oldCall.result, false);
  assert.equal(JSON.parse(oldCall.result.content[0].text).status, "ok");
});

test("the public result ABI closes and types every nested object", () => {
  for (const [operation, schema] of Object.entries(OUTPUT_SCHEMAS)) {
    validateSchemaNode(schema, `${operation}.resultSchema`, true);
  }
  for (const resource of Object.values(RESULT_SCHEMA_RESOURCES)) {
    validateSchemaNode(resource.schema, `${resource.operation}.resourceSchema`, true);
  }
});

test("the library-first namespace input contract is closed and direction-aware", () => {
  validateSchemaNode(NAMESPACE_INPUT_SCHEMA, "namespace.inputSchema", true);
  assert.equal(valueMatchesSchema({
    items: [{ id: "a", text: "é", scope: "one" }, { id: "b", text: "e\u0301", scope: "one" }],
    relations: ["nfc"]
  }, NAMESPACE_INPUT_SCHEMA), true);
  assert.equal(valueMatchesSchema({
    items: [{ id: "a", text: "paypal", scope: "one" }, { id: "b", text: "pаypal", scope: "one" }],
    relations: ["uts39_confusable"],
    confusableDirection: "LTR"
  }, NAMESPACE_INPUT_SCHEMA), true);
  assert.equal(valueMatchesSchema({ items: [], relations: ["uts39_confusable"] }, NAMESPACE_INPUT_SCHEMA), false);
  assert.equal(valueMatchesSchema({ items: [], relations: ["exact"], confusableDirection: "LTR" }, NAMESPACE_INPUT_SCHEMA), false);
  assert.equal(valueMatchesSchema({
    items: [],
    relations: [{
      kind: "protocol", profile: "precis_username_case_mapped", action: "enforce"
    }, {
      kind: "declared_collation", locale: "en", options: { ...COLLATION_OPTIONS, sensitivity: "base" }
    }]
  }, NAMESPACE_INPUT_SCHEMA), true);
  assert.equal(valueMatchesSchema({
    items: [], relations: [{ kind: "protocol", profile: "uts46_domain", action: "to_ascii", options: {} }]
  }, NAMESPACE_INPUT_SCHEMA), false);
  assert.equal(valueMatchesSchema({
    items: [],
    relations: [{ kind: "declared_collation", locale: "en", options: COLLATION_OPTIONS }],
    confusableDirection: "LTR"
  }, NAMESPACE_INPUT_SCHEMA), false);
});

test("modern MCP era answers discover, concise text plus structured results, and version errors", () => {
  const modern = createMcpSession();
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
  const discover = modern.handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } });
  assert.equal(discover.result.resultType, "complete");
  assert.equal(discover.result.supportedVersions[0], "2026-07-28");
  assert.ok(discover.result.supportedVersions.includes("2025-06-18"));
  assert.equal(discover.result._meta["io.modelcontextprotocol/serverInfo"].name, "text-integrity");
  assert.equal(discover.result.capabilities.resources.listChanged, false);
  assert.equal(typeof discover.result.ttlMs, "number");
  assert.equal(discover.result.cacheScope, "public");

  const listed = modern.handleMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: { _meta: meta } });
  assert.equal(listed.result.resultType, "complete");
  assert.equal(listed.result.tools.length, 8);
  assert.deepEqual(listed.result.tools.map((tool) => tool.name), TOOL_DEFINITIONS.map((tool) => tool.name));
  assert.equal(listed.result.cacheScope, "public");
  assert.ok(Buffer.byteLength(JSON.stringify(listed), "utf8") <= LIMITS.maxToolCatalogBytes);

  const resources = modern.handleMessage({
    jsonrpc: "2.0", id: "resource-list", method: "resources/list", params: { _meta: meta }
  });
  assert.equal(resources.result.resultType, "complete");
  assert.deepEqual(resources.result.resources, RESULT_SCHEMA_RESOURCE_LIST);
  assert.equal(resources.result.cacheScope, "public");
  const normalizeSchema = modern.handleMessage({
    jsonrpc: "2.0", id: "resource-read", method: "resources/read",
    params: { _meta: meta, uri: RESULT_SCHEMA_RESOURCES.normalize.uri }
  });
  const normalizeSchemaValue = JSON.parse(normalizeSchema.result.contents[0].text);
  assert.equal(normalizeSchemaValue.$id, RESULT_SCHEMA_RESOURCES.normalize.uri);
  assert.equal(normalizeSchemaValue["x-text-integrity-contract"], PUBLIC_RESULT_SCHEMA_VERSION);
  assert.equal(modern.handleMessage({
    jsonrpc: "2.0", id: "missing-resource", method: "resources/read",
    params: { _meta: meta, uri: "text-integrity://schemas/missing" }
  }).error.code, -32602);

  const oversizedToolDefinitions = structuredClone(TOOL_DEFINITIONS);
  oversizedToolDefinitions[0].description += "x".repeat(LIMITS.maxToolCatalogBytes);
  const oversizedCatalog = createMcpSession({ toolDefinitions: oversizedToolDefinitions }).handleMessage({
    jsonrpc: "2.0", id: "catalog-limit", method: "tools/list", params: { _meta: meta }
  });
  assert.equal(oversizedCatalog.error.code, -32001);
  assert.equal(oversizedCatalog.error.data.code, "RESULT_TOO_LARGE");

  const called = modern.handleMessage({
    jsonrpc: "2.0", id: 3, method: "tools/call",
    params: { _meta: meta, name: "text_normalize", arguments: { text: "e\u0301", form: "NFC" } }
  });
  assert.equal(called.result.resultType, "complete");
  assert.equal(called.result.isError, false);
  assert.equal(called.result.structuredContent.normalized, "é");
  assert.equal(called.result._meta["io.modelcontextprotocol/serverInfo"].name, "text-integrity");
  assert.equal(called.result._meta["text-integrity/publicResultContract"], PUBLIC_RESULT_SCHEMA_VERSION);
  assert.equal(called.result._meta["text-integrity/resultSchemaUri"], RESULT_SCHEMA_RESOURCES.normalize.uri);
  assert.ok(!called.result.content[0].text.startsWith("{"));
  assert.ok(Buffer.byteLength(called.result.content[0].text, "utf8") < Buffer.byteLength(JSON.stringify(called.result.structuredContent), "utf8"));

  const witnessed = modern.handleMessage({
    jsonrpc: "2.0", id: "modern-witness", method: "tools/call",
    params: {
      _meta: meta,
      name: "text_transcode",
      arguments: {
        sourceKind: "bytes", bytes: [0x61, 0xe1, 0x80, 0x41, 0x80], sourceEncoding: "utf-8",
        targetEncoding: "utf-8", allowLossy: true, byteRepresentation: "hex", witnessMode: "full_required"
      }
    }
  });
  assert.equal(witnessed.result.resultType, "complete");
  assert.equal(witnessed.result.isError, false);
  assert.deepEqual(
    witnessed.result.structuredContent.witness.segments
      .filter((segment) => segment.kind === "replacement")
      .map(({ sourceStart, sourceEnd }) => [sourceStart, sourceEnd]),
    [[1, 3], [4, 5]]
  );

  const unsupported = modern.handleMessage({
    jsonrpc: "2.0", id: 4, method: "tools/list",
    params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2020-01-01" } }
  });
  assert.equal(unsupported.error.code, -32022);
  assert.deepEqual(unsupported.error.data.requested, "2020-01-01");
  assert.ok(unsupported.error.data.supported.includes("2026-07-28"));
  assert.equal(modern.handleMessage({ jsonrpc: "2.0", id: 5, method: "ping", params: { _meta: meta } }).error.code, -32601);
  assert.equal(modern.handleMessage({ jsonrpc: "2.0", id: {}, method: "ping" }).error.code, -32600);
  assert.equal(
    modern.handleMessage({ jsonrpc: "2.0", id: "x".repeat(LIMITS.maxJsonRpcIdBytes + 1), method: "ping" }).error.code,
    -32600
  );
});

test("public executable contracts are deeply immutable", () => {
  assertDeepFrozen(TOOL_DEFINITIONS, "TOOL_DEFINITIONS");
  assertDeepFrozen(OUTPUT_SCHEMAS, "OUTPUT_SCHEMAS");
  assertDeepFrozen(MCP_OUTPUT_SCHEMAS, "MCP_OUTPUT_SCHEMAS");
  assertDeepFrozen(NAMESPACE_INPUT_SCHEMA, "NAMESPACE_INPUT_SCHEMA");
  assertDeepFrozen(RESULT_SCHEMA_RESOURCES, "RESULT_SCHEMA_RESOURCES");
  assert.throws(() => {
    OUTPUT_SCHEMAS.normalize.oneOf[0].additionalProperties = true;
  }, TypeError);
});

test("every direct output contract accepts current core results across optional branches", () => {
  const options = {
    usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
    caseFirst: "false", localeMatcher: "best fit", collation: "default"
  };
  const domainOptions = {
    checkBidi: true, checkHyphens: true, checkJoiners: true, ignoreInvalidPunycode: false,
    transitionalProcessing: false, useSTD3ASCIIRules: true, verifyDNSLength: true
  };
  const cases = [
    ["text_inspect", "inspect", { text: "\ud800" }],
    ["text_normalize", "normalize", { text: "①A\u0315\u0300", form: "NFKC", witnessMode: "full_required" }],
    ["text_compare", "compare", { left: "a", right: "b", locale: "en", options }],
    ["text_transcode", "transcode", { sourceKind: "bytes", bytes: [0x61, 0xc3, 0x28], sourceEncoding: "utf-8", targetEncoding: "utf-8", allowLossy: true, byteRepresentation: "bytes", witnessMode: "full_required" }],
    ["text_transcode", "transcode", { sourceKind: "text", text: "A", targetEncoding: "utf-16le", allowLossy: false, byteRepresentation: "hex" }],
    ["text_transcode", "transcode", { sourceKind: "text", text: "A", targetEncoding: "utf-8", allowLossy: false, byteRepresentation: "base64" }],
    ["text_security_observe", "security", { text: "plain", mode: "free_text" }],
    ["text_security_observe", "security", { text: "pаypal", mode: "identifier", profile: "uts39_general_security", comparison: "paypal", confusableDirection: "LTR" }],
    ["text_security_observe", "security", {
      source: "let pаypal = paypal;\r\u202e", mode: "source", confusableDirection: "LTR",
      spans: [
        { kind: "identifier", startUtf16: 4, endUtf16: 10, scope: "file" },
        { kind: "identifier", startUtf16: 13, endUtf16: 19, scope: "file" }
      ]
    }],
    ["text_explain_difference", "explain_difference", { left: "same", right: "same", locale: "en", options, confusableDirection: "LTR", witnessMode: "full_required" }],
    ["text_index_map", "index", { text: "A😀\n", maxChunkUtf8Bytes: 5 }],
    ["text_protocol_profile", "protocol_profile", { profile: "uts46_domain", action: "to_ascii", text: "faß.de", options: domainOptions, witnessMode: "full_required" }],
    ["text_protocol_profile", "protocol_profile", {
      profile: "uts46_domain", action: "to_unicode", text: "xn--fa-hia.de",
      options: Object.fromEntries(Object.entries(domainOptions).filter(([key]) => key !== "verifyDNSLength")),
      witnessMode: "summary"
    }],
    ["text_protocol_profile", "protocol_profile", { profile: "precis_username_case_mapped", action: "enforce", text: "Ｕser", witnessMode: "full_required" }],
    ["text_protocol_profile", "protocol_profile", { profile: "precis_username_case_preserved", action: "compare", text: "User", comparison: "User", witnessMode: "summary" }]
  ];
  for (const [toolName, operation, args] of cases) {
    const schema = OUTPUT_SCHEMAS[operation];
    const value = executeOperation(operation, args);
    assert.equal(valueMatchesSchema(value, schema), true, `${toolName} output must match its complete result schema`);
  }

  const namespace = analyzeNamespaceIntegrity({
    items: [
      { id: "left", text: "é", scope: "one" },
      { id: "right", text: "e\u0301", scope: "one" }
    ],
    relations: ["nfc"]
  });
  assert.equal(
    valueMatchesSchema(namespace, OUTPUT_SCHEMAS.namespace_integrity),
    true,
    "namespace_integrity output must match its complete result schema"
  );
  const configuredNamespace = analyzeNamespaceIntegrity({
    items: [
      { id: "unicode", text: "faß.de", scope: "domains" },
      { id: "ascii", text: "xn--fa-hia.de", scope: "domains" },
      { id: "accent", text: "résumé", scope: "names" },
      { id: "upper", text: "RESUME", scope: "names" }
    ],
    relations: [{
      kind: "protocol", profile: "uts46_domain", action: "to_ascii", options: domainOptions
    }, {
      kind: "declared_collation", locale: "en", options: { ...options, sensitivity: "base" }
    }]
  });
  assert.equal(
    valueMatchesSchema(configuredNamespace, OUTPUT_SCHEMAS.namespace_integrity),
    true,
    "configured namespace relations must match the complete result schema"
  );

  for (const tool of TOOL_DEFINITIONS) {
    const response = createMcpSession().handleMessage({
      jsonrpc: "2.0", id: tool.name, method: "tools/call",
      params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" }, name: tool.name, arguments: { invented: true } }
    });
    assert.equal(response.error.code, -32602, `${tool.name} must reject schema-invalid arguments at the protocol boundary`);
  }
  const semanticError = createMcpSession().handleMessage({
    jsonrpc: "2.0", id: "semantic-error", method: "tools/call",
    params: {
      _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" },
      name: "text_normalize",
      arguments: { text: "\ud800", form: "NFC" }
    }
  });
  assert.equal(semanticError.result.isError, true);
  assert.equal(semanticError.result.structuredContent.error.code, "INVALID_UNICODE");
  assert.equal(
    valueMatchesSchema(semanticError.result.structuredContent, TOOL_BY_NAME.get("text_normalize").outputSchema),
    true,
    "schema-valid semantic errors must match the published output schema"
  );
});

test("MCP complete envelopes stay bounded at maximum input in both eras", () => {
  const arguments_ = {
    sourceKind: "bytes", bytes: Array(4096).fill(65), sourceEncoding: "utf-8", targetEncoding: "utf-16le",
    allowLossy: false, byteRepresentation: "hex"
  };
  const legacy = createMcpSession();
  legacy.handleMessage({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } });
  const legacyResponse = legacy.handleMessage({
    jsonrpc: "2.0", id: "bounded", method: "tools/call", params: { name: "text_transcode", arguments: arguments_ }
  });
  assert.ok(Buffer.byteLength(JSON.stringify(legacyResponse), "utf8") <= LIMITS.maxMcpResultBytes);
  assert.equal(legacyResponse.result.isError, false);
  const modernResponse = createMcpSession().handleMessage({
    jsonrpc: "2.0", id: "bounded", method: "tools/call",
    params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" }, name: "text_transcode", arguments: arguments_ }
  });
  assert.ok(Buffer.byteLength(JSON.stringify(modernResponse), "utf8") <= LIMITS.maxMcpResultBytes);
  assert.equal(modernResponse.result.isError, false);
  assert.ok(
    Buffer.byteLength(JSON.stringify(modernResponse), "utf8")
      < Buffer.byteLength(JSON.stringify(legacyResponse), "utf8")
  );
});

test("live MCP bounds lines, recovers after an oversized message, and keeps notifications silent", async () => {
  const child = spawn(process.execPath, ["bin/text-integrity-mcp.js"], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.stdin.end([
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }),
    JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }),
    "x".repeat(LIMITS.maxMcpMessageBytes + 1),
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" }),
    "{bad json"
  ].join("\n") + "\n");
  const [code] = await once(child, "exit");
  assert.equal(code, 0, stderr);
  const messages = stdout.trim().split("\n").map(JSON.parse);
  assert.equal(messages.length, 4);
  assert.equal(messages[0].result.protocolVersion, "2025-06-18");
  assert.equal(messages[1].error.code, -32600);
  assert.deepEqual(messages[2].result, {});
  assert.equal(messages[3].error.code, -32700);
});

test("live MCP serves a modern stateless client without any handshake", async () => {
  const child = spawn(process.execPath, ["bin/text-integrity-mcp.js"], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
  child.stdin.end([
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } }),
    JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { _meta: meta, name: "text_inspect", arguments: { text: "A😀" } } })
  ].join("\n") + "\n");
  const [code] = await once(child, "exit");
  assert.equal(code, 0);
  const messages = stdout.trim().split("\n").map(JSON.parse);
  assert.equal(messages[0].result.resultType, "complete");
  assert.equal(messages[0].result.supportedVersions[0], "2026-07-28");
  assert.equal(messages[1].result.isError, false);
  assert.equal(messages[1].result.structuredContent.counts.codePoints, 2);
  assert.ok(!messages[1].result.content[0].text.startsWith("{"));
});

test("wire carriers reject malformed UTF-8 without hiding replacement and recover", async () => {
  const malformedMcp = invalidUtf8Json(
    '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"text_inspect","arguments":{"text":"',
    '"}}}\n'
  );
  const validMcp = Buffer.from(`${JSON.stringify({
    jsonrpc: "2.0", id: 2, method: "tools/call",
    params: {
      _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" },
      name: "text_inspect", arguments: { text: "after" }
    }
  })}\n`);
  const child = spawn(process.execPath, ["bin/text-integrity-mcp.js"], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stdin.end(Buffer.concat([malformedMcp, validMcp]));
  const [code] = await once(child, "exit");
  assert.equal(code, 0);
  const messages = stdout.trim().split("\n").map(JSON.parse);
  assert.equal(messages[0].error.code, -32700);
  assert.equal(messages[1].result.structuredContent.detail.codePoints[0].character, "a");

  const server = createUiServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    const url = `http://127.0.0.1:${address.port}/api/run`;
    const malformedResponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: invalidUtf8Json('{"operation":"inspect","arguments":{"text":"', '"}}')
    });
    assert.equal(malformedResponse.status, 400);
    assert.equal((await malformedResponse.json()).error.code, "INVALID_INPUT");

    const recoveredResponse = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ operation: "inspect", arguments: { text: "after" } })
    });
    assert.equal(recoveredResponse.status, 200);
    assert.equal((await recoveredResponse.json()).counts.codePoints, 5);
  } finally {
    server.close();
  }
});

test("all carriers accept a valid core request after worst-case JSON escaping", async () => {
  const text = "\u0001".repeat(LIMITS.maxTextBytes);
  const options = {
    usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
    caseFirst: "false", localeMatcher: "best fit", collation: "default"
  };
  const request = {
    operation: "compare",
    arguments: { left: text, right: text, locale: "en", options }
  };
  const serialized = JSON.stringify(request);
  assert.ok(Buffer.byteLength(serialized, "utf8") > 32768, "the regression must exceed the former carrier cap");

  const cliResult = cli(["--json"], serialized);
  assert.equal(cliResult.status, 0, cliResult.stderr);
  assert.equal(JSON.parse(cliResult.stdout).relation, "equal");

  const server = createUiServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const address = server.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/run`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: serialized
    });
    assert.equal(response.status, 200);
    assert.equal((await response.json()).relation, "equal");
  } finally {
    server.close();
  }

  const child = spawn(process.execPath, ["bin/text-integrity-mcp.js"], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stdin.end(`${JSON.stringify({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: {
      _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" },
      name: "text_compare", arguments: request.arguments
    }
  })}\n`);
  const [code] = await once(child, "exit");
  assert.equal(code, 0);
  assert.equal(JSON.parse(stdout).result.structuredContent.relation, "equal");
});

test("a slow consumer cannot force unbounded buffering and the server recovers", async () => {
  const child = spawn(process.execPath, ["bin/text-integrity-mcp.js"], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  child.stdout.setEncoding("utf8");
  child.stdout.pause();
  const requestCount = 5001;
  const lines = [
    JSON.stringify({ jsonrpc: "2.0", id: "init", method: "initialize", params: { protocolVersion: "2025-06-18" } })
  ];
  for (let index = 0; index < requestCount - 1; index += 1) {
    lines.push(JSON.stringify({ jsonrpc: "2.0", id: index, method: "ping" }));
  }
  child.stdin.write(`${lines.join("\n")}\n`);
  await new Promise((resolve) => setTimeout(resolve, 400));
  const rssKb = process.platform === "win32" ? null
    : Number(spawnSync("ps", ["-o", "rss=", "-p", String(child.pid)], { encoding: "utf8" }).stdout.trim());
  if (rssKb !== null) assert.ok(rssKb < 96 * 1024, `server RSS must stay bounded under a slow consumer, saw ${rssKb} KB`);
  let received = 0;
  let pending = "";
  child.stdout.on("data", (chunk) => {
    pending += chunk;
    const complete = pending.split("\n");
    pending = complete.pop();
    received += complete.filter((line) => line.trim() !== "").length;
  });
  const exited = once(child, "exit");
  child.stdout.resume();
  child.stdin.end();
  const [code] = await exited;
  assert.equal(code, 0);
  assert.equal(pending.trim(), "", "the server must terminate every response with a newline");
  // every ping must have been answered after the consumer resumed
  assert.equal(received, requestCount);
});

test("cancellation recovers and the connection keeps answering", async () => {
  const child = spawn(process.execPath, ["bin/text-integrity-mcp.js"], { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  child.stdout.setEncoding("utf8");
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
  const flood = [];
  for (let index = 0; index < 200; index += 1) {
    flood.push(JSON.stringify({
      jsonrpc: "2.0", id: index, method: "tools/call",
      params: { _meta: meta, name: "text_normalize", arguments: { text: "e\u0301".repeat(40), form: "NFD" } }
    }));
  }
  flood.push(JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 100, reason: "test" } }));
  flood.push(JSON.stringify({ jsonrpc: "2.0", id: 999, method: "ping", params: { _meta: meta } }));
  let stdout = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stdin.end(`${flood.join("\n")}\n`);
  const [code] = await once(child, "exit");
  assert.equal(code, 0);
  const messages = stdout.trim().split("\n").map(JSON.parse);
  const answered = new Set(messages.map((message) => message.id));
  assert.equal(answered.has(999), true, "connection must keep answering after cancellation");
  assert.ok(messages.length <= 201, `expected at most 201 responses, saw ${messages.length}`);
});

test("runMcpServer suppresses a cancelled request queued behind blocked output and resumes cleanly", async () => {
  const { PassThrough } = await import("node:stream");
  const { EventEmitter } = await import("node:events");
  const input = new PassThrough();
  const output = new EventEmitter();
  const written = [];
  let blocked = true;
  output.write = (line) => {
    written.push(line);
    return !blocked;
  };
  runMcpServer(input, output);
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
  const request = (id) => JSON.stringify({
    jsonrpc: "2.0", id, method: "tools/call",
    params: { _meta: meta, name: "text_normalize", arguments: { text: "e\u0301", form: "NFC" } }
  });
  input.write(`${request(1)}\n${request(2)}\n`);
  input.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2 } })}\n`);
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(written.length, 1, "only the pre-block request may be written");
  assert.equal(JSON.parse(written[0]).id, 1);
  output.emit("drain");
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(written.length, 1, "the cancelled request must stay suppressed after drain");
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 3, method: "ping", params: { _meta: meta } })}\n`);
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(written.length, 2, "the connection must keep answering after cancellation");
  assert.equal(JSON.parse(written[1]).id, 3);
  input.end();
});

test("blocked MCP output bounds queued parse errors and resumes them after drain", async () => {
  const { PassThrough } = await import("node:stream");
  const { EventEmitter } = await import("node:events");
  const input = new PassThrough();
  const output = new EventEmitter();
  const written = [];
  let blocked = true;
  output.write = (line) => {
    written.push(line);
    return !blocked;
  };
  runMcpServer(input, output);
  input.write(`${Array(200).fill("{bad json").join("\n")}\n`);
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(written.length, 1, "no further responses may be written while output is blocked");
  assert.equal(input.isPaused(), true, "the input must pause at the bounded response queue");

  blocked = false;
  output.emit("drain");
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(written.length, 200);
  assert.ok(written.every((line) => JSON.parse(line).error.code === -32700));
  input.end();
});

test("queued deadline errors sanitize invalid IDs and preserve precomputed protocol errors", async () => {
  const { PassThrough } = await import("node:stream");
  const { EventEmitter } = await import("node:events");
  const input = new PassThrough();
  const output = new EventEmitter();
  const written = [];
  let blocked = true;
  output.write = (line) => {
    written.push(JSON.parse(line));
    return !blocked;
  };
  runMcpServer(input, output);
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: meta } })}\n`);
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: { invalid: true }, method: "tools/list", params: { _meta: meta } })}\n`);
  input.write("{bad json\n");
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(written.length, 1);

  const originalNow = Date.now;
  try {
    Date.now = () => originalNow() + LIMITS.mcpRequestDeadlineMs + 1;
    blocked = false;
    output.emit("drain");
    await new Promise((resolve) => setTimeout(resolve, 100));
  } finally {
    Date.now = originalNow;
    input.end();
  }
  assert.equal(written.length, 3);
  assert.equal(written[1].id, null);
  assert.equal(written[1].error.code, -32003);
  assert.equal(written[2].error.code, -32700);
});

test("local human surface stays minimal and uses the same bounded core", async (t) => {
  const server = createUiServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => server.close());
  const address = server.address();
  const base = `http://127.0.0.1:${address.port}`;

  const pageText = await (await fetch(base)).text();
  assert.equal((pageText.match(/<option value=/gu) ?? []).length >= 8, true);
  assert.match(pageText, /Explain difference/u);
  assert.match(pageText, /Complete trace/u);
  assert.doesNotMatch(pageText, /source span|agent metadata|risk score/iu);
  const appText = await (await fetch(`${base}/app.js`)).text();
  assert.match(appText, /AbortController/u);
  assert.match(appText, /requestSerial/u);
  assert.match(appText, /operation\.addEventListener\("change", resetTask\)/u);
  assert.match(appText, /form\.addEventListener\("input"/u);
  assert.match(appText, /form\.addEventListener\("change"/u);
  assert.match(appText, /Byte \$\{index \+ 1\} is empty/u);
  assert.match(appText, /#security-direction/u);
  assert.match(appText, /witnessMode/u);
  assert.match(appText, /Fact boundaries/u);
  assert.doesNotMatch(appText, /confusableDirection:\s*"LTR"/u);
  assert.doesNotMatch(appText, /split\(","\)\.filter/u);
  const cssText = await (await fetch(`${base}/styles.css`)).text();
  assert.match(cssText, /\[hidden\]\s*\{\s*display:\s*none !important;/u);
  assert.match(cssText, /\.text-value \{ white-space: pre-wrap/u);

  const normalized = await fetch(`${base}/api/run`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      operation: "normalize",
      arguments: { text: "e\u0301", form: "NFC", witnessMode: "full_required" }
    })
  });
  assert.equal(normalized.status, 200);
  const normalizedValue = await normalized.json();
  assert.equal(normalizedValue.normalized, "é");
  assert.equal(normalizedValue.witness.compositionCount, 1);
  const difference = await fetch(`${base}/api/run`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({
      operation: "explain_difference",
      arguments: {
        left: "e\u0301", right: "é", locale: "en", options: COLLATION_OPTIONS,
        confusableDirection: "LTR", witnessMode: "full_required"
      }
    })
  });
  assert.equal(difference.status, 200);
  const differenceValue = await difference.json();
  assert.equal(differenceValue.witness.transformations.normalization.NFC.leftOutput, "é");
  assert.equal(differenceValue.witness.alignment.codePoint.segments[0].kind, "replace");
  assert.equal(differenceValue.witness.alignment.grapheme.segments[0].kind, "replace");
  assert.equal(differenceValue.witness.factBoundaries.collation.environmentBound, true);
  const invalid = await fetch(`${base}/api/run`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation: "inspect", arguments: { text: "a".repeat(4097) } })
  });
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error.code, "REQUEST_TOO_LARGE");
});
