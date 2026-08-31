import test from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { createUiServer } from "../src/ui/server.js";
import { createMcpSession, runMcpServer } from "../src/mcp/server.js";
import { TOOL_DEFINITIONS } from "../src/contracts.js";
import { executeOperation } from "../src/core/operations.js";
import { LIMITS } from "../src/core/limits.js";

const ROOT = new URL("../", import.meta.url);
const COLLATION_FLAGS = [
  "--locale", "en", "--usage", "sort", "--sensitivity", "variant",
  "--ignore-punctuation", "false", "--numeric", "false", "--case-first", "false",
  "--locale-matcher", "best fit", "--collation", "default"
];

function cli(args, input) {
  return spawnSync(process.execPath, ["bin/text-integrity.js", ...args], { cwd: ROOT, encoding: "utf8", input, maxBuffer: 1 << 20 });
}

function validateSchemaNode(schema, path = "$") {
  assert.notDeepEqual(schema, {}, `${path} must not be an unconstrained schema`);
  if (schema.oneOf) {
    for (const [index, branch] of schema.oneOf.entries()) validateSchemaNode(branch, `${path}.oneOf[${index}]`);
  }
  if (schema.type === "object") {
    for (const [name, property] of Object.entries(schema.properties ?? {})) {
      validateSchemaNode(property, `${path}.properties.${name}`);
    }
  }
  if (schema.type === "array") validateSchemaNode(schema.items, `${path}.items`);
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
      && (schema.maxItems === undefined || value.length <= schema.maxItems)
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
    ["normalize", "--text", "e\u0301", "--form", "NFC"],
    ["compare", "--left", "A", "--right", "a", ...COLLATION_FLAGS],
    ["explain_difference", "--left", "é", "--right", "e\u0301", ...COLLATION_FLAGS, "--confusable-direction", "LTR"],
    ["index", "--text", "A😀B", "--max-chunk-utf8-bytes", "4"],
    ["security", "--text", "pаypаl", "--mode", "identifier", "--profile", "uts39_general_security", "--comparison", "paypal", "--confusable-direction", "LTR"],
    ["protocol_profile", "--profile", "precis_username_case_mapped", "--action", "enforce", "--text", "User"],
    ["transcode", "--source-kind", "bytes", "--bytes", "[65,0]", "--source-encoding", "utf-16le", "--target-encoding", "utf-8", "--allow-lossy", "false", "--byte-representation", "hex"]
  ];
  for (const args of cases) {
    const child = cli(args);
    assert.equal(child.status, 0, child.stderr);
    assert.equal(JSON.parse(child.stdout).status, "ok");
  }

  const raw = cli(["--json"], '{"operation":"inspect","arguments":{"text":"\\ud800"}}');
  assert.equal(raw.status, 0, raw.stderr);
  assert.equal(JSON.parse(raw.stdout).inputWellFormed, false);
  assert.match(cli(["--help"]).stdout, /Raw JSON preserves escaped unpaired surrogates/u);
  const schema = JSON.parse(cli(["--schema"]).stdout);
  assert.equal(schema.tools.length, 8);
  assert.ok(schema.tools.every((tool) => tool.inputSchema && tool.outputSchema));

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
  const called = legacy.handleMessage({
    jsonrpc: "2.0", id: 6, method: "tools/call",
    params: { name: "text_normalize", arguments: { text: "e\u0301", form: "NFC" } }
  });
  assert.equal(called.result.isError, false);
  assert.deepEqual(JSON.parse(called.result.content[0].text), called.result.structuredContent);
  const invalid = legacy.handleMessage({
    jsonrpc: "2.0", id: 7, method: "tools/call",
    params: { name: "text_inspect", arguments: { text: "ok", invented: true } }
  });
  assert.equal(invalid.result.structuredContent.error.code, "INVALID_INPUT");
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

test("modern MCP era answers discover, concise text plus structured results, and version errors", () => {
  const modern = createMcpSession();
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
  const discover = modern.handleMessage({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } });
  assert.equal(discover.result.resultType, "complete");
  assert.equal(discover.result.supportedVersions[0], "2026-07-28");
  assert.ok(discover.result.supportedVersions.includes("2025-06-18"));
  assert.equal(discover.result._meta["io.modelcontextprotocol/serverInfo"].name, "text-integrity");
  assert.equal(typeof discover.result.ttlMs, "number");
  assert.equal(discover.result.cacheScope, "public");

  const listed = modern.handleMessage({ jsonrpc: "2.0", id: 2, method: "tools/list", params: { _meta: meta } });
  assert.equal(listed.result.resultType, "complete");
  assert.equal(listed.result.tools.length, 8);
  assert.deepEqual(listed.result.tools.map((tool) => tool.name), TOOL_DEFINITIONS.map((tool) => tool.name));
  assert.equal(listed.result.cacheScope, "public");
  assert.ok(Buffer.byteLength(JSON.stringify(listed), "utf8") <= LIMITS.maxToolCatalogBytes);

  const originalDescription = TOOL_DEFINITIONS[0].description;
  try {
    TOOL_DEFINITIONS[0].description = originalDescription + "x".repeat(LIMITS.maxToolCatalogBytes);
    const oversizedCatalog = modern.handleMessage({
      jsonrpc: "2.0", id: "catalog-limit", method: "tools/list", params: { _meta: meta }
    });
    assert.equal(oversizedCatalog.error.code, -32001);
    assert.equal(oversizedCatalog.error.data.code, "RESULT_TOO_LARGE");
  } finally {
    TOOL_DEFINITIONS[0].description = originalDescription;
  }

  const called = modern.handleMessage({
    jsonrpc: "2.0", id: 3, method: "tools/call",
    params: { _meta: meta, name: "text_normalize", arguments: { text: "e\u0301", form: "NFC" } }
  });
  assert.equal(called.result.resultType, "complete");
  assert.equal(called.result.isError, false);
  assert.equal(called.result.structuredContent.normalized, "é");
  assert.equal(called.result._meta["io.modelcontextprotocol/serverInfo"].name, "text-integrity");
  assert.ok(!called.result.content[0].text.startsWith("{"));
  assert.ok(Buffer.byteLength(called.result.content[0].text, "utf8") < Buffer.byteLength(JSON.stringify(called.result.structuredContent), "utf8"));

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
    ["text_normalize", "normalize", { text: "e\u0301", form: "NFC" }],
    ["text_compare", "compare", { left: "a", right: "b", locale: "en", options }],
    ["text_transcode", "transcode", { sourceKind: "bytes", bytes: [0x61, 0xc3, 0x28], sourceEncoding: "utf-8", targetEncoding: "utf-8", allowLossy: true, byteRepresentation: "bytes" }],
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
    ["text_explain_difference", "explain_difference", { left: "same", right: "same", locale: "en", options, confusableDirection: "LTR" }],
    ["text_index_map", "index", { text: "A😀\n", maxChunkUtf8Bytes: 5 }],
    ["text_protocol_profile", "protocol_profile", { profile: "uts46_domain", action: "to_ascii", text: "faß.de", options: domainOptions }],
    ["text_protocol_profile", "protocol_profile", { profile: "precis_username_case_mapped", action: "enforce", text: "User" }],
    ["text_protocol_profile", "protocol_profile", { profile: "precis_username_case_preserved", action: "compare", text: "User", comparison: "User" }]
  ];
  for (const [toolName, operation, args] of cases) {
    const schema = TOOL_DEFINITIONS.find((tool) => tool.name === toolName).outputSchema;
    const value = executeOperation(operation, args);
    assert.equal(valueMatchesSchema(value, schema), true, `${toolName} output must match its published schema`);
  }

  for (const tool of TOOL_DEFINITIONS) {
    const response = createMcpSession().handleMessage({
      jsonrpc: "2.0", id: tool.name, method: "tools/call",
      params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" }, name: tool.name, arguments: { invented: true } }
    });
    assert.equal(response.result.isError, true);
    assert.equal(
      valueMatchesSchema(response.result.structuredContent, tool.outputSchema),
      true,
      `${tool.name} structured errors must match its published output schema`
    );
  }
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
  child.stdout.on("data", (chunk) => {
    received += chunk.split("\n").filter((line) => line.trim() !== "").length;
  });
  const exited = once(child, "exit");
  child.stdout.resume();
  child.stdin.end();
  const [code] = await exited;
  assert.equal(code, 0);
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
  assert.doesNotMatch(pageText, /source span|agent metadata|risk score/iu);
  const appText = await (await fetch(`${base}/app.js`)).text();
  assert.match(appText, /AbortController/u);
  assert.match(appText, /requestSerial/u);
  assert.match(appText, /Byte \$\{index \+ 1\} is empty/u);
  assert.match(appText, /#security-direction/u);
  assert.doesNotMatch(appText, /confusableDirection:\s*"LTR"/u);
  assert.doesNotMatch(appText, /split\(","\)\.filter/u);
  const cssText = await (await fetch(`${base}/styles.css`)).text();
  assert.match(cssText, /\.text-value \{ white-space: pre-wrap/u);

  const normalized = await fetch(`${base}/api/run`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation: "normalize", arguments: { text: "e\u0301", form: "NFC" } })
  });
  assert.equal(normalized.status, 200);
  assert.equal((await normalized.json()).normalized, "é");
  const invalid = await fetch(`${base}/api/run`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ operation: "inspect", arguments: { text: "a".repeat(4097) } })
  });
  assert.equal(invalid.status, 400);
  assert.equal((await invalid.json()).error.code, "REQUEST_TOO_LARGE");
});
