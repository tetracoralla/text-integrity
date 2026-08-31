// High-frequency baseline measurements for the whole delivery: cold process,
// warm in-process calls, stdio burst throughput, slow-consumer memory bounds,
// cancellation recovery, maximum-input envelope sizes, million-call steady
// state, catalog cost, and memory growth.
//
//   node scripts/bench.mjs          print all measurements
//   node scripts/bench.mjs --json   emit machine-readable JSON only
//   node scripts/bench.mjs --slo    fail (exit 1) when a release SLO is violated
//
// SLO values are derived from the recorded baseline in
// docs/PERFORMANCE_BASELINE.md with explicit headroom; they are regression
// fences, not product acceptance.

import { spawn, spawnSync } from "node:child_process";
import { EventEmitter, once } from "node:events";
import { PassThrough } from "node:stream";
import { executeOperation, LIMITS } from "../src/library.js";
import { createMcpSession, runMcpServer } from "../src/mcp/server.js";
import { VERSION } from "../src/version.js";

const ROOT = new URL("../", import.meta.url);
const BIN = ["bin/text-integrity-mcp.js"];
const META = { "io.modelcontextprotocol/protocolVersion": "2026-07-28" };
const SAMPLES = { cold: 10, security: 20000, difference: 5000, steady: 1_000_000, burst: 1000, slowConsumer: 5000 };

// Release fences derived from docs/PERFORMANCE_BASELINE.md with explicit
// headroom for slower CI runners; they are regression fences, not product
// acceptance. Throughput floors are set well below the recorded baseline
// (not above it) so they catch real regressions without flaking on slow
// machines.
const SLO = {
  coldSecurityMedianMs: 75,
  coldRssMb: 96,
  warmSecurityP99Ms: 0.25,
  warmDifferenceP99Ms: 5,
  steadyCallsPerSecond: 25_000,
  slowConsumerRssKb: 96 * 1024,
  maxModernResultBytes: LIMITS.maxMcpResultBytes,
  catalogBytes: LIMITS.maxToolCatalogBytes,
  steadyRssGrowthKb: 32 * 1024
};

function percentile(sorted, fraction) {
  const index = Math.min(sorted.length - 1, Math.ceil(fraction * sorted.length) - 1);
  return sorted[Math.max(0, index)];
}

function stats(samples) {
  const sorted = [...samples].sort((left, right) => left - right);
  return {
    n: sorted.length,
    medianMs: percentile(sorted, 0.5),
    p99Ms: percentile(sorted, 0.99),
    maxMs: sorted[sorted.length - 1]
  };
}

async function coldStart() {
  const samples = [];
  const rssSamples = [];
  const program = `
    const start = performance.now();
    (async () => {
      const { executeOperation } = await import(${JSON.stringify(new URL("../src/library.js", import.meta.url).href)});
      executeOperation("security", { text: "p\\u0430ypal", mode: "identifier", profile: "uts39_general_security", comparison: "paypal", confusableDirection: "LTR" });
      process.stdout.write(JSON.stringify({ elapsedMs: performance.now() - start, rssMb: process.memoryUsage().rss / 1024 / 1024 }));
    })();
  `;
  for (let index = 0; index < SAMPLES.cold; index += 1) {
    const child = spawn(process.execPath, ["-e", program], { cwd: ROOT });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    const [code] = await once(child, "exit");
    if (code !== 0 || stdout === "") throw new Error(`cold-start child failed (${code})`);
    const value = JSON.parse(stdout);
    samples.push(value.elapsedMs);
    rssSamples.push(value.rssMb);
  }
  const rss = stats(rssSamples);
  return {
    coldFirstSecurityCall: stats(samples),
    coldRssMb: { n: rss.n, medianMb: rss.medianMs, p99Mb: rss.p99Ms, maxMb: rss.maxMs }
  };
}

function warmCalls() {
  const security = [];
  const identifierArgs = { text: "pаypal", mode: "identifier", profile: "uts39_general_security", comparison: "paypal", confusableDirection: "LTR" };
  const freeTextArgs = { text: "plain ascii text", mode: "free_text" };
  executeOperation("security", identifierArgs);
  for (let index = 0; index < SAMPLES.security; index += 1) {
    const start = performance.now();
    executeOperation("security", identifierArgs);
    security.push(performance.now() - start);
  }
  const freeText = [];
  for (let index = 0; index < 1000; index += 1) {
    const start = performance.now();
    executeOperation("security", freeTextArgs);
    freeText.push(performance.now() - start);
  }
  const difference = [];
  const differenceArgs = {
    left: "e\u0301\r\nраypal", right: "é\npaypal", locale: "en",
    options: {
      usage: "sort", sensitivity: "variant", ignorePunctuation: false, numeric: false,
      caseFirst: "false", localeMatcher: "best fit", collation: "default"
    },
    confusableDirection: "LTR"
  };
  executeOperation("explain_difference", differenceArgs);
  for (let index = 0; index < SAMPLES.difference; index += 1) {
    const start = performance.now();
    executeOperation("explain_difference", differenceArgs);
    difference.push(performance.now() - start);
  }
  return {
    securityIdentifier: stats(security),
    securityFreeText: stats(freeText),
    explainDifference: stats(difference)
  };
}

async function stdioRoundtrip(lines, onSpawn) {
  const child = spawn(process.execPath, BIN, { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  onSpawn?.(child);
  child.stdin.end(`${lines.join("\n")}\n`);
  const [code] = await once(child, "exit");
  if (code !== 0) throw new Error(`stdio child failed (${code}): ${stderr}`);
  return stdout.trim().split("\n").filter((line) => line !== "").map((line) => JSON.parse(line));
}

async function burst() {
  const lines = [
    JSON.stringify({ jsonrpc: "2.0", id: 0, method: "server/discover", params: { _meta: META } }),
    JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: META } })
  ];
  for (let index = 0; index < SAMPLES.burst; index += 1) {
    lines.push(JSON.stringify({
      jsonrpc: "2.0", id: index + 2, method: "tools/call",
      params: { _meta: META, name: "text_normalize", arguments: { text: "e\u0301", form: "NFC" } }
    }));
  }
  const start = performance.now();
  const messages = await stdioRoundtrip(lines);
  const elapsedMs = performance.now() - start;
  return { burstRequests: SAMPLES.burst + 2, burstMs: elapsedMs, burstResponses: messages.length };
}

async function slowConsumer() {
  const child = spawn(process.execPath, BIN, { cwd: ROOT, stdio: ["pipe", "pipe", "pipe"] });
  child.stdout.setEncoding("utf8");
  child.stdout.pause();
  const lines = [JSON.stringify({ jsonrpc: "2.0", id: "init", method: "initialize", params: { protocolVersion: "2025-06-18" } })];
  for (let index = 0; index < SAMPLES.slowConsumer; index += 1) {
    lines.push(JSON.stringify({ jsonrpc: "2.0", id: index, method: "ping" }));
  }
  child.stdin.write(`${lines.join("\n")}\n`);
  await new Promise((resolve) => setTimeout(resolve, 500));
  const rssKb = process.platform === "win32" ? null
    : Number(spawnSync("ps", ["-o", "rss=", "-p", String(child.pid)], { encoding: "utf8" }).stdout.trim());
  let received = 0;
  let pending = "";
  child.stdout.on("data", (chunk) => {
    pending += chunk;
    const lines = pending.split("\n");
    pending = lines.pop();
    received += lines.filter((line) => line.trim() !== "").length;
  });
  const exited = once(child, "exit");
  child.stdout.resume();
  child.stdin.end();
  const [code] = await exited;
  return {
    slowConsumerPausedRssKb: rssKb,
    slowConsumerResponsesRecovered: received,
    slowConsumerExitCode: code
  };
}

async function cancellationRecovery() {
  const input = new PassThrough();
  const output = new EventEmitter();
  const messages = [];
  let blocked = true;
  output.write = (line) => {
    messages.push(JSON.parse(line));
    return !blocked;
  };
  runMcpServer(input, output);
  const request = (id) => JSON.stringify({
    jsonrpc: "2.0", id, method: "tools/call",
    params: { _meta: META, name: "text_normalize", arguments: { text: "e\u0301", form: "NFC" } }
  });
  input.write(`${request(1)}\n${request(2)}\n`);
  input.write(`${JSON.stringify({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId: 2 } })}\n`);
  await new Promise((resolve) => setTimeout(resolve, 25));
  blocked = false;
  output.emit("drain");
  await new Promise((resolve) => setTimeout(resolve, 25));
  input.write(`${JSON.stringify({ jsonrpc: "2.0", id: "after-cancel", method: "tools/list", params: { _meta: META } })}\n`);
  await new Promise((resolve) => setTimeout(resolve, 25));
  input.end();
  const answered = new Set(messages.map((message) => String(message.id)));
  return {
    cancelRecoveredPing: answered.has("after-cancel"),
    cancelledResponseSuppressed: !answered.has("2"),
    cancelResponsesTotal: messages.length
  };
}

function envelopeSizes() {
  const arguments_ = {
    sourceKind: "bytes", bytes: Array(4096).fill(65), sourceEncoding: "utf-8", targetEncoding: "utf-16le",
    allowLossy: false, byteRepresentation: "hex"
  };
  const coreResult = executeOperation("transcode", arguments_);
  const coreBytes = Buffer.byteLength(JSON.stringify(coreResult), "utf8");
  const legacy = createMcpSession();
  legacy.handleMessage({ jsonrpc: "2.0", id: 0, method: "initialize", params: { protocolVersion: "2025-06-18" } });
  const legacyResult = legacy.handleMessage({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: "text_transcode", arguments: arguments_ }
  });
  const modern = createMcpSession();
  const modernResult = modern.handleMessage({
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { _meta: META, name: "text_transcode", arguments: arguments_ }
  });
  const catalogResult = modern.handleMessage({
    jsonrpc: "2.0", id: 2, method: "tools/list", params: { _meta: META }
  });
  const legacyBytes = Buffer.byteLength(JSON.stringify(legacyResult), "utf8");
  const modernBytes = Buffer.byteLength(JSON.stringify(modernResult), "utf8");
  const catalog = Buffer.byteLength(JSON.stringify(catalogResult), "utf8");
  return {
    maxTranscodeCoreResultBytes: coreBytes,
    maxTranscodeLegacyEnvelopeBytes: legacyBytes,
    maxTranscodeModernEnvelopeBytes: modernBytes,
    modernVsCoreRatio: Number((modernBytes / coreBytes).toFixed(2)),
    legacyVsCoreRatio: Number((legacyBytes / coreBytes).toFixed(2)),
    catalogBytes: catalog,
    catalogApproxTokens: Math.round(catalog / 4)
  };
}

function steadyState() {
  const args = { text: "plain ascii text", mode: "free_text" };
  executeOperation("security", args);
  global.gc?.();
  const rssBeforeKb = process.memoryUsage().rss / 1024;
  const start = performance.now();
  for (let index = 0; index < SAMPLES.steady; index += 1) executeOperation("security", args);
  const elapsedMs = performance.now() - start;
  global.gc?.();
  const rssAfterKb = process.memoryUsage().rss / 1024;
  return {
    steadyCalls: SAMPLES.steady,
    steadySeconds: elapsedMs / 1000,
    steadyCallsPerSecond: Math.round(SAMPLES.steady / (elapsedMs / 1000)),
    steadyRssBeforeKb: Math.round(rssBeforeKb),
    steadyRssAfterKb: Math.round(rssAfterKb),
    steadyRssGrowthKb: Math.round(rssAfterKb - rssBeforeKb)
  };
}

function evaluateSlo(measurements) {
  const violations = [];
  const check = (name, ok, actual, limit) => {
    if (!ok) violations.push(`${name}: ${actual} exceeded limit ${limit}`);
  };
  check("coldSecurityMedianMs", measurements.cold.coldFirstSecurityCall.medianMs <= SLO.coldSecurityMedianMs,
    measurements.cold.coldFirstSecurityCall.medianMs, SLO.coldSecurityMedianMs);
  check("coldRssMb", measurements.cold.coldRssMb.medianMb <= SLO.coldRssMb,
    measurements.cold.coldRssMb.medianMb, SLO.coldRssMb);
  check("warmSecurityP99Ms", measurements.warm.securityIdentifier.p99Ms <= SLO.warmSecurityP99Ms,
    measurements.warm.securityIdentifier.p99Ms, SLO.warmSecurityP99Ms);
  check("warmDifferenceP99Ms", measurements.warm.explainDifference.p99Ms <= SLO.warmDifferenceP99Ms,
    measurements.warm.explainDifference.p99Ms, SLO.warmDifferenceP99Ms);
  check("steadyCallsPerSecond", measurements.steady.steadyCallsPerSecond >= SLO.steadyCallsPerSecond,
    measurements.steady.steadyCallsPerSecond, SLO.steadyCallsPerSecond);
  if (measurements.slowConsumer.slowConsumerPausedRssKb !== null) {
    check("slowConsumerRssKb", measurements.slowConsumer.slowConsumerPausedRssKb <= SLO.slowConsumerRssKb,
      measurements.slowConsumer.slowConsumerPausedRssKb, SLO.slowConsumerRssKb);
  }
  check("slowConsumerResponsesRecovered",
    measurements.slowConsumer.slowConsumerResponsesRecovered === SAMPLES.slowConsumer + 1,
    measurements.slowConsumer.slowConsumerResponsesRecovered, SAMPLES.slowConsumer + 1);
  check("slowConsumerExitCode", measurements.slowConsumer.slowConsumerExitCode === 0,
    measurements.slowConsumer.slowConsumerExitCode, 0);
  check("burstResponses", measurements.burst.burstResponses === measurements.burst.burstRequests,
    measurements.burst.burstResponses, measurements.burst.burstRequests);
  check("cancelRecoveredPing", measurements.cancel.cancelRecoveredPing,
    measurements.cancel.cancelRecoveredPing, true);
  check("cancelledResponseSuppressed", measurements.cancel.cancelledResponseSuppressed,
    measurements.cancel.cancelledResponseSuppressed, true);
  check("maxModernResultBytes", measurements.envelopes.maxTranscodeModernEnvelopeBytes <= SLO.maxModernResultBytes,
    measurements.envelopes.maxTranscodeModernEnvelopeBytes, SLO.maxModernResultBytes);
  check("catalogBytes", measurements.envelopes.catalogBytes <= SLO.catalogBytes,
    measurements.envelopes.catalogBytes, SLO.catalogBytes);
  check("steadyRssGrowthKb", measurements.steady.steadyRssGrowthKb <= SLO.steadyRssGrowthKb,
    measurements.steady.steadyRssGrowthKb, SLO.steadyRssGrowthKb);
  return violations;
}

const asJson = process.argv.includes("--json");
const asSlo = process.argv.includes("--slo");

const measurements = {
  meta: {
    version: VERSION,
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    samples: SAMPLES
  },
  cold: await coldStart(),
  warm: warmCalls(),
  steady: steadyState(),
  envelopes: envelopeSizes(),
  burst: await burst(),
  slowConsumer: await slowConsumer(),
  cancel: await cancellationRecovery()
};

if (asJson) {
  process.stdout.write(`${JSON.stringify(measurements, null, 2)}\n`);
} else {
  const { cold, warm, steady, envelopes, burst: burstResult, slowConsumer: slow, cancel } = measurements;
  process.stdout.write([
    `text-integrity ${VERSION} baseline — node ${process.version} on ${process.platform}-${process.arch}`,
    `cold first security call (n=${cold.coldFirstSecurityCall.n}): median ${cold.coldFirstSecurityCall.medianMs.toFixed(1)} ms, p99 ${cold.coldFirstSecurityCall.p99Ms.toFixed(1)} ms, RSS ${cold.coldRssMb.medianMb.toFixed(1)} MB`,
    `warm security identifier (n=${warm.securityIdentifier.n}): median ${warm.securityIdentifier.medianMs.toFixed(3)} ms, p99 ${warm.securityIdentifier.p99Ms.toFixed(3)} ms, max ${warm.securityIdentifier.maxMs.toFixed(3)} ms`,
    `warm security free_text (n=${warm.securityFreeText.n}): median ${warm.securityFreeText.medianMs.toFixed(3)} ms, p99 ${warm.securityFreeText.p99Ms.toFixed(3)} ms`,
    `warm explain_difference (n=${warm.explainDifference.n}): median ${warm.explainDifference.medianMs.toFixed(3)} ms, p99 ${warm.explainDifference.p99Ms.toFixed(3)} ms`,
    `steady state: ${steady.steadyCalls.toLocaleString("en-US")} free_text calls in ${steady.steadySeconds.toFixed(2)} s (${steady.steadyCallsPerSecond.toLocaleString("en-US")}/s), RSS growth ${steady.steadyRssGrowthKb} KB`,
    `stdio burst: ${burstResult.burstResponses}/${burstResult.burstRequests} responses in ${burstResult.burstMs.toFixed(0)} ms`,
    `slow consumer: paused RSS ${slow.slowConsumerPausedRssKb} KB, recovered ${slow.slowConsumerResponsesRecovered} responses, exit ${slow.slowConsumerExitCode}`,
    `cancellation: suppressed=${cancel.cancelledResponseSuppressed}, connection recovered=${cancel.cancelRecoveredPing}, responses ${cancel.cancelResponsesTotal}`,
    `catalog: ${envelopes.catalogBytes} bytes (~${envelopes.catalogApproxTokens} tokens at 4 bytes/token)`,
    `max transcode: core ${envelopes.maxTranscodeCoreResultBytes} B, legacy envelope ${envelopes.maxTranscodeLegacyEnvelopeBytes} B (${envelopes.legacyVsCoreRatio}x), modern envelope ${envelopes.maxTranscodeModernEnvelopeBytes} B (${envelopes.modernVsCoreRatio}x)`
  ].join("\n") + "\n");
}

if (asSlo) {
  const violations = evaluateSlo(measurements);
  if (violations.length > 0) {
    process.stderr.write(`SLO violations:\n${violations.map((line) => `- ${line}`).join("\n")}\n`);
    process.exit(1);
  }
  process.stdout.write("slo: all release fences passed\n");
}
