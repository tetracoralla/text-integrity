import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { REFERENCE_WASM_RAW_ABI } from "../src/reference/wasm.js";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const NATIVE_BINARY = path.join(ROOT, "native", "target", "release", "text-integrity-reference");
const WASM_BINARY = path.join(ROOT, "wasm", "text_integrity_reference.wasm");

function taggedScalar(value) {
  return { $text: { kind: "unicode_scalar_string", value } };
}

function differenceArguments(left, right, witnessMode) {
  return {
    left: taggedScalar(left),
    right: taggedScalar(right),
    locale: "en",
    options: {
      usage: "sort",
      sensitivity: "variant",
      ignorePunctuation: false,
      numeric: false,
      caseFirst: "false",
      localeMatcher: "lookup",
      collation: "default"
    },
    confusableDirection: "LTR",
    detailLimit: 0,
    witnessMode
  };
}

function sourceSpans() {
  return [
    ...Array.from({ length: 64 }, () => ({
      kind: "identifier", startUtf16: 0, endUtf16: 1365, scope: "same"
    })),
    ...Array.from({ length: 64 }, () => ({
      kind: "identifier", startUtf16: 1365, endUtf16: 2730, scope: "same"
    }))
  ];
}

function uts46Options() {
  return {
    checkBidi: true,
    checkHyphens: true,
    checkJoiners: true,
    ignoreInvalidPunycode: false,
    transitionalProcessing: false,
    useSTD3ASCIIRules: true,
    verifyDNSLength: true
  };
}

function namespaceItems() {
  const text = `${"a".repeat(63)}.${"b".repeat(63)}`;
  return Array.from({ length: 512 }, (_, index) => ({
    id: `i${index}`,
    text: taggedScalar(text),
    scope: "same"
  }));
}

const latin = "a".repeat(1365);
const cyrillic = "а".repeat(1365);
const maximumDomain = Array.from({ length: 64 }, () => "a".repeat(63)).join(".");
const maximumPunycodeLabel = Array.from(
  { length: 1365 },
  (_, index) => String.fromCodePoint(0x4e00 + index)
).join("");
const candidates = Object.freeze({
  difference_summary_max: Object.freeze({
    operation: "reference_explain_difference_spine",
    arguments: differenceArguments("A".repeat(4096), "B".repeat(4096), "summary"),
    workModel: Object.freeze({
      kind: "alignment_grid_cells",
      unitsPerRequest: 2 * 4096 * 4096,
      basis: "two 4096-by-4096 code-point/grapheme alignment grids"
    })
  }),
  difference_full_max: Object.freeze({
    operation: "reference_explain_difference_spine",
    arguments: differenceArguments("A".repeat(4096), "B".repeat(4096), "full_required"),
    workModel: Object.freeze({
      kind: "alignment_grid_cells",
      unitsPerRequest: 2 * 4096 * 4096,
      basis: "the same two grids plus complete witness construction"
    })
  }),
  security_identifier_comparison_max: Object.freeze({
    operation: "security",
    arguments: {
      text: taggedScalar(latin),
      mode: "identifier",
      profile: "uts39_general_security",
      comparison: taggedScalar(cyrillic),
      confusableDirection: "LTR",
      detailLimit: 0
    },
    workModel: Object.freeze({
      kind: "explicit_text_code_units",
      unitsPerRequest: latin.length + cyrillic.length,
      basis: "two confusable identifier inputs at the combined UTF-8 ceiling"
    })
  }),
  security_source_overlap_max: Object.freeze({
    operation: "security",
    arguments: {
      source: taggedScalar(`${latin}${cyrillic}`),
      mode: "source",
      spans: sourceSpans(),
      confusableDirection: "LTR",
      detailLimit: 128
    },
    workModel: Object.freeze({
      kind: "conservative_source_skeleton_code_units",
      unitsPerRequest: 2730 + (128 * 1365) + (128 * 2730),
      basis: "source scan plus 128 explicit span skeletons and the 128 largest detailed same-scope pair sides"
    })
  }),
  protocol_precis_compare_full_max: Object.freeze({
    operation: "protocol_profile",
    arguments: {
      profile: "precis_username_case_mapped",
      action: "compare",
      text: taggedScalar("Ａ".repeat(1365)),
      comparison: taggedScalar("Ａ".repeat(1365)),
      witnessMode: "full_required"
    },
    workModel: Object.freeze({
      kind: "explicit_protocol_code_units",
      unitsPerRequest: 2730,
      basis: "two full-width PRECIS sides at the combined UTF-8 ceiling with complete witnesses"
    })
  }),
  protocol_uts46_full_max: Object.freeze({
    operation: "protocol_profile",
    arguments: {
      profile: "uts46_domain",
      action: "to_ascii",
      text: taggedScalar(maximumDomain),
      options: uts46Options(),
      witnessMode: "full_required"
    },
    workModel: Object.freeze({
      kind: "explicit_protocol_code_units",
      unitsPerRequest: maximumDomain.length,
      basis: "64 maximum DNS labels under the 4096-byte text ceiling with a complete witness"
    })
  }),
  protocol_uts46_punycode_max: Object.freeze({
    operation: "protocol_profile",
    arguments: {
      profile: "uts46_domain",
      action: "to_ascii",
      text: taggedScalar(maximumPunycodeLabel),
      options: { ...uts46Options(), checkBidi: false, verifyDNSLength: false },
      witnessMode: "full_required"
    },
    workModel: Object.freeze({
      kind: "uts46_punycode_scalar_steps",
      unitsPerRequest: maximumPunycodeLabel.length ** 2,
      basis: "1365 distinct mapped CJK scalars in one label, recording a conservative square for repeated Punycode scans"
    })
  }),
  namespace_protocol_relations_max: Object.freeze({
    operation: "namespace_integrity",
    arguments: {
      items: namespaceItems(),
      relations: [
        "uts39_confusable",
        { kind: "protocol", profile: "uts46_domain", action: "to_ascii", options: uts46Options() },
        { kind: "protocol", profile: "precis_username_case_mapped", action: "enforce" },
        { kind: "protocol", profile: "precis_username_case_preserved", action: "enforce" },
        { kind: "protocol", profile: "precis_opaque_string", action: "enforce" }
      ],
      confusableDirection: "LTR"
    },
    workModel: Object.freeze({
      kind: "namespace_relation_text_code_units",
      unitsPerRequest: 512 * 127 * 5,
      basis: "512 explicit items at 65,024 cumulative text units across five expensive relation plans"
    })
  })
});

function requestFor(name) {
  const candidate = candidates[name];
  if (candidate === undefined) throw new Error(`unknown candidate ${name}`);
  return { operation: candidate.operation, arguments: candidate.arguments };
}

function frameFor(name, scale) {
  const request = requestFor(name);
  if (scale === "single") return Buffer.from(JSON.stringify([request]));
  if (scale !== "maximum") throw new Error(`unknown scale ${scale}`);
  let low = 1;
  let high = REFERENCE_WASM_RAW_ABI.maxBatchRequests;
  let best = null;
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const input = Buffer.from(JSON.stringify(Array.from({ length: middle }, () => request)));
    if (input.length <= REFERENCE_WASM_RAW_ABI.maxInputBytes) {
      best = { input, requestCount: middle };
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  if (best === null) throw new Error(`${name} cannot fit one request in the raw frame`);
  return best.input;
}

function frameSummary(name, scale, input) {
  const requestCount = JSON.parse(input).length;
  const workModel = candidates[name].workModel;
  const workLimit = workModel.kind === "alignment_grid_cells"
    ? REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells
    : workModel.kind === "conservative_source_skeleton_code_units"
      ? REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits
      : workModel.kind === "uts46_punycode_scalar_steps"
        ? REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits
        : null;
  return {
    candidate: name,
    scale,
    requestCount,
    inputBytes: input.length,
    modeledWork: {
      ...workModel,
      aggregateUnits: workModel.unitsPerRequest * requestCount,
      rawFrameLimit: workLimit,
      exceedsRawFrameLimit: workLimit === null
        ? false
        : workModel.unitsPerRequest * requestCount > workLimit
    }
  };
}

function nativeMeasurement(name, scale) {
  const input = frameFor(name, scale);
  const started = performance.now();
  const child = spawnSync("/usr/bin/time", ["-l", NATIVE_BINARY], {
    cwd: ROOT,
    input,
    encoding: "buffer",
    maxBuffer: 16 << 20,
    timeout: 120000
  });
  const elapsedMs = performance.now() - started;
  const stderr = Buffer.from(child.stderr ?? []).toString("utf8");
  const maximumResidentMatch = stderr.match(/([0-9]+)\s+maximum resident set size/u);
  return {
    ...frameSummary(name, scale, input),
    runtime: "rust_native",
    elapsedMs,
    exitStatus: child.status,
    signal: child.signal,
    errorCode: child.error?.code ?? null,
    outputBytes: Buffer.from(child.stdout ?? []).length,
    maximumResidentBytes: maximumResidentMatch === null
      ? null
      : Number(maximumResidentMatch[1])
  };
}

async function wasmMeasurement(name, scale) {
  const input = frameFor(name, scale);
  const instantiated = await WebAssembly.instantiate(readFileSync(WASM_BINARY), {});
  const instance = instantiated.instance;
  const pointer = instance.exports.ti_alloc(input.length);
  if (pointer === 0) throw new Error(`WASM rejected ${input.length} input bytes`);
  new Uint8Array(instance.exports.memory.buffer, pointer, input.length).set(input);
  const started = performance.now();
  const status = instance.exports.ti_run(pointer, input.length);
  const elapsedMs = performance.now() - started;
  const outputBytes = instance.exports.ti_result_len();
  instance.exports.ti_dealloc(pointer, input.length);
  return {
    ...frameSummary(name, scale, input),
    runtime: "rust_wasm",
    elapsedMs,
    rawStatus: status,
    outputBytes,
    linearMemoryBytes: instance.exports.memory.buffer.byteLength,
    maximumResidentBytes: process.resourceUsage().maxRSS * 1024
  };
}

function wasmWorker(name, scale) {
  const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--wasm-worker", name, scale], {
    cwd: ROOT,
    encoding: "utf8",
    maxBuffer: 4 << 20,
    timeout: 120000
  });
  if (child.status !== 0) {
    const input = frameFor(name, scale);
    return {
      ...frameSummary(name, scale, input),
      runtime: "rust_wasm",
      exitStatus: child.status,
      signal: child.signal,
      errorCode: child.error?.code ?? null,
      stderr: child.stderr.trim()
    };
  }
  return JSON.parse(child.stdout);
}

if (process.argv[2] === "--wasm-worker") {
  process.stdout.write(JSON.stringify(await wasmMeasurement(process.argv[3], process.argv[4])));
} else if (process.argv[2] === "--describe") {
  const descriptions = Object.keys(candidates).flatMap((name) => ["single", "maximum"].map((scale) => {
    const input = frameFor(name, scale);
    return frameSummary(name, scale, input);
  }));
  process.stdout.write(`${JSON.stringify({
    authority: "static_frame_calculation",
    thresholdStatus: "raw_abi_v2_enforced_for_expensive_operations",
    rawAbi: REFERENCE_WASM_RAW_ABI,
    descriptions
  }, null, 2)}\n`);
} else {
  const requested = process.argv.slice(2);
  const scaleArgument = requested.find((value) => value.startsWith("--scale="));
  const scales = scaleArgument === undefined
    ? ["single", "maximum"]
    : [scaleArgument.slice("--scale=".length)];
  if (scales.some((scale) => !["single", "maximum"].includes(scale))) {
    throw new Error("--scale must be single or maximum");
  }
  const candidateArguments = requested.filter((value) => !value.startsWith("--scale="));
  const selected = candidateArguments.length === 0
    ? Object.keys(candidates)
    : candidateArguments;
  for (const name of selected) {
    if (!Object.hasOwn(candidates, name)) throw new Error(`unknown candidate ${name}`);
  }
  const measurements = [];
  for (const name of selected) {
    for (const scale of scales) {
      measurements.push(nativeMeasurement(name, scale));
      measurements.push(wasmWorker(name, scale));
    }
  }
  process.stdout.write(`${JSON.stringify({
    authority: "current_runtime_measurement",
    thresholdStatus: "raw_abi_v2_enforced_for_expensive_operations",
    environment: {
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
      cpuCount: os.cpus().length,
      loadAverage: os.loadavg()
    },
    rawAbi: REFERENCE_WASM_RAW_ABI,
    measurements
  }, null, 2)}\n`);
}
