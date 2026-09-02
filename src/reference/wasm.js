import { OUTPUT_SCHEMAS } from "../output-schemas.js";
import {
  BoundedJsonDepthError,
  DuplicateJsonKeyError,
  assertUniqueJsonObjectKeys,
  validateJsonGraph,
  valueMatchesSchema
} from "./json-validation.js";

const SUPPORTED_OPERATIONS = Object.freeze([
  "index", "inspect", "normalize", "protocol_profile", "security", "transcode"
]);

export const REFERENCE_WASM_MODULE_INTERFACE = Object.freeze({
  imports: Object.freeze([]),
  exports: Object.freeze([
    Object.freeze({ name: "memory", kind: "memory" }),
    Object.freeze({ name: "ti_alloc", kind: "function" }),
    Object.freeze({ name: "ti_dealloc", kind: "function" }),
    Object.freeze({ name: "ti_run", kind: "function" }),
    Object.freeze({ name: "ti_abi_version", kind: "function" }),
    Object.freeze({ name: "ti_max_input_len", kind: "function" }),
    Object.freeze({ name: "ti_max_batch_len", kind: "function" }),
    Object.freeze({ name: "ti_max_result_len", kind: "function" }),
    Object.freeze({ name: "ti_max_difference_alignment_cells", kind: "function" }),
    Object.freeze({ name: "ti_max_source_diagnostic_units", kind: "function" }),
    Object.freeze({ name: "ti_max_uts46_punycode_scan_units", kind: "function" }),
    Object.freeze({ name: "ti_result_ptr", kind: "function" }),
    Object.freeze({ name: "ti_result_len", kind: "function" }),
    Object.freeze({ name: "__data_end", kind: "global" }),
    Object.freeze({ name: "__heap_base", kind: "global" })
  ])
});

const REQUIRED_FUNCTION_EXPORTS = Object.freeze(
  REFERENCE_WASM_MODULE_INTERFACE.exports
    .filter(({ kind }) => kind === "function")
    .map(({ name }) => name)
);

export const REFERENCE_WASM_RAW_ABI = Object.freeze({
  version: 2,
  maxInputBytes: 1048576,
  maxBatchRequests: 1024,
  maxResultBytes: 8388608,
  workLimits: Object.freeze({
    differenceAlignmentCells: 33554432,
    sourceDiagnosticUnits: 1576960,
    uts46PunycodeScanUnits: 16777216
  }),
  statuses: Object.freeze({
    ok: 0,
    invalidInputBuffer: 1,
    inputTooLarge: 2,
    batchTooLarge: 3,
    resultTooLarge: 4,
    differenceAlignmentWorkTooLarge: 5,
    sourceDiagnosticWorkTooLarge: 6,
    uts46PunycodeWorkTooLarge: 7
  })
});

export const REFERENCE_WASM_LIMITS = Object.freeze({
  maxRequestBytes: 131072,
  maxResultBytes: 65536,
  maxJsonDepth: 64,
  maxJsonNodes: 65536,
  maxObjectKeys: 256,
  maxArrayItems: 32768,
  maxStringCodeUnits: 65536,
  maxIdentifierCodeUnits: 512
});

function omitSchemaPath(schema, path) {
  for (const branch of schema.oneOf ?? []) omitSchemaPath(branch, path);
  if (schema.type !== "object" || path.length === 0) return;
  const [field, ...remaining] = path;
  if (!Object.hasOwn(schema.properties ?? {}, field)) return;
  if (remaining.length === 0) {
    delete schema.properties[field];
    if (Array.isArray(schema.required)) {
      schema.required = schema.required.filter((name) => name !== field);
    }
    return;
  }
  omitSchemaPath(schema.properties[field], remaining);
}

function semanticSchema(operation) {
  const schema = JSON.parse(JSON.stringify(OUTPUT_SCHEMAS[operation]));
  omitSchemaPath(schema, ["runtime"]);
  if (operation === "security") omitSchemaPath(schema, ["confusableComparison", "engine"]);
  if (operation === "protocol_profile") {
    omitSchemaPath(schema, ["standards", "engine"]);
    omitSchemaPath(schema, ["witness", "engine"]);
  }
  return schema;
}

const SEMANTIC_OUTPUT_SCHEMAS = Object.freeze(Object.fromEntries(
  SUPPORTED_OPERATIONS.map((operation) => [operation, semanticSchema(operation)])
));

function requireClosedRequest(request) {
  const unknown = Object.keys(request)
    .filter((field) => !["operation", "arguments"].includes(field))
    .sort();
  if (unknown.length > 0) {
    throw new TypeError(`Reference WASM request has unknown fields: ${unknown.join(", ")}.`);
  }
  const missing = ["operation", "arguments"].filter((field) => !Object.hasOwn(request, field));
  if (missing.length > 0) {
    throw new TypeError(`Reference WASM request is missing fields: ${missing.join(", ")}.`);
  }
  if (typeof request.operation !== "string" || !SUPPORTED_OPERATIONS.includes(request.operation)) {
    throw new TypeError("Reference WASM operation is not publicly supported.");
  }
}

function requireWasmInstance(instance) {
  if (instance === null || typeof instance !== "object"
    || instance.exports === null || typeof instance.exports !== "object") {
    throw new TypeError("Reference WASM did not instantiate to an export object.");
  }
  if (!(instance.exports.memory instanceof WebAssembly.Memory)) {
    throw new TypeError("Reference WASM export memory must be a WebAssembly.Memory.");
  }
  for (const name of REQUIRED_FUNCTION_EXPORTS) {
    if (typeof instance.exports[name] !== "function") {
      throw new TypeError(`Reference WASM export ${name} must be a function.`);
    }
  }
  for (const [name, expected] of Object.entries({
    ti_abi_version: REFERENCE_WASM_RAW_ABI.version,
    ti_max_input_len: REFERENCE_WASM_RAW_ABI.maxInputBytes,
    ti_max_batch_len: REFERENCE_WASM_RAW_ABI.maxBatchRequests,
    ti_max_result_len: REFERENCE_WASM_RAW_ABI.maxResultBytes,
    ti_max_difference_alignment_cells:
      REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells,
    ti_max_source_diagnostic_units:
      REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits,
    ti_max_uts46_punycode_scan_units:
      REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits
  })) {
    const actual = instance.exports[name]();
    if (!Number.isSafeInteger(actual) || actual !== expected) {
      throw new TypeError(
        `Reference WASM export ${name} returned ${String(actual)}; expected ${expected}.`
      );
    }
  }
}

function rawStatusError(status) {
  if (status === REFERENCE_WASM_RAW_ABI.statuses.invalidInputBuffer) {
    return new Error("Reference WASM rejected an unowned or mismatched request buffer (status 1).");
  }
  if (status === REFERENCE_WASM_RAW_ABI.statuses.inputTooLarge) {
    return new RangeError(
      `Reference WASM raw request frame exceeds ${REFERENCE_WASM_RAW_ABI.maxInputBytes} bytes (status 2).`
    );
  }
  if (status === REFERENCE_WASM_RAW_ABI.statuses.batchTooLarge) {
    return new RangeError(
      `Reference WASM raw request frame exceeds ${REFERENCE_WASM_RAW_ABI.maxBatchRequests} requests (status 3).`
    );
  }
  if (status === REFERENCE_WASM_RAW_ABI.statuses.resultTooLarge) {
    return new RangeError(
      `Reference WASM raw result frame exceeds ${REFERENCE_WASM_RAW_ABI.maxResultBytes} bytes (status 4).`
    );
  }
  if (status === REFERENCE_WASM_RAW_ABI.statuses.differenceAlignmentWorkTooLarge) {
    return new RangeError(
      `Reference WASM raw request frame exceeds ${REFERENCE_WASM_RAW_ABI.workLimits.differenceAlignmentCells} difference-alignment cells (status 5).`
    );
  }
  if (status === REFERENCE_WASM_RAW_ABI.statuses.sourceDiagnosticWorkTooLarge) {
    return new RangeError(
      `Reference WASM raw request frame exceeds ${REFERENCE_WASM_RAW_ABI.workLimits.sourceDiagnosticUnits} source-diagnostic units (status 6).`
    );
  }
  if (status === REFERENCE_WASM_RAW_ABI.statuses.uts46PunycodeWorkTooLarge) {
    return new RangeError(
      `Reference WASM raw request frame exceeds ${REFERENCE_WASM_RAW_ABI.workLimits.uts46PunycodeScanUnits} UTS #46 Punycode scan units (status 7).`
    );
  }
  return new Error(`Reference WASM returned unknown raw ABI status ${String(status)}.`);
}

function requireMemoryRange(pointer, length, memoryBytes, field) {
  if (!Number.isSafeInteger(pointer) || pointer < 0) {
    throw new RangeError(`Reference WASM ${field} pointer is outside linear memory.`);
  }
  if (!Number.isSafeInteger(length) || length < 0 || pointer + length > memoryBytes) {
    throw new RangeError(`Reference WASM ${field} range is outside linear memory.`);
  }
}

function projectSemanticResult(operation, result) {
  if (result?.status === "ok") {
    delete result.runtime;
    if (operation === "security" && result.confusableComparison !== null
      && typeof result.confusableComparison === "object"
      && !Array.isArray(result.confusableComparison)) {
      delete result.confusableComparison.engine;
    }
    if (operation === "protocol_profile") {
      if (result.standards !== null && typeof result.standards === "object"
        && !Array.isArray(result.standards)) delete result.standards.engine;
      if (result.witness !== null && typeof result.witness === "object"
        && !Array.isArray(result.witness)) delete result.witness.engine;
    }
  } else if (result?.status === "error" && result.error?.code === "RESULT_TOO_LARGE"
    && result.error.details !== null && typeof result.error.details === "object"
    && !Array.isArray(result.error.details)) {
    delete result.error.details.actualBytes;
    delete result.error.details.metadataBytes;
  }
  return result;
}

function parseSemanticResult(operation, bytes, decoder) {
  let json;
  try {
    json = decoder.decode(bytes);
  } catch (error) {
    throw new TypeError("Reference WASM result must be well-formed UTF-8.", { cause: error });
  }
  let result;
  try {
    assertUniqueJsonObjectKeys(json, {
      maxDepth: REFERENCE_WASM_LIMITS.maxJsonDepth,
      subject: "Reference WASM result JSON"
    });
    result = JSON.parse(json);
  } catch (error) {
    if (error instanceof DuplicateJsonKeyError || error instanceof BoundedJsonDepthError) {
      throw error;
    }
    throw new TypeError("Reference WASM result must contain valid JSON.", { cause: error });
  }
  validateJsonGraph(result, {
    limits: REFERENCE_WASM_LIMITS,
    field: "result",
    rootLabel: "Reference WASM result"
  });
  const semantic = projectSemanticResult(operation, result);
  if (!valueMatchesSchema(semantic, SEMANTIC_OUTPUT_SCHEMAS[operation])) {
    throw new TypeError(
      `Reference WASM ${operation} result does not match its closed semantic public result schema.`
    );
  }
  return semantic;
}

export async function createReferenceWasmRunner(source) {
  const instantiated = await WebAssembly.instantiate(source, {});
  const instance = instantiated instanceof WebAssembly.Instance
    ? instantiated
    : instantiated.instance;
  requireWasmInstance(instance);
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });

  return Object.freeze({
    supportedOperations: SUPPORTED_OPERATIONS,
    run(request) {
      if (request === null || typeof request !== "object" || Array.isArray(request)) {
        throw new TypeError("Reference WASM accepts one explicit request object.");
      }
      validateJsonGraph(request, {
        limits: REFERENCE_WASM_LIMITS,
        field: "request",
        rootLabel: "Reference WASM request"
      });
      let snapshot;
      try {
        snapshot = structuredClone(request);
      } catch (error) {
        throw new TypeError(
          "Reference WASM request must be a structured-cloneable JSON value.",
          { cause: error }
        );
      }
      requireClosedRequest(snapshot);
      const input = encoder.encode(JSON.stringify(snapshot));
      if (input.length > REFERENCE_WASM_LIMITS.maxRequestBytes) {
        throw new RangeError(
          `Reference WASM request exceeds ${REFERENCE_WASM_LIMITS.maxRequestBytes} bytes.`
        );
      }

      const pointer = instance.exports.ti_alloc(input.length);
      if (input.length > 0 && pointer === 0) {
        throw new RangeError("Reference WASM could not allocate the request.");
      }
      requireMemoryRange(pointer, input.length, instance.exports.memory.buffer.byteLength, "request");
      let status;
      try {
        new Uint8Array(instance.exports.memory.buffer, pointer, input.length).set(input);
        status = instance.exports.ti_run(pointer, input.length);
      } finally {
        instance.exports.ti_dealloc(pointer, input.length);
      }
      if (!Number.isInteger(status) || status !== REFERENCE_WASM_RAW_ABI.statuses.ok) {
        throw rawStatusError(status);
      }

      const resultPointer = instance.exports.ti_result_ptr();
      const resultLength = instance.exports.ti_result_len();
      if (!Number.isSafeInteger(resultLength) || resultLength < 0) {
        throw new RangeError("Reference WASM result length is invalid.");
      }
      if (resultLength > REFERENCE_WASM_LIMITS.maxResultBytes) {
        throw new RangeError(
          `Reference WASM result exceeds ${REFERENCE_WASM_LIMITS.maxResultBytes} bytes.`
        );
      }
      requireMemoryRange(
        resultPointer,
        resultLength,
        instance.exports.memory.buffer.byteLength,
        "result"
      );
      const resultBytes = new Uint8Array(
        instance.exports.memory.buffer,
        resultPointer,
        resultLength
      ).slice();
      return parseSemanticResult(snapshot.operation, resultBytes, decoder);
    }
  });
}
