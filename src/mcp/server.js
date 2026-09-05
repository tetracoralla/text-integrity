import { TOOL_BY_NAME, TOOL_DEFINITIONS } from "../contracts.js";
import { executeOperation } from "../core/operations.js";
import { TextIntegrityError, errorPayload } from "../core/errors.js";
import { LIMITS } from "../core/limits.js";
import { summarizeResult } from "./summary.js";
import { PRODUCT_NAME, VERSION } from "../version.js";
import { parseUtf8Json } from "../transport-json.js";
import { valueMatchesSchema } from "../reference/json-validation.js";
import {
  PUBLIC_RESULT_SCHEMA_VERSION,
  RESULT_SCHEMA_RESOURCE_LIST,
  resultSchemaResourceForOperation,
  resultSchemaResourceForUri
} from "../result-contract.js";

const SERVER_INFO = Object.freeze({ name: PRODUCT_NAME, version: VERSION });

const MODERN_PROTOCOL_VERSION = "2026-07-28";
const LEGACY_PROTOCOL_VERSIONS = Object.freeze([
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
  "2024-10-07"
]);
const LATEST_LEGACY_PROTOCOL_VERSION = LEGACY_PROTOCOL_VERSIONS[0];
const STRUCTURED_CONTENT_LEGACY_MIN = LEGACY_PROTOCOL_VERSIONS.indexOf("2025-06-18");
const SUPPORTED_PROTOCOL_VERSIONS = Object.freeze([MODERN_PROTOCOL_VERSION, ...LEGACY_PROTOCOL_VERSIONS]);
const PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion";
const SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo";
const CATALOG_TTL_MS = 86_400_000;
const DISCOVER_TTL_MS = 3_600_000;

const ERROR_UNSUPPORTED_PROTOCOL_VERSION = -32022;
const ERROR_NOT_INITIALIZED = -32002;
const ERROR_REQUEST_DEADLINE_EXCEEDED = -32003;

function validId(id) {
  if (!(id === null || typeof id === "string" || (typeof id === "number" && Number.isFinite(id)))) return false;
  return Buffer.byteLength(JSON.stringify(id), "utf8") <= LIMITS.maxJsonRpcIdBytes;
}

function legacySupportsStructuredContent(negotiatedVersion) {
  return LEGACY_PROTOCOL_VERSIONS.indexOf(negotiatedVersion) <= STRUCTURED_CONTENT_LEGACY_MIN;
}

function modernMeta(operation = undefined) {
  const schemaResource = operation === undefined ? null : resultSchemaResourceForOperation(operation);
  return {
    [SERVER_INFO_META_KEY]: SERVER_INFO,
    ...(schemaResource === null ? {} : {
      "text-integrity/publicResultContract": PUBLIC_RESULT_SCHEMA_VERSION,
      "text-integrity/resultSchemaUri": schemaResource.uri
    })
  };
}

function toolResultModern(value, isError, operation) {
  return {
    resultType: "complete",
    content: [{ type: "text", text: summarizeResult(value) }],
    structuredContent: value,
    isError,
    _meta: modernMeta(operation)
  };
}

function toolResultLegacy(value, isError, negotiatedVersion) {
  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    ...(legacySupportsStructuredContent(negotiatedVersion) ? { structuredContent: value } : {}),
    isError
  };
}

function callTool(message) {
  const tool = TOOL_BY_NAME.get(message.params?.name);
  if (!tool) {
    return {
      protocolError: { code: -32602, message: "Unknown tool" }
    };
  }
  const arguments_ = message.params?.arguments ?? {};
  if (!valueMatchesSchema(arguments_, tool.inputSchema)) {
    return {
      protocolError: {
        code: -32602,
        message: "Invalid tool arguments",
        data: { tool: tool.name }
      }
    };
  }
  try {
    return { value: executeOperation(tool.operation, arguments_), isError: false, operation: tool.operation };
  } catch (error) {
    return { value: errorPayload(error), isError: true, operation: tool.operation };
  }
}

function listedTools(toolDefinitions) {
  return toolDefinitions.map(({ operation: _operation, ...tool }) => tool);
}

export function createMcpSession({ toolDefinitions = TOOL_DEFINITIONS } = {}) {
  let initialized = false;
  let negotiatedLegacyVersion = LATEST_LEGACY_PROTOCOL_VERSION;

  function handleMessage(message) {
    const hasId = message !== null && typeof message === "object" && Object.hasOwn(message, "id");
    const id = hasId && validId(message.id) ? message.id : null;
    if (message?.jsonrpc !== "2.0" || typeof message?.method !== "string" || (hasId && !validId(message.id))) {
      return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } };
    }
    if (!hasId) return null;

    const meta = message.params?._meta;
    const requestedVersion = meta !== null && typeof meta === "object" ? meta[PROTOCOL_VERSION_META_KEY] : undefined;

    if (requestedVersion !== undefined) {
      if (requestedVersion !== MODERN_PROTOCOL_VERSION) {
        return {
          jsonrpc: "2.0",
          id,
          error: {
            code: ERROR_UNSUPPORTED_PROTOCOL_VERSION,
            message: "Unsupported protocol version",
            data: { supported: SUPPORTED_PROTOCOL_VERSIONS, requested: requestedVersion }
          }
        };
      }
      return boundedResponse(
        handleModernRequest(message, id),
        id,
        message.method === "tools/list" ? LIMITS.maxToolCatalogBytes : LIMITS.maxMcpResultBytes
      );
    }

    if (message.method === "initialize") {
      const requested = message.params?.protocolVersion;
      negotiatedLegacyVersion = LEGACY_PROTOCOL_VERSIONS.includes(requested)
        ? requested
        : LATEST_LEGACY_PROTOCOL_VERSION;
      initialized = true;
      return boundedResponse({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: negotiatedLegacyVersion,
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false }
          },
          serverInfo: SERVER_INFO
        }
      }, id);
    }

    if (!initialized) {
      return {
        jsonrpc: "2.0",
        id,
        error: {
          code: ERROR_NOT_INITIALIZED,
          message: "Server not initialized",
          data: { supported: SUPPORTED_PROTOCOL_VERSIONS }
        }
      };
    }
    return boundedResponse(
      handleLegacyRequest(message, id),
      id,
      message.method === "tools/list" ? LIMITS.maxToolCatalogBytes : LIMITS.maxMcpResultBytes
    );
  }

  function handleModernRequest(message, id) {
    if (message.method === "server/discover") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          resultType: "complete",
          supportedVersions: SUPPORTED_PROTOCOL_VERSIONS,
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false }
          },
          _meta: modernMeta(),
          ttlMs: DISCOVER_TTL_MS,
          cacheScope: "public"
        }
      };
    }
    if (message.method === "tools/list") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          resultType: "complete",
          tools: listedTools(toolDefinitions),
          _meta: modernMeta(),
          ttlMs: CATALOG_TTL_MS,
          cacheScope: "public"
        }
      };
    }
    if (message.method === "resources/list") {
      return {
        jsonrpc: "2.0",
        id,
        result: {
          resultType: "complete",
          resources: RESULT_SCHEMA_RESOURCE_LIST,
          _meta: modernMeta(),
          ttlMs: CATALOG_TTL_MS,
          cacheScope: "public"
        }
      };
    }
    if (message.method === "resources/read") {
      const resource = resultSchemaResourceForUri(message.params?.uri);
      if (resource === null) {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: "Unknown result schema resource" } };
      }
      return {
        jsonrpc: "2.0",
        id,
        result: {
          resultType: "complete",
          contents: [{ uri: resource.uri, mimeType: resource.mimeType, text: JSON.stringify(resource.schema) }],
          _meta: modernMeta(),
          ttlMs: CATALOG_TTL_MS,
          cacheScope: "public"
        }
      };
    }
    if (message.method === "tools/call") {
      const { value, isError, operation, protocolError } = callTool(message);
      if (protocolError !== undefined) return { jsonrpc: "2.0", id, error: protocolError };
      return { jsonrpc: "2.0", id, result: toolResultModern(value, isError, operation) };
    }
    return { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } };
  }

  function handleLegacyRequest(message, id) {
    if (message.method === "ping") return { jsonrpc: "2.0", id, result: {} };
    if (message.method === "tools/list") {
      return { jsonrpc: "2.0", id, result: { tools: listedTools(toolDefinitions) } };
    }
    if (message.method === "resources/list") {
      return { jsonrpc: "2.0", id, result: { resources: RESULT_SCHEMA_RESOURCE_LIST } };
    }
    if (message.method === "resources/read") {
      const resource = resultSchemaResourceForUri(message.params?.uri);
      if (resource === null) {
        return { jsonrpc: "2.0", id, error: { code: -32602, message: "Unknown result schema resource" } };
      }
      return {
        jsonrpc: "2.0",
        id,
        result: { contents: [{ uri: resource.uri, mimeType: resource.mimeType, text: JSON.stringify(resource.schema) }] }
      };
    }
    if (message.method === "tools/call") {
      const { value, isError, protocolError } = callTool(message);
      if (protocolError !== undefined) return { jsonrpc: "2.0", id, error: protocolError };
      return { jsonrpc: "2.0", id, result: toolResultLegacy(value, isError, negotiatedLegacyVersion) };
    }
    return { jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } };
  }

  return { handleMessage, isInitialized: () => initialized };
}

function boundedResponse(response, id, limit = LIMITS.maxMcpResultBytes) {
  if (Buffer.byteLength(JSON.stringify(response), "utf8") <= limit) return response;
  const value = errorPayload(new TextIntegrityError(
    "RESULT_TOO_LARGE",
    `The complete MCP response exceeds ${limit} bytes.`
  ));
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: -32001,
      message: value.error.message,
      data: value.error
    }
  };
}

function idKey(id) {
  return JSON.stringify(id);
}

// One cooperative loop owns all progress: it drains the bounded request queue,
// then splits complete lines from the input buffer. It suspends whenever the
// output stream is backpressured or the queue is full, so buffered memory stays
// bounded by LIMITS regardless of how fast the peer writes.
export function runMcpServer(input = process.stdin, output = process.stdout) {
  const session = createMcpSession();
  const cancelledIds = new Set();
  const requestQueue = [];
  let buffer = Buffer.alloc(0);
  let discardingOversizedLine = false;
  let advancing = false;
  let scheduled = false;
  let sliceBudget = LIMITS.mcpRequestsPerSlice;
  let outputBlocked = false;
  let inputPausedByUs = false;

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    setImmediate(() => {
      scheduled = false;
      advance();
    });
  }

  function pauseReading() {
    if (!inputPausedByUs && typeof input.pause === "function") {
      input.pause();
      inputPausedByUs = true;
    }
  }

  function maybeResumeReading() {
    if (inputPausedByUs && !outputBlocked && requestQueue.length <= Math.floor(LIMITS.maxMcpQueuedRequests / 2)) {
      inputPausedByUs = false;
      if (typeof input.resume === "function") input.resume();
    }
  }

  function writeResponse(response) {
    if (!output.write(`${JSON.stringify(response)}\n`)) outputBlocked = true;
  }

  function enqueueResponse(response) {
    requestQueue.push({
      response,
      key: null,
      deadlineAt: Number.POSITIVE_INFINITY
    });
  }

  function handleNotification(message) {
    if (message.method === "notifications/cancelled") {
      const requestId = message.params?.requestId;
      if (validId(requestId)) {
        if (cancelledIds.size > LIMITS.maxMcpQueuedRequests * 2) cancelledIds.clear();
        cancelledIds.add(idKey(requestId));
      }
    }
  }

  function handleLine(line) {
    let message;
    try {
      message = parseUtf8Json(line);
    } catch {
      enqueueResponse({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      return;
    }
    if (message === null || typeof message !== "object" || Array.isArray(message)) {
      enqueueResponse({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
      return;
    }
    if (!Object.hasOwn(message, "id")) {
      handleNotification(message);
      return;
    }
    const requestId = validId(message.id) ? message.id : null;
    requestQueue.push({
      message,
      responseId: requestId,
      key: requestId === null ? null : idKey(requestId),
      deadlineAt: Date.now() + LIMITS.mcpRequestDeadlineMs
    });
  }

  // Returns true while making progress through complete lines.
  function takeLine() {
    while (true) {
      if (buffer.length === 0) return false;
      const newline = buffer.indexOf(0x0a);
      if (newline === -1) {
        if (discardingOversizedLine) {
          buffer = Buffer.alloc(0);
          return false;
        }
        if (buffer.length > LIMITS.maxMcpMessageBytes) {
          discardingOversizedLine = true;
          enqueueResponse({
            jsonrpc: "2.0",
            id: null,
            error: { code: -32600, message: `Message exceeds ${LIMITS.maxMcpMessageBytes} bytes` }
          });
          return true;
        }
        return false;
      }
      const line = buffer.subarray(0, newline);
      buffer = buffer.subarray(newline + 1);
      if (discardingOversizedLine) {
        discardingOversizedLine = false;
        continue;
      }
      if (line.length > LIMITS.maxMcpMessageBytes) {
        enqueueResponse({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32600, message: `Message exceeds ${LIMITS.maxMcpMessageBytes} bytes` }
        });
        continue;
      }
      if (line.toString("utf8").trim() === "") continue;
      handleLine(line);
      return true;
    }
  }

  function advance() {
    if (advancing) return;
    advancing = true;
    try {
      while (true) {
        if (requestQueue.length >= LIMITS.maxMcpQueuedRequests) pauseReading();
        if (requestQueue.length > 0 && !outputBlocked && sliceBudget > 0) {
          sliceBudget -= 1;
          const entry = requestQueue.shift();
          if (entry.key !== null && cancelledIds.delete(entry.key)) continue;
          if (entry.response !== undefined) {
            writeResponse(entry.response);
            maybeResumeReading();
            continue;
          }
          if (Date.now() > entry.deadlineAt) {
            writeResponse({
              jsonrpc: "2.0",
              id: entry.responseId,
              error: {
                code: ERROR_REQUEST_DEADLINE_EXCEEDED,
                message: "Request deadline exceeded before execution",
                data: { deadlineMs: LIMITS.mcpRequestDeadlineMs }
              }
            });
            continue;
          }
          const response = entry.response ?? session.handleMessage(entry.message);
          if (response !== null) writeResponse(response);
          maybeResumeReading();
          continue;
        }
        // Requests cannot run now (blocked output, slice boundary, or an empty
        // queue). Keep splitting lines so cancellation notifications reach
        // requests that are still waiting; execution order stays FIFO.
        if (requestQueue.length >= LIMITS.maxMcpQueuedRequests) {
          pauseReading();
          if (!outputBlocked && sliceBudget === 0) {
            sliceBudget = LIMITS.mcpRequestsPerSlice;
            schedule();
          }
          break;
        }
        if (!takeLine()) {
          if (requestQueue.length === 0) {
            cancelledIds.clear();
            maybeResumeReading();
          } else if (!outputBlocked && sliceBudget === 0) {
            sliceBudget = LIMITS.mcpRequestsPerSlice;
            schedule();
          }
          break;
        }
      }
    } finally {
      advancing = false;
    }
    if (outputBlocked || requestQueue.length >= LIMITS.maxMcpQueuedRequests) pauseReading();
  }

  output.on("drain", () => {
    outputBlocked = false;
    schedule();
  });

  input.on("data", (chunk) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    buffer = buffer.length === 0 ? bytes : Buffer.concat([buffer, bytes]);
    schedule();
  });
}
