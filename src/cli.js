import { readFileSync } from "node:fs";
import { executeOperation, SUPPORTED_OPERATIONS } from "./core/operations.js";
import { LIMITS } from "./core/limits.js";
import { TextIntegrityError, errorPayload } from "./core/errors.js";
import { parseUtf8Json } from "./transport-json.js";
import { TOOL_DEFINITIONS } from "./contracts.js";
import { VERSION } from "./version.js";
import {
  PUBLIC_RESULT_SCHEMA_VERSION,
  RESULT_SCHEMA_RESOURCE_LIST,
  resultSchemaResourceForOperation
} from "./result-contract.js";
const HELP = `text-integrity ${VERSION}

Usage:
  text-integrity <operation> --name value
  text-integrity <operation> --name=value
  text-integrity --json < request.json
  text-integrity --schema
  text-integrity --schema-full <operation>

Operations: inspect, normalize, compare, transcode, security,
            explain_difference, index, protocol_profile

Raw JSON request: {"operation":"inspect","arguments":{"text":"hello"}}
All successful results and all errors are JSON. Values beginning with -- are
accepted with either flag form. Raw JSON preserves escaped unpaired surrogates.
`;

function parseFlags(argv) {
  const flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--") || token === "--") {
      throw new TextIntegrityError("INVALID_INPUT", `Unexpected argument: ${token}.`);
    }
    const equals = token.indexOf("=");
    const key = token.slice(2, equals === -1 ? undefined : equals);
    const value = equals === -1 ? argv[index + 1] : token.slice(equals + 1);
    if (key === "" || value === undefined) {
      throw new TextIntegrityError("INVALID_INPUT", `Missing value for --${key}.`);
    }
    if (Object.hasOwn(flags, key)) {
      throw new TextIntegrityError("INVALID_INPUT", `Duplicate option: --${key}.`);
    }
    flags[key] = value;
    if (equals === -1) index += 1;
  }
  return flags;
}

function booleanFlag(value, name) {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new TextIntegrityError("INVALID_INPUT", `--${name} must be true or false.`);
}

function onlyFlags(flags, allowed) {
  const unknown = Object.keys(flags).filter((name) => !allowed.includes(name));
  if (unknown.length > 0) {
    throw new TextIntegrityError("INVALID_INPUT", "Unknown CLI options are not allowed.", { unknownOptions: unknown.sort() });
  }
}

function required(flags, name) {
  if (!Object.hasOwn(flags, name)) throw new TextIntegrityError("INVALID_INPUT", `Missing required option --${name}.`);
  return flags[name];
}

function optionalInteger(flags, name, target) {
  return Object.hasOwn(flags, name) ? { [target]: Number(flags[name]) } : {};
}

function parseJson(value, name) {
  try {
    return JSON.parse(value);
  } catch {
    throw new TextIntegrityError("INVALID_INPUT", `--${name} must be valid JSON.`);
  }
}

function parseBytes(value) {
  if (value.trim().startsWith("[")) return parseJson(value, "bytes");
  return value.split(",").map((item, index) => {
    const trimmed = item.trim();
    if (trimmed === "") throw new TextIntegrityError("INVALID_INPUT", "--bytes must not contain empty entries.", { index });
    return Number(trimmed);
  });
}

function collation(flags) {
  return {
    usage: required(flags, "usage"),
    sensitivity: required(flags, "sensitivity"),
    ignorePunctuation: booleanFlag(required(flags, "ignore-punctuation"), "ignore-punctuation"),
    numeric: booleanFlag(required(flags, "numeric"), "numeric"),
    caseFirst: required(flags, "case-first"),
    localeMatcher: required(flags, "locale-matcher"),
    collation: required(flags, "collation")
  };
}

const COLLATION_FLAGS = ["left", "right", "locale", "usage", "sensitivity", "ignore-punctuation", "numeric", "case-first", "locale-matcher", "collation"];

export function cliRequest(argv) {
  const [operation, ...rest] = argv;
  if (!operation) throw new TextIntegrityError("INVALID_INPUT", `Expected one of: ${SUPPORTED_OPERATIONS.join(", ")}.`);
  const flags = parseFlags(rest);
  if (operation === "inspect") {
    onlyFlags(flags, ["text", "detail-limit"]);
    return { operation, args: { text: required(flags, "text"), ...optionalInteger(flags, "detail-limit", "detailLimit") } };
  }
  if (operation === "normalize") {
    onlyFlags(flags, ["text", "form", "witness-mode"]);
    return { operation, args: {
      text: required(flags, "text"), form: required(flags, "form"),
      ...(Object.hasOwn(flags, "witness-mode") ? { witnessMode: flags["witness-mode"] } : {})
    } };
  }
  if (operation === "compare" || operation === "explain_difference") {
    const extra = operation === "explain_difference" ? ["confusable-direction", "detail-limit", "witness-mode"] : [];
    onlyFlags(flags, [...COLLATION_FLAGS, ...extra]);
    return {
      operation,
      args: {
        left: required(flags, "left"), right: required(flags, "right"), locale: required(flags, "locale"),
        options: collation(flags),
        ...(operation === "explain_difference" ? {
          confusableDirection: required(flags, "confusable-direction"),
          ...optionalInteger(flags, "detail-limit", "detailLimit"),
          ...(Object.hasOwn(flags, "witness-mode") ? { witnessMode: flags["witness-mode"] } : {})
        } : {})
      }
    };
  }
  if (operation === "security") {
    const mode = required(flags, "mode");
    if (mode === "source") {
      onlyFlags(flags, ["mode", "source", "spans", "confusable-direction", "detail-limit"]);
      return {
        operation,
        args: {
          mode, source: required(flags, "source"), spans: parseJson(required(flags, "spans"), "spans"),
          confusableDirection: required(flags, "confusable-direction"),
          ...optionalInteger(flags, "detail-limit", "detailLimit")
        }
      };
    }
    onlyFlags(flags, ["text", "mode", "profile", "comparison", "confusable-direction", "detail-limit"]);
    return {
      operation,
      args: {
        text: required(flags, "text"), mode,
        ...(mode === "identifier" ? { profile: required(flags, "profile") } : {}),
        ...(Object.hasOwn(flags, "comparison") ? {
          comparison: flags.comparison,
          confusableDirection: required(flags, "confusable-direction")
        } : {}),
        ...optionalInteger(flags, "detail-limit", "detailLimit")
      }
    };
  }
  if (operation === "transcode") {
    const sourceKind = required(flags, "source-kind");
    const common = {
      sourceKind, targetEncoding: required(flags, "target-encoding"),
      allowLossy: booleanFlag(required(flags, "allow-lossy"), "allow-lossy"),
      byteRepresentation: required(flags, "byte-representation"),
      ...(Object.hasOwn(flags, "witness-mode") ? { witnessMode: flags["witness-mode"] } : {})
    };
    if (sourceKind === "bytes") {
      onlyFlags(flags, ["source-kind", "bytes", "source-encoding", "target-encoding", "allow-lossy", "byte-representation", "witness-mode"]);
      return { operation, args: { ...common, bytes: parseBytes(required(flags, "bytes")), sourceEncoding: required(flags, "source-encoding") } };
    }
    onlyFlags(flags, ["source-kind", "text", "target-encoding", "allow-lossy", "byte-representation", "witness-mode"]);
    return { operation, args: { ...common, text: required(flags, "text") } };
  }
  if (operation === "index") {
    onlyFlags(flags, ["text", "detail-limit", "max-chunk-utf8-bytes"]);
    return { operation, args: {
      text: required(flags, "text"), ...optionalInteger(flags, "detail-limit", "detailLimit"),
      ...optionalInteger(flags, "max-chunk-utf8-bytes", "maxChunkUtf8Bytes")
    } };
  }
  if (operation === "protocol_profile") {
    onlyFlags(flags, ["profile", "action", "text", "comparison", "options", "witness-mode"]);
    return { operation, args: {
      profile: required(flags, "profile"), action: required(flags, "action"), text: required(flags, "text"),
      ...(Object.hasOwn(flags, "comparison") ? { comparison: flags.comparison } : {}),
      ...(Object.hasOwn(flags, "options") ? { options: parseJson(flags.options, "options") } : {}),
      ...(Object.hasOwn(flags, "witness-mode") ? { witnessMode: flags["witness-mode"] } : {})
    } };
  }
  return { operation, args: flags };
}

function rawJsonRequest() {
  const input = readFileSync(0);
  if (input.length > LIMITS.maxCliInputBytes) {
    throw new TextIntegrityError("REQUEST_TOO_LARGE", `CLI JSON input exceeds ${LIMITS.maxCliInputBytes} bytes.`);
  }
  let value;
  try { value = parseUtf8Json(input); }
  catch { throw new TextIntegrityError("INVALID_INPUT", "CLI input must be valid JSON."); }
  if (value === null || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== 2 || !Object.hasOwn(value, "operation") || !Object.hasOwn(value, "arguments")) {
    throw new TextIntegrityError("INVALID_INPUT", "CLI JSON request must contain only operation and arguments.");
  }
  return { operation: value.operation, args: value.arguments };
}

export function runCli(argv) {
  if (argv.length === 1 && argv[0] === "--help") { process.stdout.write(HELP); return 0; }
  if (argv.length === 1 && argv[0] === "--version") { process.stdout.write(`${VERSION}\n`); return 0; }
  if (argv.length === 1 && argv[0] === "--schema") {
    process.stdout.write(`${JSON.stringify({
      version: VERSION,
      publicResultContract: PUBLIC_RESULT_SCHEMA_VERSION,
      strictOutputSchemaResources: RESULT_SCHEMA_RESOURCE_LIST.map(({ operation, uri }) => ({ operation, uri })),
      tools: TOOL_DEFINITIONS.map(({ operation, name, inputSchema, outputSchema }) => ({ operation, tool: name, inputSchema, outputSchema }))
    })}\n`);
    return 0;
  }
  if (argv.length === 2 && argv[0] === "--schema-full") {
    const resource = resultSchemaResourceForOperation(argv[1]);
    if (resource === null) {
      process.stderr.write(`${JSON.stringify(errorPayload(new TextIntegrityError(
        "UNKNOWN_OPERATION",
        "No strict result schema exists for the requested operation.",
        { allowed: RESULT_SCHEMA_RESOURCE_LIST.map(({ operation }) => operation) }
      )))}\n`);
      return 2;
    }
    process.stdout.write(`${JSON.stringify(resource.schema)}\n`);
    return 0;
  }
  try {
    const request = argv.length === 1 && argv[0] === "--json" ? rawJsonRequest() : cliRequest(argv);
    process.stdout.write(`${JSON.stringify(executeOperation(request.operation, request.args))}\n`);
    return 0;
  } catch (error) {
    let payload = errorPayload(error);
    if (Buffer.byteLength(JSON.stringify(payload), "utf8") > LIMITS.maxResultBytes) {
      payload = errorPayload(new TextIntegrityError("RESULT_TOO_LARGE", `The complete CLI error envelope exceeds ${LIMITS.maxResultBytes} bytes.`));
    }
    process.stderr.write(`${JSON.stringify(payload)}\n`);
    return 2;
  }
}
