import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertByteBudget, assertTextBudget, enforceResultBudget } from "./limits.js";
import { assertPinnedUnicodeRuntime, runtimeInfo } from "./runtime.js";
import { observeSecurity } from "./security.js";
import { compareWithCollator } from "./collation.js";
import { explainDifference } from "./difference.js";
import { applyProtocolProfile } from "./protocol.js";
import { diagnoseSource } from "./source-diagnostics.js";
import { indexText } from "./text-position.js";
import { buildTranscodeWitness } from "./transcode-witness.js";
import { decodeByteSegments, decodedText, decodeTextSegments } from "./transcode-codec.js";
import { normalizeUnicode17, normalizeUnicode17WithWitness } from "./normalization.js";
import { segmentGraphemesUnicode17 } from "./grapheme.js";
import {
  assertKeys,
  requireBoolean,
  requireEnum,
  requireInteger,
  requireObject,
  requireString
} from "./validation.js";

const NORMALIZATION_FORMS = Object.freeze(["NFC", "NFD", "NFKC", "NFKD"]);
const ENCODINGS = Object.freeze(["utf-8", "utf-16le"]);
const BYTE_REPRESENTATIONS = Object.freeze(["bytes", "hex", "base64"]);
const WITNESS_MODES = Object.freeze(["none", "summary", "full_required"]);

function requireEncoding(value, field) {
  if (typeof value !== "string" || !ENCODINGS.includes(value)) {
    throw new TextIntegrityError("UNSUPPORTED_ENCODING", `${field} is not supported.`, {
      field,
      requestedType: value === null ? "null" : Array.isArray(value) ? "array" : typeof value,
      supported: ENCODINGS
    });
  }
  return value;
}

function inspect(args) {
  requireObject(args);
  assertKeys(args, ["text", "detailLimit"], ["text"]);
  const value = requireString(args.text, "text");
  assertTextBudget(value, "text");
  const detailLimit = Object.hasOwn(args, "detailLimit")
    ? requireInteger(args.detailLimit, "detailLimit", 0, LIMITS.maxDetailItems)
    : LIMITS.defaultDetailItems;

  const codePoints = [];
  const inputWellFormed = value.isWellFormed();
  let codePointCount = 0;
  let codeUnitIndex = 0;
  for (const character of value) {
    const codeUnit = character.charCodeAt(0);
    const unpairedSurrogate = character.length === 1 && codeUnit >= 0xd800 && codeUnit <= 0xdfff;
    if (codePoints.length < detailLimit) {
      const numeric = character.codePointAt(0);
      codePoints.push({
        indexCodeUnit: codeUnitIndex,
        value: `U+${numeric.toString(16).toUpperCase().padStart(4, "0")}`,
        character,
        kind: unpairedSurrogate ? "unpaired_surrogate" : "scalar",
        utf8Hex: unpairedSurrogate ? null : Buffer.from(character, "utf8").toString("hex")
      });
    }
    codePointCount += 1;
    codeUnitIndex += character.length;
  }

  const graphemes = [];
  let graphemeCount = 0;
  for (const part of segmentGraphemesUnicode17(value)) {
    if (graphemes.length < detailLimit) {
      graphemes.push({ indexCodeUnit: part.index, text: part.segment });
    }
    graphemeCount += 1;
  }

  return {
    status: "ok",
    operation: "inspect",
    inputWellFormed,
    counts: {
      utf16CodeUnits: value.length,
      codePoints: codePointCount,
      graphemes: graphemeCount,
      utf8Bytes: inputWellFormed ? Buffer.byteLength(value, "utf8") : null,
      utf16leBytes: Buffer.byteLength(value, "utf16le")
    },
    encodings: {
      utf8: {
        wellFormed: inputWellFormed,
        byteLength: inputWellFormed ? Buffer.byteLength(value, "utf8") : null,
        hex: inputWellFormed ? Buffer.from(value, "utf8").toString("hex") : null
      },
      utf16le: {
        wellFormed: inputWellFormed,
        byteLength: Buffer.byteLength(value, "utf16le"),
        hex: Buffer.from(value, "utf16le").toString("hex")
      }
    },
    detail: {
      limit: detailLimit,
      codePoints,
      codePointsTruncated: codePointCount > codePoints.length,
      graphemes,
      graphemesTruncated: graphemeCount > graphemes.length
    },
    runtime: runtimeInfo()
  };
}

function assertWellFormed(value, field) {
  if (!value.isWellFormed()) {
    throw new TextIntegrityError("INVALID_UNICODE", `${field} contains an unpaired UTF-16 surrogate.`, { field });
  }
}

function normalize(args) {
  requireObject(args);
  assertKeys(args, ["text", "form", "witnessMode"], ["text", "form"]);
  const value = requireString(args.text, "text");
  assertTextBudget(value, "text");
  assertWellFormed(value, "text");
  const form = requireEnum(args.form, "form", NORMALIZATION_FORMS);
  const witnessMode = Object.hasOwn(args, "witnessMode")
    ? requireEnum(args.witnessMode, "witnessMode", WITNESS_MODES)
    : "none";
  const transformation = witnessMode === "none"
    ? { normalized: normalizeUnicode17(value, form) }
    : normalizeUnicode17WithWitness(value, form, witnessMode);
  const { normalized } = transformation;

  return {
    status: "ok",
    operation: "normalize",
    form,
    original: value,
    normalized,
    changed: value !== normalized,
    canonicalEquivalent: normalizeUnicode17(value, "NFD") === normalizeUnicode17(normalized, "NFD"),
    compatibilityEquivalent: normalizeUnicode17(value, "NFKD") === normalizeUnicode17(normalized, "NFKD"),
    bytes: {
      originalUtf8: Buffer.byteLength(value, "utf8"),
      normalizedUtf8: Buffer.byteLength(normalized, "utf8")
    },
    ...(transformation.witness === undefined ? {} : { witness: transformation.witness }),
    runtime: runtimeInfo()
  };
}

function compare(args) {
  requireObject(args);
  assertKeys(args, ["left", "right", "locale", "options"], ["left", "right", "locale", "options"]);
  const left = requireString(args.left, "left");
  const right = requireString(args.right, "right");
  assertTextBudget(left, "left");
  assertTextBudget(right, "right");
  assertWellFormed(left, "left");
  assertWellFormed(right, "right");
  return compareWithCollator(left, right, args);
}

function requireBytes(value) {
  if (!Array.isArray(value)) {
    throw new TextIntegrityError("INVALID_INPUT", "bytes must be an array.", { field: "bytes" });
  }
  assertByteBudget(value);
  for (let index = 0; index < value.length; index += 1) {
    if (!Number.isInteger(value[index]) || value[index] < 0 || value[index] > 255) {
      throw new TextIntegrityError("INVALID_INPUT", "Every byte must be an integer from 0 to 255.", {
        field: "bytes",
        index
      });
    }
  }
  return Uint8Array.from(value);
}

function decodeBytes(bytes, encoding, allowLossy) {
  const segments = decodeByteSegments(bytes, encoding);
  const invalidByte = segments.find((segment) => segment.kind === "replacement")?.sourceStart ?? null;
  if (invalidByte !== null && !allowLossy) {
    throw new TextIntegrityError("DECODE_FAILED", `bytes are not valid ${encoding}.`, {
      encoding,
      firstInvalidByte: invalidByte
    });
  }
  return {
    text: decodedText(segments),
    segments,
    lossy: invalidByte !== null,
    firstInvalidByte: invalidByte,
    warnings: invalidByte === null
      ? []
      : ["Invalid source byte sequences were replaced with U+FFFD during decoding."]
  };
}

function bomKind(bytes, encoding) {
  if (encoding === "utf-8" && bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return "utf-8";
  }
  if (encoding === "utf-16le" && bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return "utf-16le";
  }
  return null;
}

function encodeText(value, encoding) {
  return encoding === "utf-8" ? Buffer.from(value, "utf8") : Buffer.from(value, "utf16le");
}

function transcode(args) {
  requireObject(args);
  const sourceKind = requireEnum(args.sourceKind, "sourceKind", ["text", "bytes"]);
  const targetEncoding = requireEncoding(args.targetEncoding, "targetEncoding");
  const allowLossy = requireBoolean(args.allowLossy, "allowLossy");
  const byteRepresentation = requireEnum(args.byteRepresentation, "byteRepresentation", BYTE_REPRESENTATIONS);
  const witnessMode = Object.hasOwn(args, "witnessMode")
    ? requireEnum(args.witnessMode, "witnessMode", WITNESS_MODES)
    : "none";
  let text;
  let source;
  let sourceText;
  let sourceBytes;
  let sourceEncoding;
  let sourceSegments;
  let lossy = false;
  let warnings = [];

  if (sourceKind === "text") {
    assertKeys(args, ["sourceKind", "text", "targetEncoding", "allowLossy", "byteRepresentation", "witnessMode"], [
      "sourceKind",
      "text",
      "targetEncoding",
      "allowLossy",
      "byteRepresentation"
    ]);
    sourceText = requireString(args.text, "text");
    assertTextBudget(sourceText, "text");
    sourceSegments = decodeTextSegments(sourceText);
    const inputWellFormed = sourceSegments.every((segment) => segment.kind === "scalar");
    if (!inputWellFormed) {
      if (!allowLossy) {
        throw new TextIntegrityError("INVALID_UNICODE", "text contains an unpaired UTF-16 surrogate.", { field: "text" });
      }
      lossy = true;
      warnings.push("Unpaired UTF-16 surrogates were replaced with U+FFFD before encoding.");
    }
    text = decodedText(sourceSegments);
    source = { kind: "text", inputWellFormed };
  } else {
    assertKeys(args, ["sourceKind", "bytes", "sourceEncoding", "targetEncoding", "allowLossy", "byteRepresentation", "witnessMode"], [
      "sourceKind",
      "bytes",
      "sourceEncoding",
      "targetEncoding",
      "allowLossy",
      "byteRepresentation"
    ]);
    sourceEncoding = requireEncoding(args.sourceEncoding, "sourceEncoding");
    sourceBytes = requireBytes(args.bytes);
    const decoded = decodeBytes(sourceBytes, sourceEncoding, allowLossy);
    text = decoded.text;
    sourceSegments = decoded.segments;
    lossy = decoded.lossy;
    warnings = decoded.warnings;
    source = {
      kind: "bytes",
      encoding: sourceEncoding,
      byteLength: sourceBytes.length,
      bom: bomKind(sourceBytes, sourceEncoding),
      firstInvalidByte: decoded.firstInvalidByte,
      decodedThenReencodedEqual: !decoded.lossy
        && Buffer.from(encodeText(text, sourceEncoding)).equals(Buffer.from(sourceBytes))
    };
  }

  const encoded = encodeText(text, targetEncoding);
  const witness = witnessMode === "none" ? undefined : buildTranscodeWitness({
    mode: witnessMode,
    sourceKind,
    sourceSegments,
    targetEncoding,
    decodedText: text,
    bom: source.kind === "bytes" ? source.bom : null
  });
  return {
    status: "ok",
    operation: "transcode",
    source,
    targetEncoding,
    byteRepresentation,
    text,
    ...(byteRepresentation === "bytes" ? { bytes: [...encoded] } : {}),
    ...(byteRepresentation === "hex" ? { hex: encoded.toString("hex") } : {}),
    ...(byteRepresentation === "base64" ? { base64: encoded.toString("base64") } : {}),
    byteLength: encoded.length,
    lossy,
    warnings,
    ...(witness === undefined ? {} : { witness }),
    runtime: runtimeInfo()
  };
}

function security(args) {
  return args?.mode === "source" ? diagnoseSource(args) : observeSecurity(args);
}

const EXECUTORS = Object.freeze({
  inspect,
  normalize,
  compare,
  transcode,
  security,
  explain_difference: explainDifference,
  index: indexText,
  protocol_profile: applyProtocolProfile
});

export function executeOperation(name, args) {
  const executor = EXECUTORS[name];
  if (!executor) {
    throw new TextIntegrityError("UNKNOWN_OPERATION", `Unknown operation: ${name}.`, {
      allowed: Object.keys(EXECUTORS)
    });
  }
  assertPinnedUnicodeRuntime("Text Integrity core");
  return enforceResultBudget(executor(args));
}

export const SUPPORTED_OPERATIONS = Object.freeze(Object.keys(EXECUTORS));
export const SUPPORTED_ENCODINGS = ENCODINGS;
export const SUPPORTED_NORMALIZATION_FORMS = NORMALIZATION_FORMS;
export const SUPPORTED_BYTE_REPRESENTATIONS = BYTE_REPRESENTATIONS;
export const SUPPORTED_WITNESS_MODES = WITNESS_MODES;
