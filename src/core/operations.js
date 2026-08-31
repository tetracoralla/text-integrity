import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertByteBudget, assertTextBudget, enforceResultBudget } from "./limits.js";
import { assertPinnedUnicodeRuntime, runtimeInfo } from "./runtime.js";
import { observeSecurity } from "./security.js";
import { compareWithCollator } from "./collation.js";
import { explainDifference } from "./difference.js";
import { applyProtocolProfile } from "./protocol.js";
import { diagnoseSource } from "./source-diagnostics.js";
import { indexText } from "./text-position.js";
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

function requireEncoding(value, field) {
  if (typeof value !== "string" || !ENCODINGS.includes(value)) {
    throw new TextIntegrityError("UNSUPPORTED_ENCODING", `${field} is not supported.`, {
      field,
      requested: value,
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
  const segmenter = new Intl.Segmenter(undefined, { granularity: "grapheme" });
  for (const part of segmenter.segment(value)) {
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
  assertKeys(args, ["text", "form"], ["text", "form"]);
  const value = requireString(args.text, "text");
  assertTextBudget(value, "text");
  assertWellFormed(value, "text");
  const form = requireEnum(args.form, "form", NORMALIZATION_FORMS);
  const normalized = value.normalize(form);

  return {
    status: "ok",
    operation: "normalize",
    form,
    original: value,
    normalized,
    changed: value !== normalized,
    canonicalEquivalent: value.normalize("NFD") === normalized.normalize("NFD"),
    compatibilityEquivalent: value.normalize("NFKD") === normalized.normalize("NFKD"),
    bytes: {
      originalUtf8: Buffer.byteLength(value, "utf8"),
      normalizedUtf8: Buffer.byteLength(normalized, "utf8")
    },
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

function firstInvalidByte(bytes, encoding) {
  if (encoding === "utf-16le") {
    if (bytes.length % 2 !== 0) return bytes.length - 1;
    for (let index = 0; index < bytes.length; index += 2) {
      const unit = bytes[index] | (bytes[index + 1] << 8);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        if (index + 3 >= bytes.length) return index;
        const next = bytes[index + 2] | (bytes[index + 3] << 8);
        if (next < 0xdc00 || next > 0xdfff) return index;
        index += 2;
      } else if (unit >= 0xdc00 && unit <= 0xdfff) {
        return index;
      }
    }
    return null;
  }
  const continuation = (value) => value >= 0x80 && value <= 0xbf;
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index];
    if (first <= 0x7f) { index += 1; continue; }
    let length;
    if (first >= 0xc2 && first <= 0xdf) length = 2;
    else if (first >= 0xe0 && first <= 0xef) length = 3;
    else if (first >= 0xf0 && first <= 0xf4) length = 4;
    else return index;
    if (index + length > bytes.length) return index;
    const second = bytes[index + 1];
    if (!continuation(second)) return index;
    if ((first === 0xe0 && second < 0xa0) || (first === 0xed && second > 0x9f)
      || (first === 0xf0 && second < 0x90) || (first === 0xf4 && second > 0x8f)) return index;
    for (let offset = 2; offset < length; offset += 1) if (!continuation(bytes[index + offset])) return index;
    index += length;
  }
  return null;
}

function decodeBytes(bytes, encoding, allowLossy) {
  try {
    return {
      text: new TextDecoder(encoding, { fatal: true, ignoreBOM: true }).decode(bytes),
      lossy: false,
      firstInvalidByte: null,
      warnings: []
    };
  } catch {
    const invalidByte = firstInvalidByte(bytes, encoding);
    if (!allowLossy) {
      throw new TextIntegrityError("DECODE_FAILED", `bytes are not valid ${encoding}.`, {
        encoding,
        firstInvalidByte: invalidByte
      });
    }
    return {
      text: new TextDecoder(encoding, { fatal: false, ignoreBOM: true }).decode(bytes),
      lossy: true,
      firstInvalidByte: invalidByte,
      warnings: ["Invalid source byte sequences were replaced with U+FFFD during decoding."]
    };
  }
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
  let text;
  let source;
  let lossy = false;
  let warnings = [];

  if (sourceKind === "text") {
    assertKeys(args, ["sourceKind", "text", "targetEncoding", "allowLossy", "byteRepresentation"], [
      "sourceKind",
      "text",
      "targetEncoding",
      "allowLossy",
      "byteRepresentation"
    ]);
    text = requireString(args.text, "text");
    assertTextBudget(text, "text");
    if (!text.isWellFormed()) {
      if (!allowLossy) {
        throw new TextIntegrityError("INVALID_UNICODE", "text contains an unpaired UTF-16 surrogate.", { field: "text" });
      }
      text = text.toWellFormed();
      lossy = true;
      warnings.push("Unpaired UTF-16 surrogates were replaced with U+FFFD before encoding.");
    }
    source = { kind: "text", inputWellFormed: args.text.isWellFormed() };
  } else {
    assertKeys(args, ["sourceKind", "bytes", "sourceEncoding", "targetEncoding", "allowLossy", "byteRepresentation"], [
      "sourceKind",
      "bytes",
      "sourceEncoding",
      "targetEncoding",
      "allowLossy",
      "byteRepresentation"
    ]);
    const sourceEncoding = requireEncoding(args.sourceEncoding, "sourceEncoding");
    const bytes = requireBytes(args.bytes);
    const decoded = decodeBytes(bytes, sourceEncoding, allowLossy);
    text = decoded.text;
    lossy = decoded.lossy;
    warnings = decoded.warnings;
    source = {
      kind: "bytes",
      encoding: sourceEncoding,
      byteLength: bytes.length,
      bom: bomKind(bytes, sourceEncoding),
      firstInvalidByte: decoded.firstInvalidByte,
      decodedThenReencodedEqual: !decoded.lossy
        && Buffer.from(encodeText(text, sourceEncoding)).equals(Buffer.from(bytes))
    };
  }

  const encoded = encodeText(text, targetEncoding);
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
