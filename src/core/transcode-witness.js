import { TextIntegrityError } from "./errors.js";
import { decodedText as joinDecodedText } from "./transcode-codec.js";

function codePointLabel(text) {
  return `U+${text.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`;
}

function encodedLength(text, encoding) {
  return encoding === "utf-8" ? Buffer.byteLength(text, "utf8") : Buffer.byteLength(text, "utf16le");
}

function decoratedSegments(rawSegments, targetEncoding) {
  let decodedUtf16 = 0;
  let targetByte = 0;
  return rawSegments.map((segment) => {
    const decodedEnd = decodedUtf16 + segment.text.length;
    const targetEnd = targetByte + encodedLength(segment.text, targetEncoding);
    const value = {
      kind: segment.kind,
      codePoint: codePointLabel(segment.text),
      sourceStart: segment.sourceStart,
      sourceEnd: segment.sourceEnd,
      decodedStartUtf16: decodedUtf16,
      decodedEndUtf16: decodedEnd,
      targetStartByte: targetByte,
      targetEndByte: targetEnd
    };
    decodedUtf16 = decodedEnd;
    targetByte = targetEnd;
    return value;
  });
}

export function buildTranscodeWitness({
  mode,
  sourceKind,
  sourceSegments,
  targetEncoding,
  decodedText,
  bom
}) {
  const rawSegments = sourceSegments;
  const reconstructed = joinDecodedText(rawSegments);
  if (reconstructed !== decodedText) {
    throw new TextIntegrityError(
      "INTERNAL_ERROR",
      "The transcode witness did not reproduce the runtime decoder result."
    );
  }
  const segments = decoratedSegments(rawSegments, targetEncoding);
  const summary = {
    mode,
    sourceUnit: sourceKind === "bytes" ? "byte" : "utf16_code_unit",
    segmentCount: segments.length,
    replacementCount: segments.filter((segment) => segment.kind === "replacement").length,
    bom: {
      kind: bom,
      handling: sourceKind === "text" ? "not_applicable" : bom === null ? "not_present" : "preserved_as_character"
    }
  };
  return mode === "full_required" ? { ...summary, segments } : summary;
}
