const SUMMARY_BYTE_BUDGET = 480;

function truncate(value) {
  if (Buffer.byteLength(value, "utf8") <= SUMMARY_BYTE_BUDGET) return value;
  let kept = "";
  for (const character of value) {
    if (Buffer.byteLength(kept + character, "utf8") > SUMMARY_BYTE_BUDGET - 14) break;
    kept += character;
  }
  return `${kept}…[truncated]`;
}

function inspectSummary(value) {
  const { counts, inputWellFormed } = value;
  return `inspect: ${counts.codePoints} code points, ${counts.graphemes} graphemes, `
    + `${counts.utf8Bytes ?? "no"} UTF-8 bytes, ${counts.utf16CodeUnits} UTF-16 units, `
    + `wellFormed=${inputWellFormed}`;
}

function normalizeSummary(value) {
  return `normalize ${value.form}: changed=${value.changed}, `
    + `canonicalEquivalent=${value.canonicalEquivalent}, `
    + `compatibilityEquivalent=${value.compatibilityEquivalent}`;
}

function compareSummary(value) {
  return `compare [${value.canonicalLocale}]: relation=${value.relation}, order=${value.order}, `
    + `collatesEqual=${value.collatesEqual}, codeUnitEqual=${value.codeUnitEqual}, `
    + `canonicalEquivalent=${value.canonicalEquivalent}`;
}

function transcodeSummary(value) {
  return `transcode -> ${value.targetEncoding}: ${value.byteLength} bytes as ${value.byteRepresentation}, `
    + `lossy=${value.lossy}${value.warnings.length > 0 ? `, warnings=${value.warnings.length}` : ""}`;
}

function securitySummary(value) {
  if (value.mode === "source") {
    const diagnostics = value.diagnostics;
    return `source diagnostics: spans=${value.spans.count} (identifiers=${value.spans.identifiers}), `
      + `hiddenCharacters=${diagnostics.hiddenCharacters.count}, `
      + `abnormalLineEndings=${diagnostics.abnormalLineEndings.count}, `
      + `confusableIdentifierPairs=${diagnostics.confusableIdentifiers.count}`;
  }
  const signals = value.observations.signalCounts;
  const base = `security ${value.mode}: codePoints=${value.observations.counts.codePoints}, `
    + `bidiControls=${signals.bidiControls}, defaultIgnorables=${signals.defaultIgnorables}, `
    + `formatCharacters=${signals.formatCharacters}`;
  if (value.mode === "identifier") {
    const profile = value.identifierProfile;
    const confusable = value.confusableComparison
      ? `, confusable=${value.confusableComparison.relation}`
      : "";
    return `${base}, profile=${profile.name}, conforms=${profile.conforms}, `
      + `restrictionLevel=${profile.restrictionLevel}${confusable}`;
  }
  return base;
}

function explainDifferenceSummary(value) {
  return `explain_difference: exactEqual=${value.exact.equal}, `
    + `NFC=${value.normalization.NFC.equal}, NFKC=${value.normalization.NFKC.equal}, `
    + `nfkcCasefoldEqual=${value.nfkcCasefold.equal}, `
    + `collation=${value.collation.relation}, `
    + `confusable=${value.identifierConfusableComparison.relation}`;
}

function indexSummary(value) {
  const counts = value.counts;
  const chunks = value.chunking ? `, chunks=${value.chunking.chunks.length}` : "";
  return `index: ${counts.utf8Bytes} UTF-8 bytes, ${counts.utf16CodeUnits} UTF-16 units, `
    + `${counts.codePoints} code points, ${counts.graphemes} graphemes, ${counts.lines} lines${chunks}`;
}

function protocolProfileSummary(value) {
  const comparison = value.action === "compare"
    ? `, equal=${value.equal}`
    : "";
  return `protocol_profile ${value.profile}/${value.action}: changed=${value.changed}${comparison}`;
}

function errorSummary(value) {
  const error = value.error ?? {};
  return `error ${error.code ?? "UNKNOWN"}: ${error.message ?? "The operation failed."}`;
}

const SUMMARIES = Object.freeze({
  inspect: inspectSummary,
  normalize: normalizeSummary,
  compare: compareSummary,
  transcode: transcodeSummary,
  security: securitySummary,
  source_diagnose: securitySummary,
  explain_difference: explainDifferenceSummary,
  index: indexSummary,
  protocol_profile: protocolProfileSummary
});

export function summarizeResult(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return truncate("text-integrity: result is not an object");
  }
  if (value.status === "error") return truncate(errorSummary(value));
  const summarizer = SUMMARIES[value.operation] ?? ((result) => `${result.operation ?? "unknown"}: ok`);
  return truncate(summarizer(value));
}
