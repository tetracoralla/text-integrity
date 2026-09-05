import { dataLookup, unicodeNormalizationData } from "./unicode-security-data.js";

const FORMS = new Set(["NFC", "NFD", "NFKC", "NFKD"]);
const S_BASE = 0xac00;
const L_BASE = 0x1100;
const V_BASE = 0x1161;
const T_BASE = 0x11a7;
const L_COUNT = 19;
const V_COUNT = 21;
const T_COUNT = 28;
const N_COUNT = V_COUNT * T_COUNT;
const S_COUNT = L_COUNT * N_COUNT;

function combiningClass(data, codePoint) {
  return dataLookup(data.combiningClasses, codePoint) ?? 0;
}

function appendOrdered(output, codePoint, data) {
  const canonicalClass = combiningClass(data, codePoint);
  let index = output.length;
  while (canonicalClass !== 0 && index > 0) {
    const precedingClass = output[index - 1].canonicalClass;
    if (precedingClass === 0 || precedingClass <= canonicalClass) break;
    index -= 1;
  }
  output.splice(index, 0, { codePoint, canonicalClass });
}

function hangulDecomposition(codePoint) {
  const syllableIndex = codePoint - S_BASE;
  if (syllableIndex < 0 || syllableIndex >= S_COUNT) return null;
  const leading = L_BASE + Math.floor(syllableIndex / N_COUNT);
  const vowel = V_BASE + Math.floor((syllableIndex % N_COUNT) / T_COUNT);
  const trailing = T_BASE + (syllableIndex % T_COUNT);
  return trailing === T_BASE ? [leading, vowel] : [leading, vowel, trailing];
}

function decomposeCodePoint(data, codePoint, compatibility, output, raw) {
  const hangul = hangulDecomposition(codePoint);
  if (hangul !== null) {
    for (const part of hangul) {
      raw.push(part);
      appendOrdered(output, part, data);
    }
    return;
  }
  const mappings = compatibility ? data.compatibilityDecompositions : data.canonicalDecompositions;
  const mapping = mappings.get(codePoint);
  if (mapping === undefined) {
    raw.push(codePoint);
    appendOrdered(output, codePoint, data);
    return;
  }
  for (const character of mapping) {
    decomposeCodePoint(data, character.codePointAt(0), compatibility, output, raw);
  }
}

function decompose(data, text, compatibility) {
  const output = [];
  const raw = [];
  for (const character of text) {
    decomposeCodePoint(data, character.codePointAt(0), compatibility, output, raw);
  }
  return { ordered: output, raw };
}

function composeHangul(starter, current) {
  const leadingIndex = starter - L_BASE;
  if (leadingIndex >= 0 && leadingIndex < L_COUNT) {
    const vowelIndex = current - V_BASE;
    if (vowelIndex >= 0 && vowelIndex < V_COUNT) {
      return S_BASE + (leadingIndex * V_COUNT + vowelIndex) * T_COUNT;
    }
  }
  const syllableIndex = starter - S_BASE;
  const trailingIndex = current - T_BASE;
  if (syllableIndex >= 0 && syllableIndex < S_COUNT && syllableIndex % T_COUNT === 0
    && trailingIndex > 0 && trailingIndex < T_COUNT) {
    return starter + trailingIndex;
  }
  return undefined;
}

function composePair(data, starter, current) {
  return composeHangul(starter, current) ?? data.compositionMappings.get(starter, current);
}

function compose(data, decomposed, captureSteps) {
  if (decomposed.length === 0) return { codePoints: [], count: 0, steps: [] };
  const output = [decomposed[0].codePoint];
  const steps = [];
  let count = 0;
  let starterPosition = 0;
  let starter = decomposed[0].codePoint;
  let precedingClass = decomposed[0].canonicalClass;

  for (const item of decomposed.slice(1)) {
    const composite = composePair(data, starter, item.codePoint);
    if (composite !== undefined && (precedingClass === 0 || precedingClass < item.canonicalClass)) {
      if (captureSteps) {
        steps.push({
          starter: starter,
          current: item.codePoint,
          composite,
          outputIndexCodePoint: starterPosition
        });
      }
      output[starterPosition] = composite;
      starter = composite;
      count += 1;
      continue;
    }
    if (item.canonicalClass === 0) {
      starterPosition = output.length;
      starter = item.codePoint;
    }
    output.push(item.codePoint);
    precedingClass = item.canonicalClass;
  }
  return { codePoints: output, count, steps };
}

function label(codePoint) {
  return `U+${codePoint.toString(16).toUpperCase().padStart(4, "0")}`;
}

function normalization(data, text, form, witnessMode) {
  if (!FORMS.has(form)) throw new RangeError(`Unsupported normalization form: ${form}`);
  const compatibility = form === "NFKC" || form === "NFKD";
  const decomposed = decompose(data, text, compatibility);
  const composeResult = form === "NFC" || form === "NFKC"
    ? compose(data, decomposed.ordered, witnessMode === "full_required")
    : { codePoints: decomposed.ordered.map((item) => item.codePoint), count: 0, steps: [] };
  const normalized = composeResult.codePoints.map((codePoint) => String.fromCodePoint(codePoint)).join("");
  if (witnessMode === "none") return { normalized };

  const input = [...text].map((character) => character.codePointAt(0));
  const ordered = decomposed.ordered.map((item) => item.codePoint);
  const summary = {
    mode: witnessMode,
    specification: "Unicode Standard Annex #15",
    unicodeVersion: "17.0.0",
    inputCodePointCount: input.length,
    decomposedCodePointCount: decomposed.raw.length,
    decompositionChanged: input.length !== decomposed.raw.length
      || input.some((codePoint, index) => codePoint !== decomposed.raw[index]),
    canonicalReorderedPositionCount: decomposed.raw.reduce(
      (count, codePoint, index) => count + (codePoint === ordered[index] ? 0 : 1),
      0
    ),
    compositionCount: composeResult.count,
    outputCodePointCount: composeResult.codePoints.length
  };
  if (witnessMode === "summary") return { normalized, witness: summary };
  return {
    normalized,
    witness: {
      ...summary,
      stages: {
        input: input.map(label),
        decomposed: decomposed.raw.map(label),
        canonicalOrdered: ordered.map(label),
        compositions: composeResult.steps.map((step) => ({
          starter: label(step.starter),
          current: label(step.current),
          composite: label(step.composite),
          outputIndexCodePoint: step.outputIndexCodePoint
        }))
      }
    }
  };
}

export function normalizeUnicode17(text, form, data = unicodeNormalizationData()) {
  return normalization(data, text, form, "none").normalized;
}

export function normalizeUnicode17WithWitness(text, form, witnessMode, data = unicodeNormalizationData()) {
  if (witnessMode !== "summary" && witnessMode !== "full_required") {
    throw new RangeError(`Unsupported normalization witness mode: ${witnessMode}`);
  }
  return normalization(data, text, form, witnessMode);
}
