import { dataLookup, unicodeSecurityData } from "./unicode-security-data.js";

const CONTROLS = new Set(["Control", "CR", "LF"]);

function codePointEntries(text, data) {
  const entries = [];
  let indexUtf16 = 0;
  for (const character of text) {
    const codePoint = character.codePointAt(0);
    entries.push({
      codePoint,
      startUtf16: indexUtf16,
      endUtf16: indexUtf16 + character.length,
      graphemeBreak: dataLookup(data.graphemeBreaks, codePoint) ?? "Other",
      indicConjunctBreak: dataLookup(data.indicConjunctBreak, codePoint) ?? "None",
      extendedPictographic: dataLookup(data.extendedPictographic, codePoint) === true
    });
    indexUtf16 += character.length;
  }
  return entries;
}

function boundaryContexts(entries) {
  const contexts = [];
  let indicConsonant = false;
  let indicLinker = false;
  let pictographicExtendRun = false;
  let emojiZwj = false;
  let regionalIndicators = 0;

  for (const entry of entries) {
    contexts.push({
      indicConjunct: indicConsonant && indicLinker,
      emojiZwj,
      regionalIndicators
    });

    if (entry.indicConjunctBreak === "Consonant") {
      indicConsonant = true;
      indicLinker = false;
    } else if (indicConsonant && ["Extend", "Linker"].includes(entry.indicConjunctBreak)) {
      indicLinker ||= entry.indicConjunctBreak === "Linker";
    } else {
      indicConsonant = false;
      indicLinker = false;
    }

    if (entry.graphemeBreak === "ZWJ") {
      emojiZwj = pictographicExtendRun;
      pictographicExtendRun = false;
    } else {
      emojiZwj = false;
      if (entry.extendedPictographic) pictographicExtendRun = true;
      else if (entry.graphemeBreak !== "Extend") pictographicExtendRun = false;
    }

    regionalIndicators = entry.graphemeBreak === "Regional_Indicator"
      ? regionalIndicators + 1
      : 0;
  }
  return contexts;
}

function breaksBefore(entries, contexts, index) {
  const previous = entries[index - 1];
  const current = entries[index];
  const left = previous.graphemeBreak;
  const right = current.graphemeBreak;

  if (left === "CR" && right === "LF") return false;
  if (CONTROLS.has(left) || CONTROLS.has(right)) return true;
  if (left === "L" && ["L", "V", "LV", "LVT"].includes(right)) return false;
  if (["LV", "V"].includes(left) && ["V", "T"].includes(right)) return false;
  if (["LVT", "T"].includes(left) && right === "T") return false;
  if (["Extend", "ZWJ"].includes(right)) return false;
  if (right === "SpacingMark") return false;
  if (left === "Prepend") return false;
  if (current.indicConjunctBreak === "Consonant" && contexts[index].indicConjunct) return false;
  if (current.extendedPictographic && contexts[index].emojiZwj) return false;
  if (left === "Regional_Indicator" && right === "Regional_Indicator") {
    return contexts[index].regionalIndicators % 2 === 0;
  }
  return true;
}

export function segmentGraphemesUnicode17(text, data = unicodeSecurityData()) {
  const entries = codePointEntries(text, data);
  if (entries.length === 0) return [];
  const contexts = boundaryContexts(entries);
  const segments = [];
  let startUtf16 = 0;
  for (let index = 1; index < entries.length; index += 1) {
    if (!breaksBefore(entries, contexts, index)) continue;
    const endUtf16 = entries[index].startUtf16;
    segments.push({ index: startUtf16, segment: text.slice(startUtf16, endUtf16) });
    startUtf16 = endUtf16;
  }
  segments.push({ index: startUtf16, segment: text.slice(startUtf16) });
  return segments;
}
