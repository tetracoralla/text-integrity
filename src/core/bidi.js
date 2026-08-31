import bidiFactory from "../../vendor/bidi-js-unicode17/bidi.mjs";
import { dataLookup } from "./unicode-security-data.js";

const bidi = bidiFactory();

const CLASS_REPRESENTATIVES = Object.freeze({
  L: "A",
  R: "א",
  EN: "0",
  ES: "+",
  ET: "#",
  AN: "٠",
  CS: ",",
  B: "\u2029",
  S: "\t",
  WS: " ",
  ON: "!",
  BN: "\u00AD",
  NSM: "\u036F",
  AL: "ە",
  LRO: "\u202D",
  RLO: "\u202E",
  LRE: "\u202A",
  RLE: "\u202B",
  PDF: "\u202C",
  LRI: "\u2066",
  RLI: "\u2067",
  FSI: "\u2068",
  PDI: "\u2069"
});

export function bidiClassFor(data, codePoint) {
  const explicit = dataLookup(data.bidiClasses, codePoint);
  if (explicit) return explicit;
  for (let index = data.bidiMissing.length - 1; index >= 0; index -= 1) {
    const range = data.bidiMissing[index];
    if (codePoint >= range.start && codePoint <= range.end) return range.value;
  }
  return "L";
}

function proxyCharacter(data, character) {
  const codePoint = character.codePointAt(0);
  if (codePoint <= 0xffff) return character;
  return CLASS_REPRESENTATIVES[bidiClassFor(data, codePoint)] ?? "A";
}

function applyCombiningMarkReordering(data, entries) {
  for (let index = 0; index < entries.length;) {
    const combining = dataLookup(data.combiningClasses, entries[index].character.codePointAt(0)) ?? 0;
    if (combining === 0 || entries[index].level % 2 === 0) {
      index += 1;
      continue;
    }

    const start = index;
    while (index < entries.length) {
      const entryCombining = dataLookup(data.combiningClasses, entries[index].character.codePointAt(0)) ?? 0;
      if (entryCombining === 0 || entries[index].level % 2 === 0) break;
      index += 1;
    }
    if (index < entries.length && entries[index].level % 2 === 1) {
      const reversed = entries.slice(start, index + 1).reverse();
      entries.splice(start, reversed.length, ...reversed);
      index = start + reversed.length;
    }
  }
}

export function reorderForDisplay(data, text, direction) {
  const characters = [...text];
  const proxy = characters.map((character) => proxyCharacter(data, character)).join("");
  const baseDirection = direction === "LTR" ? "ltr" : direction === "RTL" ? "rtl" : "auto";
  const embedding = bidi.getEmbeddingLevels(proxy, baseDirection);
  const order = bidi.getReorderedIndices(proxy, embedding);
  const entries = order.map((index) => ({
    character: characters[index],
    logicalCodePointIndex: index,
    level: embedding.levels[index]
  }));

  applyCombiningMarkReordering(data, entries);
  for (const entry of entries) {
    if (entry.level % 2 === 0) continue;
    const mirrored = data.bidiMirroring.get(entry.character.codePointAt(0));
    if (mirrored !== undefined) entry.character = String.fromCodePoint(mirrored);
  }

  return {
    text: entries.map((entry) => entry.character).join(""),
    entries,
    paragraphLevels: embedding.paragraphs.map((paragraph) => paragraph.level)
  };
}

export function bidiConformanceEngine() {
  return bidi;
}

export const BIDI_ENGINE = Object.freeze({
  name: "bidi-js-unicode17-adapter",
  upstreamVersion: "1.0.3",
  unicodeVersion: "17.0.0",
  conformance: ["BidiTest.txt", "BidiCharacterTest.txt"]
});
