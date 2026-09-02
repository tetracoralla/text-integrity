import { dataLookup, unicodeProtocolData } from "./unicode-security-data.js";

function hasCasedBefore(codePoints, index, data) {
  for (let cursor = index - 1; cursor >= 0; cursor -= 1) {
    const codePoint = codePoints[cursor];
    if (dataLookup(data.cased, codePoint) === true) return true;
    if (dataLookup(data.caseIgnorable, codePoint) !== true) return false;
  }
  return false;
}

function hasCasedAfter(codePoints, index, data) {
  for (let cursor = index + 1; cursor < codePoints.length; cursor += 1) {
    const codePoint = codePoints[cursor];
    if (dataLookup(data.cased, codePoint) === true) return true;
    if (dataLookup(data.caseIgnorable, codePoint) !== true) return false;
  }
  return false;
}

function isFinalSigma(codePoints, index, data) {
  return codePoints[index] === 0x03a3
    && hasCasedBefore(codePoints, index, data)
    && !hasCasedAfter(codePoints, index, data);
}

export function lowercaseUnicode17(text, data = unicodeProtocolData()) {
  const codePoints = [...text].map((character) => character.codePointAt(0));
  let output = "";
  for (const [index, codePoint] of codePoints.entries()) {
    if (isFinalSigma(codePoints, index, data)) {
      output += "\u03c2";
    } else {
      output += data.lowercaseMappings.get(codePoint) ?? String.fromCodePoint(codePoint);
    }
  }
  return output;
}
