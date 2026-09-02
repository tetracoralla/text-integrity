function codePoints(value) {
  return value.split(/\s+/u).filter(Boolean).map((item) => Number.parseInt(item, 16));
}

function parseExclusions(text) {
  const ranges = [];
  for (const line of text.split(/\r?\n/u)) {
    const content = line.split("#", 1)[0].trim();
    if (content === "") continue;
    const [range, property] = content.split(";").map((field) => field.trim());
    if (property !== "Full_Composition_Exclusion") continue;
    const [first, last = first] = range.split("..").map((item) => Number.parseInt(item, 16));
    ranges.push([first, last]);
  }
  return ranges;
}

function isExcluded(ranges, codePoint) {
  return ranges.some(([start, end]) => codePoint >= start && codePoint <= end);
}

function asText(points) {
  return points.map((codePoint) => String.fromCodePoint(codePoint)).join("");
}

export function parseNormalizationData(unicodeDataText, derivedNormalizationText) {
  const canonicalDecompositions = [];
  const compatibilityDecompositions = [];
  const canonicalEntries = [];

  for (const line of unicodeDataText.split(/\r?\n/u)) {
    if (line === "") continue;
    const fields = line.split(";");
    if (fields.length < 15) throw new Error("malformed UnicodeData row");
    const raw = fields[5];
    if (raw === "") continue;
    const key = Number.parseInt(fields[0], 16);
    const compatibility = raw.startsWith("<");
    const mapping = codePoints(compatibility ? raw.replace(/^<[^>]+>\s*/u, "") : raw);
    const value = asText(mapping);
    compatibilityDecompositions.push({ key, value });
    if (!compatibility) {
      canonicalDecompositions.push({ key, value });
      canonicalEntries.push({ key, mapping });
    }
  }

  const exclusions = parseExclusions(derivedNormalizationText);
  const compositionMappings = canonicalEntries
    .filter(({ key, mapping }) => mapping.length === 2 && !isExcluded(exclusions, key))
    .map(({ key, mapping }) => ({ first: mapping[0], second: mapping[1], value: key }))
    .sort((left, right) => left.first - right.first || left.second - right.second);

  canonicalDecompositions.sort((left, right) => left.key - right.key);
  compatibilityDecompositions.sort((left, right) => left.key - right.key);
  return { canonicalDecompositions, compatibilityDecompositions, compositionMappings };
}
