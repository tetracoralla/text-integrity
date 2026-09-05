const SOURCE_KINDS = new Set(["text", "bytes"]);

export function createTranscodeSourceDrafts(initialKind, initialValue = "") {
  if (!SOURCE_KINDS.has(initialKind) || typeof initialValue !== "string") {
    throw new TypeError("A valid transcode source kind and string draft are required.");
  }
  const drafts = new Map([["text", ""], ["bytes", ""]]);
  drafts.set(initialKind, initialValue);
  let activeKind = initialKind;

  return Object.freeze({
    switchTo(nextKind, currentValue) {
      if (!SOURCE_KINDS.has(nextKind) || typeof currentValue !== "string") {
        throw new TypeError("A valid transcode source kind and string draft are required.");
      }
      drafts.set(activeKind, currentValue);
      activeKind = nextKind;
      return drafts.get(nextKind);
    }
  });
}
