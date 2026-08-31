import { TextIntegrityError } from "./errors.js";

export const PINNED_UNICODE_VERSION = "17.0";

export function runtimeInfo() {
  return {
    node: process.versions.node,
    icu: process.versions.icu ?? null,
    unicode: process.versions.unicode ?? null,
    cldr: process.versions.cldr ?? null
  };
}

export function assertPinnedUnicodeRuntime(feature) {
  if (process.versions.unicode !== PINNED_UNICODE_VERSION) {
    throw new TextIntegrityError(
      "UNICODE_VERSION_MISMATCH",
      `${feature} requires runtime Unicode ${PINNED_UNICODE_VERSION}.`,
      { feature, required: PINNED_UNICODE_VERSION, actual: process.versions.unicode ?? null }
    );
  }
}
