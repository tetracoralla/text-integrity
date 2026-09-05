import { createHash } from "node:crypto";

function serialize(value) {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON accepts only finite numbers.");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(serialize).join(",")}]`;
  if (typeof value === "object") {
    const entries = Object.keys(value).sort().map((key) => {
      if (value[key] === undefined) throw new TypeError("Canonical JSON does not accept undefined values.");
      return `${JSON.stringify(key)}:${serialize(value[key])}`;
    });
    return `{${entries.join(",")}}`;
  }
  throw new TypeError(`Canonical JSON does not accept ${typeof value} values.`);
}

export function canonicalJson(value) {
  return serialize(value);
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function canonicalDigest(value) {
  return sha256Hex(canonicalJson(value));
}

export function merkleRoot(entries) {
  if (entries.length === 0) return sha256Hex(Buffer.from([0]));
  let level = entries
    .map((entry) => createHash("sha256")
      .update(Buffer.from([0]))
      .update(canonicalJson(entry))
      .digest());
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      next.push(createHash("sha256")
        .update(Buffer.from([1]))
        .update(left)
        .update(right)
        .digest());
    }
    level = next;
  }
  return level[0].toString("hex");
}
