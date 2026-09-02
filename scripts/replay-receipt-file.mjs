import {
  closeSync,
  fsyncSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { randomUUID } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { compareReplayReceipts } from "../src/reference/replay-comparison.js";

function filePath(value) {
  return value instanceof URL ? fileURLToPath(value) : value;
}

export function readReplayReceiptState(receiptPath) {
  try {
    return { status: "present", text: readFileSync(receiptPath, "utf8") };
  } catch (error) {
    if (error?.code === "ENOENT") return { status: "missing" };
    throw error;
  }
}

export function assessReplayReceiptState(committed, rendered) {
  if (committed.status === "missing") {
    return {
      matched: false,
      stdout: "",
      stderr: "replay receipt is missing; run npm run replay:write to regenerate it atomically\n"
    };
  }
  if (committed.text === rendered) {
    return {
      matched: true,
      stdout: "replay receipt matches current named replay inputs\n",
      stderr: ""
    };
  }
  try {
    const comparison = compareReplayReceipts(
      JSON.parse(committed.text),
      JSON.parse(rendered)
    );
    return {
      matched: false,
      stdout: "",
      stderr: [
        "replay receipt differs from current named replay inputs",
        JSON.stringify(comparison, null, 2)
      ].join("\n") + "\n"
    };
  } catch {
    return {
      matched: false,
      stdout: "",
      stderr: [
        "replay receipt differs from current named replay inputs",
        "structured mismatch diagnostics unavailable because the committed receipt is not valid current-schema data",
        "run npm run replay:write to regenerate the derived receipt atomically"
      ].join("\n") + "\n"
    };
  }
}

export function atomicReplaceReplayReceipt(receiptPath, rendered) {
  if (typeof rendered !== "string") {
    throw new TypeError("rendered replay receipt must be a string.");
  }
  JSON.parse(rendered);
  const target = filePath(receiptPath);
  const temporary = path.join(
    path.dirname(target),
    `.${path.basename(target)}.${process.pid}.${randomUUID()}.tmp`
  );
  let descriptor;
  let published = false;
  try {
    descriptor = openSync(temporary, "wx", 0o666);
    writeFileSync(descriptor, rendered, "utf8");
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;
    renameSync(temporary, target);
    published = true;
  } finally {
    try {
      if (descriptor !== undefined) closeSync(descriptor);
    } finally {
      if (!published) rmSync(temporary, { force: true });
    }
  }
}
