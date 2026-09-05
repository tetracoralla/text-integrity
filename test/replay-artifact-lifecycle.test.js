import test from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { spawn } from "node:child_process";
import {
  assessReplayReceiptState,
  atomicReplaceReplayReceipt,
  readReplayReceiptState
} from "../scripts/replay-receipt-file.mjs";

const receiptFileModule = new URL(
  "../scripts/replay-receipt-file.mjs",
  import.meta.url
).href;

function concurrentAtomicReplace(target, rendered) {
  const source = [
    `import { atomicReplaceReplayReceipt } from ${JSON.stringify(receiptFileModule)};`,
    `atomicReplaceReplayReceipt(${JSON.stringify(target)}, ${JSON.stringify(rendered)});`
  ].join("\n");
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", source], {
      stdio: ["ignore", "ignore", "pipe"]
    });
    let stderr = "";
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve();
      else reject(new Error(stderr || `atomic replacement child exited ${code}`));
    });
  });
}

test("replay receipt assessment reports supported drift without echoing changed values", () => {
  const current = JSON.parse(readFileSync(
    new URL("../reference/replay-receipt.json", import.meta.url),
    "utf8"
  ));
  const changed = structuredClone(current);
  changed.nonClaims.push("SECRET_CHANGED_VALUE");
  const assessment = assessReplayReceiptState(
    { status: "present", text: `${JSON.stringify(current, null, 2)}\n` },
    `${JSON.stringify(changed, null, 2)}\n`
  );
  assert.equal(assessment.matched, false);
  assert.match(assessment.stderr, /text-integrity\.replay-receipt-comparison\/1/u);
  assert.equal(assessment.stderr.includes("SECRET_CHANGED_VALUE"), false);
});

test("replay receipt regeneration atomically creates and recovers the derived file", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "text-integrity-replay-lifecycle-"));
  const target = path.join(directory, "replay-receipt.json");
  try {
    assert.deepEqual(readReplayReceiptState(target), { status: "missing" });
    const missingAssessment = assessReplayReceiptState(
      { status: "missing" },
      '{"schemaVersion":"generated"}\n'
    );
    assert.equal(missingAssessment.matched, false);
    assert.match(missingAssessment.stderr, /regenerate it atomically/u);

    const first = '{"schemaVersion":"first"}\n';
    atomicReplaceReplayReceipt(pathToFileURL(target), first);
    assert.deepEqual(readReplayReceiptState(target), { status: "present", text: first });

    writeFileSync(target, "corrupt partial JSON", "utf8");
    const corruptAssessment = assessReplayReceiptState(
      { status: "present", text: "SECRET_CORRUPT_VALUE" },
      first
    );
    assert.equal(corruptAssessment.matched, false);
    assert.match(corruptAssessment.stderr, /not valid current-schema data/u);
    assert.equal(corruptAssessment.stderr.includes("SECRET_CORRUPT_VALUE"), false);
    const recovered = '{"schemaVersion":"recovered"}\n';
    atomicReplaceReplayReceipt(target, recovered);
    assert.equal(readFileSync(target, "utf8"), recovered);
    assert.deepEqual(readdirSync(directory), ["replay-receipt.json"]);

    assert.throws(
      () => atomicReplaceReplayReceipt(target, "not JSON"),
      /Unexpected token|Unexpected end/u
    );
    assert.equal(readFileSync(target, "utf8"), recovered);
    assert.deepEqual(readdirSync(directory), ["replay-receipt.json"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("concurrent replay receipt replacements publish one complete record", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "text-integrity-replay-concurrent-"));
  const target = path.join(directory, "replay-receipt.json");
  const first = `${JSON.stringify({ writer: "first", payload: "a".repeat(4096) })}\n`;
  const second = `${JSON.stringify({ writer: "second", payload: "b".repeat(4096) })}\n`;
  try {
    await Promise.all([
      concurrentAtomicReplace(target, first),
      concurrentAtomicReplace(target, second)
    ]);
    const published = readFileSync(target, "utf8");
    assert.ok(published === first || published === second);
    assert.deepEqual(readdirSync(directory), ["replay-receipt.json"]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
