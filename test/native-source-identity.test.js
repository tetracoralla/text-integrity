import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { nativeSourceDigest } from "../scripts/native-source-identity.mjs";

test("native source identity tracks build inputs but excludes documentation and target output", () => {
  const directory = mkdtempSync(path.join(os.tmpdir(), "text-integrity-native-source-"));
  try {
    mkdirSync(path.join(directory, "src"));
    mkdirSync(path.join(directory, "target"));
    writeFileSync(path.join(directory, "Cargo.toml"), "[package]\nname='probe'\n");
    writeFileSync(path.join(directory, "Cargo.lock"), "lock-v1\n");
    writeFileSync(path.join(directory, "rust-toolchain.toml"), "channel='1.89.0'\n");
    writeFileSync(path.join(directory, "src", "lib.rs"), "pub fn value() -> u8 { 1 }\n");
    writeFileSync(path.join(directory, "README.md"), "first documentation\n");
    writeFileSync(path.join(directory, "target", "artifact"), "first artifact\n");

    const initial = nativeSourceDigest(directory);
    writeFileSync(path.join(directory, "README.md"), "revised documentation\n");
    writeFileSync(path.join(directory, "target", "artifact"), "revised artifact\n");
    assert.equal(nativeSourceDigest(directory), initial);

    writeFileSync(path.join(directory, "src", "lib.rs"), "pub fn value() -> u8 { 2 }\n");
    assert.notEqual(nativeSourceDigest(directory), initial);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
