import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const ROOT_BUILD_INPUTS = Object.freeze([
  "Cargo.lock",
  "Cargo.toml",
  "build.rs",
  "rust-toolchain",
  "rust-toolchain.toml"
]);

function filesBelow(directory) {
  const files = [];
  for (const entry of readdirSync(directory).sort()) {
    const absolute = path.join(directory, entry);
    if (statSync(absolute).isDirectory()) files.push(...filesBelow(absolute));
    else files.push(absolute);
  }
  return files;
}

export function nativeBuildInputFiles(nativeRoot) {
  const files = [];
  for (const relative of ROOT_BUILD_INPUTS) {
    const absolute = path.join(nativeRoot, relative);
    if (existsSync(absolute) && statSync(absolute).isFile()) files.push(absolute);
  }
  const sourceRoot = path.join(nativeRoot, "src");
  if (existsSync(sourceRoot)) files.push(...filesBelow(sourceRoot));
  return files.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
}

export function nativeSourceDigest(nativeRoot) {
  const hash = createHash("sha256");
  for (const file of nativeBuildInputFiles(nativeRoot)) {
    const relative = path.relative(nativeRoot, file).split(path.sep).join("/");
    const bytes = readFileSync(file);
    hash.update(`${relative.length}:${relative}:${bytes.length}:`);
    hash.update(bytes);
  }
  return hash.digest("hex");
}
