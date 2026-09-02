import { spawnSync } from "node:child_process";
import { generateCargoWasmSbom, validateCargoWasmSbom, validateNpmSbom } from "./release-sbom.js";

function npmSbom() {
  const child = process.env.npm_execpath
    ? spawnSync(process.execPath, [process.env.npm_execpath, "sbom", "--sbom-format", "cyclonedx"], { encoding: "utf8", maxBuffer: 16 << 20 })
    : spawnSync(process.platform === "win32" ? "npm.cmd" : "npm", ["sbom", "--sbom-format", "cyclonedx"], {
      encoding: "utf8", maxBuffer: 16 << 20, shell: process.platform === "win32"
    });
  if (child.status !== 0) throw new Error(child.stderr || child.stdout || "npm sbom failed");
  return JSON.parse(child.stdout);
}

const npmResult = validateNpmSbom(npmSbom());
const cargoResult = validateCargoWasmSbom(generateCargoWasmSbom());
process.stdout.write(`release SBOMs complete: npm ${npmResult.componentCount} components; Cargo/WASM ${cargoResult.componentCount} components\n`);
