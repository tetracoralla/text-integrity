export const UTS46_ENGINE_LABEL = "tr46@6.0.0";

const PUNYCODE_IDENTITY = Object.freeze({
  name: "punycode",
  version: "2.3.1",
  packageIntegrity: "sha512-vYt7UD1U9Wg6138shLtLOvdAu+8DsC/ilFtEVHcH+wydcSpNE20AfSOduf6MkRFahL5FY7X1oU7nKVZFtfq8Fg=="
});

const IDNA_CONFORMANCE_IDENTITY = Object.freeze({
  corpus: "Unicode 17.0.0 IdnaTestV2.txt",
  compressedSha256: "9f8a1da3fee709da51a9bb80667db9b1f92df22f4577f8174ac9f1b4fec155c8",
  uncompressedSha256: "beb5d0be20e896189b03209a82fdc34f06351502bbd4b8e2523583fc2954d9cf",
  wellFormedCaseCount: 6389,
  rerunCommand: "npm run check"
});

export const UTS46_ENGINE_IDENTITY = Object.freeze({
  specification: "UTS #46 revision 35",
  unicodeVersion: "17.0.0",
  package: "tr46",
  version: "6.0.0",
  packageIntegrity: "sha512-bLVMLPtstlZ4iMQHpFHTR7GAGj2jxi8Dg0s2h2MafAE4uSWF98FC/3MomU51iQAMf8/qDUbKWf5GxuvvVcXEhw==",
  runtimeTreeSha256: "a4b97c0735cda47715ec66318e2f8aba66db3427fec8aa8069f87257622fdfc4",
  dependency: PUNYCODE_IDENTITY,
  conformance: IDNA_CONFORMANCE_IDENTITY
});

export const UTS46_RUNTIME_FILES = Object.freeze([
  "tr46/index.js",
  "tr46/lib/mappingTable.json",
  "tr46/lib/regexes.js",
  "tr46/lib/statusMapping.js",
  "tr46/package.json",
  "punycode/punycode.js",
  "punycode/package.json"
]);
