import {
  arrayOf,
  boolean,
  closed,
  collationOptions,
  integer,
  limitations,
  nullable,
  resolvedCollationOptions,
  runtime,
  string,
  stringArray,
  success,
  unicodeData
} from "./common.js";

const simpleRelation = {
  type: "string",
  enum: ["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable"]
};

const uts46Options = (includeDnsLength) => {
  const base = {
    checkBidi: boolean,
    checkHyphens: boolean,
    checkJoiners: boolean,
    ignoreInvalidPunycode: boolean,
    transitionalProcessing: boolean,
    useSTD3ASCIIRules: boolean,
    ...(includeDnsLength ? { verifyDNSLength: boolean } : {})
  };
  return closed(Object.keys(base), base);
};

const precisProfile = {
  type: "string",
  enum: ["precis_username_case_mapped", "precis_username_case_preserved", "precis_opaque_string"]
};

const protocolDefinition = {
  oneOf: [
    closed(
      ["kind", "profile", "action", "options"],
      { kind: { const: "protocol" }, profile: { const: "uts46_domain" }, action: { const: "to_ascii" }, options: uts46Options(true) }
    ),
    closed(
      ["kind", "profile", "action", "options"],
      { kind: { const: "protocol" }, profile: { const: "uts46_domain" }, action: { const: "to_unicode" }, options: uts46Options(false) }
    ),
    closed(
      ["kind", "profile", "action"],
      { kind: { const: "protocol" }, profile: precisProfile, action: { const: "enforce" } }
    )
  ]
};

const declaredCollationDefinition = closed(
  ["kind", "requestedLocale", "canonicalLocale", "requestedOptions", "resolvedOptions"],
  {
    kind: { const: "declared_collation" },
    requestedLocale: string,
    canonicalLocale: string,
    requestedOptions: collationOptions,
    resolvedOptions: resolvedCollationOptions
  }
);

const relationSummary = {
  oneOf: [
    closed(["relation", "groupCount"], { relation: simpleRelation, groupCount: integer }),
    closed(
      ["relation", "configurationSha256", "definition", "groupCount"],
      {
        relation: { const: "protocol" },
        configurationSha256: string,
        definition: protocolDefinition,
        groupCount: integer
      }
    ),
    closed(
      ["relation", "configurationSha256", "definition", "groupCount"],
      {
        relation: { const: "declared_collation" },
        configurationSha256: string,
        definition: declaredCollationDefinition,
        groupCount: integer
      }
    )
  ]
};

const keyGroupBase = {
  scope: string,
  keySha256: string,
  distinctTextCount: integer,
  memberIds: stringArray
};

const namespaceGroup = {
  oneOf: [
    closed(
      ["relation", ...Object.keys(keyGroupBase)],
      { relation: simpleRelation, ...keyGroupBase }
    ),
    closed(
      ["relation", "configurationSha256", ...Object.keys(keyGroupBase)],
      { relation: { const: "protocol" }, configurationSha256: string, ...keyGroupBase }
    ),
    closed(
      ["relation", "configurationSha256", "scope", "memberSetSha256", "distinctTextCount", "memberIds"],
      {
        relation: { const: "declared_collation" },
        configurationSha256: string,
        scope: string,
        memberSetSha256: string,
        distinctTextCount: integer,
        memberIds: stringArray
      }
    )
  ]
};

export const namespaceIntegrity = success("namespace_integrity", {
  relations: arrayOf(relationSummary),
  confusableDirection: nullable({ type: "string", enum: ["LTR", "RTL", "FS"] }),
  groups: arrayOf(namespaceGroup),
  isolatedIds: stringArray,
  summary: closed(
    [
      "inputCount", "scopeCount", "relationCount", "collisionGroupCount",
      "groupedItemCount", "isolatedItemCount", "cumulativeTextUtf8Bytes"
    ],
    {
      inputCount: integer,
      scopeCount: integer,
      relationCount: integer,
      collisionGroupCount: integer,
      groupedItemCount: integer,
      isolatedItemCount: integer,
      cumulativeTextUtf8Bytes: integer
    }
  ),
  limits: closed(
    ["maxItems", "maxRelations", "maxTextBytesPerItem", "maxCumulativeTextBytes", "maxResultBytes"],
    {
      maxItems: integer,
      maxRelations: integer,
      maxTextBytesPerItem: integer,
      maxCumulativeTextBytes: integer,
      maxResultBytes: integer
    }
  ),
  data: unicodeData,
  limitations,
  runtime
});
