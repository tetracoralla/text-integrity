import { LIMITS } from "./core/limits.js";
import { deepFreezeContract } from "./schemas/common.js";

const simpleNonConfusableRelation = {
  type: "string",
  enum: ["exact", "nfc", "nfkc", "nfkc_casefold"]
};
const simpleRelation = {
  type: "string",
  enum: ["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable"]
};
const uts46Options = (includeDnsLength) => ({
  type: "object",
  additionalProperties: false,
  required: [
    "checkBidi", "checkHyphens", "checkJoiners", "ignoreInvalidPunycode",
    "transitionalProcessing", "useSTD3ASCIIRules", ...(includeDnsLength ? ["verifyDNSLength"] : [])
  ],
  properties: {
    checkBidi: { type: "boolean" },
    checkHyphens: { type: "boolean" },
    checkJoiners: { type: "boolean" },
    ignoreInvalidPunycode: { type: "boolean" },
    transitionalProcessing: { type: "boolean" },
    useSTD3ASCIIRules: { type: "boolean" },
    ...(includeDnsLength ? { verifyDNSLength: { type: "boolean" } } : {})
  }
});
const precisProfile = {
  type: "string",
  enum: ["precis_username_case_mapped", "precis_username_case_preserved", "precis_opaque_string"]
};
const protocolRelation = {
  oneOf: [
    {
      type: "object", additionalProperties: false, required: ["kind", "profile", "action", "options"],
      properties: {
        kind: { const: "protocol" }, profile: { const: "uts46_domain" }, action: { const: "to_ascii" },
        options: uts46Options(true)
      }
    },
    {
      type: "object", additionalProperties: false, required: ["kind", "profile", "action", "options"],
      properties: {
        kind: { const: "protocol" }, profile: { const: "uts46_domain" }, action: { const: "to_unicode" },
        options: uts46Options(false)
      }
    },
    {
      type: "object", additionalProperties: false, required: ["kind", "profile", "action"],
      properties: { kind: { const: "protocol" }, profile: precisProfile, action: { const: "enforce" } }
    }
  ]
};
const collationOptions = {
  type: "object",
  additionalProperties: false,
  required: ["usage", "sensitivity", "ignorePunctuation", "numeric", "caseFirst", "localeMatcher", "collation"],
  properties: {
    usage: { type: "string", enum: ["sort", "search"] },
    sensitivity: { type: "string", enum: ["base", "accent", "case", "variant"] },
    ignorePunctuation: { type: "boolean" },
    numeric: { type: "boolean" },
    caseFirst: { type: "string", enum: ["upper", "lower", "false"] },
    localeMatcher: { type: "string", enum: ["lookup", "best fit"] },
    collation: { type: "string", minLength: 1, maxLength: LIMITS.maxCollationChars }
  }
};
const declaredCollationRelation = {
  type: "object",
  additionalProperties: false,
  required: ["kind", "locale", "options"],
  properties: {
    kind: { const: "declared_collation" },
    locale: { type: "string", minLength: 1, maxLength: LIMITS.maxLocaleChars },
    options: collationOptions
  }
};
const nonConfusableRelation = {
  oneOf: [simpleNonConfusableRelation, protocolRelation, declaredCollationRelation]
};
const allRelations = {
  oneOf: [simpleRelation, protocolRelation, declaredCollationRelation]
};
const item = {
  type: "object",
  additionalProperties: false,
  required: ["id", "text", "scope"],
  properties: {
    id: {
      type: "string",
      minLength: 1,
      maxLength: LIMITS.maxNamespaceIdChars,
      description: "Explicit well-formed identifier used only for result membership."
    },
    text: {
      type: "string",
      description: `Explicit well-formed text. Limit: ${LIMITS.maxTextBytes} UTF-8 bytes.`
    },
    scope: {
      type: "string",
      minLength: 1,
      maxLength: LIMITS.maxNamespaceScopeChars,
      description: "Explicit well-formed scope label used only for grouping."
    }
  }
};
const items = {
  type: "array",
  maxItems: LIMITS.maxNamespaceItems,
  items: item
};

export const NAMESPACE_INPUT_SCHEMA = deepFreezeContract({
  oneOf: [
    {
      type: "object",
      additionalProperties: false,
      required: ["items", "relations"],
      properties: {
        items,
        relations: {
          type: "array",
          minItems: 1,
          maxItems: LIMITS.maxNamespaceRelations,
          uniqueItems: true,
          items: nonConfusableRelation
        }
      }
    },
    {
      type: "object",
      additionalProperties: false,
      required: ["items", "relations", "confusableDirection"],
      properties: {
        items,
        relations: {
          type: "array",
          minItems: 1,
          maxItems: LIMITS.maxNamespaceRelations,
          uniqueItems: true,
          items: allRelations,
          contains: { const: "uts39_confusable" }
        },
        confusableDirection: { type: "string", enum: ["LTR", "RTL", "FS"] }
      }
    }
  ]
});
