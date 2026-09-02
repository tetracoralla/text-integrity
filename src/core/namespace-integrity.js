import { createHash } from "node:crypto";
import { TextIntegrityError } from "./errors.js";
import { LIMITS, assertTextBudget, enforceResultBudget } from "./limits.js";
import { assertPinnedUnicodeRuntime, runtimeInfo } from "./runtime.js";
import { bidiSkeleton, nfkcCasefold } from "./security.js";
import { unicodeSecurityData } from "./unicode-security-data.js";
import { normalizeUnicode17 } from "./normalization.js";
import { applyProtocolProfile } from "./protocol.js";
import { compareUtf16CodeUnits } from "./string-order.js";
import { validateCollationRequest } from "./collation.js";
import {
  assertKeys,
  requireArray,
  requireBoolean,
  requireEnum,
  requireObject,
  requireString
} from "./validation.js";

const SIMPLE_RELATIONS = Object.freeze(["exact", "nfc", "nfkc", "nfkc_casefold", "uts39_confusable"]);
const PROTOCOL_PROFILES = Object.freeze([
  "uts46_domain",
  "precis_username_case_mapped",
  "precis_username_case_preserved",
  "precis_opaque_string"
]);
const DIRECTIONS = Object.freeze(["LTR", "RTL", "FS"]);

function digest(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function boundedString(value, field, maximum) {
  const text = requireString(value, field);
  if (text === "" || text.length > maximum) {
    throw new TextIntegrityError(
      "INVALID_INPUT",
      `${field} must contain 1 to ${maximum} characters.`,
      { field, minimum: 1, maximum }
    );
  }
  if (!text.isWellFormed()) {
    throw new TextIntegrityError(
      "INVALID_UNICODE",
      `${field} contains an unpaired UTF-16 surrogate.`,
      { field }
    );
  }
  return text;
}

function parseUts46Options(value, action, field) {
  const options = requireObject(value, field);
  const keys = [
    "checkBidi", "checkHyphens", "checkJoiners", "ignoreInvalidPunycode",
    "transitionalProcessing", "useSTD3ASCIIRules",
    ...(action === "to_ascii" ? ["verifyDNSLength"] : [])
  ];
  assertKeys(options, keys, keys);
  return Object.fromEntries(keys.map((key) => [key, requireBoolean(options[key], `${field}.${key}`)]));
}

function parseRelation(input, index) {
  const field = `relations[${index}]`;
  if (typeof input === "string") {
    const relation = requireEnum(input, field, SIMPLE_RELATIONS);
    return { kind: "simple", relation, identity: `simple:${relation}` };
  }

  requireObject(input, field);
  const kind = requireEnum(input.kind, `${field}.kind`, ["protocol", "declared_collation"]);
  if (kind === "protocol") {
    const profile = requireEnum(input.profile, `${field}.profile`, PROTOCOL_PROFILES);
    if (profile === "uts46_domain") {
      assertKeys(input, ["kind", "profile", "action", "options"], ["kind", "profile", "action", "options"]);
      const action = requireEnum(input.action, `${field}.action`, ["to_ascii", "to_unicode"]);
      const definition = {
        kind,
        profile,
        action,
        options: parseUts46Options(input.options, action, `${field}.options`)
      };
      const configurationSha256 = digest(JSON.stringify(definition));
      return { kind, relation: "protocol", definition, configurationSha256, identity: `${kind}:${configurationSha256}` };
    }
    assertKeys(input, ["kind", "profile", "action"], ["kind", "profile", "action"]);
    const action = requireEnum(input.action, `${field}.action`, ["enforce"]);
    const definition = { kind, profile, action };
    const configurationSha256 = digest(JSON.stringify(definition));
    return { kind, relation: "protocol", definition, configurationSha256, identity: `${kind}:${configurationSha256}` };
  }

  assertKeys(input, ["kind", "locale", "options"], ["kind", "locale", "options"]);
  const { locale, canonicalLocale, requestedOptions, collator } = validateCollationRequest(input);
  const definition = {
    kind,
    requestedLocale: locale,
    canonicalLocale,
    requestedOptions,
    resolvedOptions: collator.resolvedOptions()
  };
  const configurationSha256 = digest(JSON.stringify(definition));
  return {
    kind,
    relation: "declared_collation",
    definition,
    configurationSha256,
    identity: `${kind}:${configurationSha256}`,
    collator
  };
}

function relationKey(data, item, plan, direction) {
  const relation = plan.relation;
  if (relation === "exact") return item.text;
  if (relation === "nfc") return normalizeUnicode17(item.text, "NFC", data);
  if (relation === "nfkc") return normalizeUnicode17(item.text, "NFKC", data);
  if (relation === "nfkc_casefold") return nfkcCasefold(data, item.text);
  if (relation === "uts39_confusable") return bidiSkeleton(data, item.text, direction).value;
  const { kind: _kind, ...profile } = plan.definition;
  return applyProtocolProfile({ ...profile, text: item.text }).output;
}

function groupsForKeyRelation(data, items, plan, direction) {
  const scopes = new Map();
  for (const item of items) {
    const key = relationKey(data, item, plan, direction);
    const scope = scopes.get(item.scope) ?? new Map();
    const bucket = scope.get(key) ?? [];
    bucket.push(item);
    scope.set(key, bucket);
    scopes.set(item.scope, scope);
  }

  const groups = [];
  for (const [scope, buckets] of [...scopes.entries()].sort(([left], [right]) => compareUtf16CodeUnits(left, right))) {
    for (const [key, bucket] of buckets) {
      if (bucket.length < 2) continue;
      const distinctTexts = new Set(bucket.map((item) => item.text));
      if (plan.relation !== "exact" && distinctTexts.size < 2) continue;
      groups.push({
        relation: plan.relation,
        ...(plan.configurationSha256 === undefined ? {} : { configurationSha256: plan.configurationSha256 }),
        scope,
        keySha256: digest(key),
        distinctTextCount: distinctTexts.size,
        memberIds: bucket.map((item) => item.id).sort(compareUtf16CodeUnits)
      });
    }
  }
  return groups.sort((left, right) => compareUtf16CodeUnits(left.scope, right.scope)
    || compareUtf16CodeUnits(left.keySha256, right.keySha256));
}

function groupsForDeclaredCollation(items, plan) {
  const scopes = new Map();
  for (const item of items) {
    const scope = scopes.get(item.scope) ?? [];
    scope.push(item);
    scopes.set(item.scope, scope);
  }

  const groups = [];
  for (const [scope, scopedItems] of [...scopes.entries()].sort(([left], [right]) => compareUtf16CodeUnits(left, right))) {
    const sorted = [...scopedItems].sort((left, right) => {
      const order = plan.collator.compare(left.text, right.text);
      return order === 0 ? compareUtf16CodeUnits(left.id, right.id) : order;
    });
    for (let start = 0; start < sorted.length;) {
      let end = start + 1;
      while (end < sorted.length && plan.collator.compare(sorted[start].text, sorted[end].text) === 0) end += 1;
      const bucket = sorted.slice(start, end);
      const distinctTexts = new Set(bucket.map((item) => item.text));
      if (bucket.length >= 2 && distinctTexts.size >= 2) {
        const memberIds = bucket.map((item) => item.id).sort(compareUtf16CodeUnits);
        groups.push({
          relation: "declared_collation",
          configurationSha256: plan.configurationSha256,
          scope,
          memberSetSha256: digest([plan.configurationSha256, scope, ...memberIds].join("\0")),
          distinctTextCount: distinctTexts.size,
          memberIds
        });
      }
      start = end;
    }
  }
  return groups.sort((left, right) => compareUtf16CodeUnits(left.scope, right.scope)
    || compareUtf16CodeUnits(left.memberSetSha256, right.memberSetSha256));
}

function relationSummary(plan, groups) {
  const groupCount = groups.filter((group) => group.relation === plan.relation
    && (plan.configurationSha256 === undefined || group.configurationSha256 === plan.configurationSha256)).length;
  if (plan.kind === "simple") return { relation: plan.relation, groupCount };
  return {
    relation: plan.relation,
    configurationSha256: plan.configurationSha256,
    definition: plan.definition,
    groupCount
  };
}

export function analyzeNamespaceIntegrity(args) {
  requireObject(args);
  assertKeys(args, ["items", "relations", "confusableDirection"], ["items", "relations"]);
  assertPinnedUnicodeRuntime("Namespace integrity analysis");

  const inputItems = requireArray(args.items, "items", LIMITS.maxNamespaceItems);
  const inputRelations = requireArray(args.relations, "relations", LIMITS.maxNamespaceRelations);
  if (inputRelations.length === 0) {
    throw new TextIntegrityError("INVALID_INPUT", "relations must contain at least one named relation.", {
      field: "relations",
      minimum: 1,
      maximum: LIMITS.maxNamespaceRelations
    });
  }
  const relationPlans = inputRelations.map(parseRelation);
  if (new Set(relationPlans.map((plan) => plan.identity)).size !== relationPlans.length) {
    throw new TextIntegrityError("INVALID_INPUT", "relations must not contain duplicates.", { field: "relations" });
  }

  const needsDirection = relationPlans.some((plan) => plan.relation === "uts39_confusable");
  let direction = null;
  if (needsDirection) {
    if (!Object.hasOwn(args, "confusableDirection")) {
      throw new TextIntegrityError("INVALID_INPUT", "confusableDirection is required for uts39_confusable.", {
        field: "confusableDirection"
      });
    }
    direction = requireEnum(args.confusableDirection, "confusableDirection", DIRECTIONS);
  } else if (Object.hasOwn(args, "confusableDirection")) {
    throw new TextIntegrityError("INVALID_INPUT", "confusableDirection is allowed only for uts39_confusable.", {
      field: "confusableDirection"
    });
  }

  const ids = new Set();
  let cumulativeTextUtf8Bytes = 0;
  const items = inputItems.map((input, index) => {
    const field = `items[${index}]`;
    requireObject(input, field);
    assertKeys(input, ["id", "text", "scope"], ["id", "text", "scope"]);
    const id = boundedString(input.id, `${field}.id`, LIMITS.maxNamespaceIdChars);
    if (ids.has(id)) {
      throw new TextIntegrityError("DUPLICATE_ITEM_ID", "Namespace item IDs must be unique.", { id });
    }
    ids.add(id);
    const scope = boundedString(input.scope, `${field}.scope`, LIMITS.maxNamespaceScopeChars);
    const text = requireString(input.text, `${field}.text`);
    assertTextBudget(text, `${field}.text`);
    if (!text.isWellFormed()) {
      throw new TextIntegrityError("INVALID_UNICODE", `${field}.text contains an unpaired UTF-16 surrogate.`, {
        field: `${field}.text`
      });
    }
    cumulativeTextUtf8Bytes += Buffer.byteLength(text, "utf8");
    return { id, text, scope };
  });
  if (cumulativeTextUtf8Bytes > LIMITS.maxNamespaceTextBytes) {
    throw new TextIntegrityError(
      "REQUEST_TOO_LARGE",
      `Namespace text exceeds the ${LIMITS.maxNamespaceTextBytes}-byte cumulative limit.`,
      {
        field: "items[].text",
        actualBytes: cumulativeTextUtf8Bytes,
        limitBytes: LIMITS.maxNamespaceTextBytes
      }
    );
  }

  const data = unicodeSecurityData();
  const groups = relationPlans.flatMap((plan) => plan.kind === "declared_collation"
    ? groupsForDeclaredCollation(items, plan)
    : groupsForKeyRelation(data, items, plan, direction));
  const groupedIds = new Set(groups.flatMap((group) => group.memberIds));
  const isolatedIds = items.map((item) => item.id)
    .filter((id) => !groupedIds.has(id))
    .sort(compareUtf16CodeUnits);
  const relationSummaries = relationPlans.map((plan) => relationSummary(plan, groups));

  return enforceResultBudget({
    status: "ok",
    operation: "namespace_integrity",
    relations: relationSummaries,
    confusableDirection: direction,
    groups,
    isolatedIds,
    summary: {
      inputCount: items.length,
      scopeCount: new Set(items.map((item) => item.scope)).size,
      relationCount: relationPlans.length,
      collisionGroupCount: groups.length,
      groupedItemCount: groupedIds.size,
      isolatedItemCount: isolatedIds.length,
      cumulativeTextUtf8Bytes
    },
    limits: {
      maxItems: LIMITS.maxNamespaceItems,
      maxRelations: LIMITS.maxNamespaceRelations,
      maxTextBytesPerItem: LIMITS.maxTextBytes,
      maxCumulativeTextBytes: LIMITS.maxNamespaceTextBytes,
      maxResultBytes: LIMITS.maxResultBytes
    },
    data: data.metadata,
    limitations: [
      "Groups report equality under only the explicitly requested relation and scope.",
      "Protocol key material is represented only by SHA-256; normalization outputs, protocol outputs, and confusable skeletons are not returned as replacement text.",
      "Key digests are identities, not anonymization; low-entropy normalization, protocol, or skeleton values can be enumerated offline.",
      "Declared collation groups use the current runtime-resolved ICU comparator and a member-set digest because ICU does not expose a stable public sort key.",
      "The result does not decide whether a name is malicious, acceptable, unique under an application policy, or authorized for registration."
    ],
    runtime: runtimeInfo()
  });
}

export const SUPPORTED_NAMESPACE_RELATIONS = Object.freeze([
  ...SIMPLE_RELATIONS,
  "protocol",
  "declared_collation"
]);
