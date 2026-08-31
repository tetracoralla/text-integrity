const $ = (selector) => document.querySelector(selector);
const operation = $("#operation");
const form = $("#task-form");
const primary = $("#primary");
const primaryLabel = $("#primary-label");
const result = $("#result");
const securityMode = $("#security-mode");
const sourceKind = $("#source-kind");
const protocolProfile = $("#protocol-profile");
const protocolAction = $("#protocol-action");
let activeRequest;
let requestSerial = 0;

function setActions() {
  const domain = protocolProfile.value === "uts46_domain";
  const values = domain ? [["to_ascii", "To ASCII"], ["to_unicode", "To Unicode"]] : [["enforce", "Enforce"], ["compare", "Compare"]];
  const previous = protocolAction.value;
  protocolAction.replaceChildren(...values.map(([value, label]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    return option;
  }));
  if (values.some(([value]) => value === previous)) protocolAction.value = previous;
  $("#domain-options").hidden = !domain;
  $("#protocol-comparison-label").hidden = domain || protocolAction.value !== "compare";
}

function updateFields() {
  const op = operation.value;
  const paired = op === "compare" || op === "explain_difference";
  $("#normalize-fields").hidden = op !== "normalize";
  $("#compare-fields").hidden = !paired;
  $("#confusable-direction-label").hidden = op !== "explain_difference";
  $("#security-fields").hidden = op !== "security";
  $("#identifier-profile-label").hidden = op !== "security" || securityMode.value !== "identifier";
  $("#security-direction-label").hidden = op !== "security" || securityMode.value !== "identifier";
  $("#security-comparison-label").hidden = op !== "security" || securityMode.value !== "identifier";
  $("#index-fields").hidden = op !== "index";
  $("#protocol-fields").hidden = op !== "protocol_profile";
  $("#transcode-fields").hidden = op !== "transcode";
  const byteMode = op === "transcode" && sourceKind.value === "bytes";
  $("#source-encoding-label").hidden = !byteMode;
  primaryLabel.textContent = byteMode ? "Bytes (comma-separated)" : paired ? "First text" : "Text";
  primary.placeholder = byteMode ? "72, 101, 108, 108, 111" : "Paste text";
  setActions();
}

function resetTask() {
  activeRequest?.abort();
  activeRequest = undefined;
  requestSerial += 1;
  form.querySelector("button").disabled = false;
  result.hidden = true;
  result.replaceChildren();
  updateFields();
}

operation.addEventListener("change", resetTask);
sourceKind.addEventListener("change", resetTask);
securityMode.addEventListener("change", resetTask);
protocolProfile.addEventListener("change", resetTask);
protocolAction.addEventListener("change", resetTask);
updateFields();

function collationOptions() {
  return {
    usage: $("#usage").value,
    sensitivity: $("#sensitivity").value,
    ignorePunctuation: $("#ignore-punctuation").checked,
    numeric: $("#numeric").checked,
    caseFirst: $("#case-first").value,
    localeMatcher: $("#locale-matcher").value,
    collation: $("#collation").value
  };
}

function parseBytes(value) {
  return value.split(",").map((item, index) => {
    const trimmed = item.trim();
    if (trimmed === "") throw new Error(`Byte ${index + 1} is empty.`);
    if (!/^\d+$/.test(trimmed)) throw new Error(`Byte ${index + 1} is not an integer.`);
    const byte = Number(trimmed);
    if (byte < 0 || byte > 255) throw new Error(`Byte ${index + 1} must be from 0 through 255.`);
    return byte;
  });
}

function requestArguments() {
  const op = operation.value;
  if (op === "inspect") return { text: primary.value };
  if (op === "normalize") return { text: primary.value, form: $("#normalization-form").value };
  if (op === "compare" || op === "explain_difference") return {
    left: primary.value,
    right: $("#secondary").value,
    locale: $("#locale").value,
    options: collationOptions(),
    ...(op === "explain_difference" ? { confusableDirection: $("#confusable-direction").value } : {})
  };
  if (op === "index") {
    const chunk = $("#chunk-bytes").value.trim();
    return { text: primary.value, ...(chunk === "" ? {} : { maxChunkUtf8Bytes: Number(chunk) }) };
  }
  if (op === "security") {
    const comparison = $("#security-comparison").value;
    return {
      text: primary.value,
      mode: securityMode.value,
      ...(securityMode.value === "identifier" ? { profile: $("#identifier-profile").value } : {}),
      ...(securityMode.value === "identifier" && comparison !== "" ? {
        comparison,
        confusableDirection: $("#security-direction").value
      } : {})
    };
  }
  if (op === "protocol_profile") {
    const profile = protocolProfile.value;
    const action = protocolAction.value;
    if (profile === "uts46_domain") return {
      profile, action, text: primary.value,
      options: {
        checkBidi: true, checkHyphens: true, checkJoiners: true, ignoreInvalidPunycode: false,
        transitionalProcessing: $("#domain-transitional").checked,
        useSTD3ASCIIRules: $("#domain-std3").checked,
        ...(action === "to_ascii" ? { verifyDNSLength: true } : {})
      }
    };
    return {
      profile, action, text: primary.value,
      ...(action === "compare" ? { comparison: $("#protocol-comparison").value } : {})
    };
  }
  const common = {
    sourceKind: sourceKind.value,
    targetEncoding: $("#target-encoding").value,
    allowLossy: $("#allow-lossy").checked,
    byteRepresentation: $("#byte-representation").value
  };
  return sourceKind.value === "bytes"
    ? { ...common, bytes: parseBytes(primary.value), sourceEncoding: $("#source-encoding").value }
    : { ...common, text: primary.value };
}

function element(name, text, className) {
  const node = document.createElement(name);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function metric(label, value) {
  const node = element("div", undefined, "metric");
  node.append(element("span", label), element("strong", value));
  return node;
}

function summary(...metrics) {
  const node = element("div", undefined, "summary");
  node.append(...metrics);
  result.append(node);
}

function scrollingTable(table, label) {
  const region = element("div", undefined, "table-scroll");
  region.tabIndex = 0;
  region.setAttribute("role", "region");
  region.setAttribute("aria-label", label);
  region.append(table);
  return region;
}

function renderRuntime(value) {
  const version = value.runtime;
  result.append(element("p", `Unicode ${version.unicode ?? "unknown"} · ICU ${version.icu ?? "unknown"} · CLDR ${version.cldr ?? "unknown"}`, "runtime"));
}

function renderInspect(value) {
  result.append(element("h2", value.inputWellFormed ? "Well-formed text" : "Contains unpaired surrogates"));
  summary(metric("Code points", value.counts.codePoints), metric("Graphemes", value.counts.graphemes), metric("UTF-8 bytes", value.counts.utf8Bytes ?? "—"), metric("UTF-16 units", value.counts.utf16CodeUnits));
  const table = element("table");
  const head = element("tr");
  for (const label of ["Index", "Value", "Character", "UTF-8"]) head.append(element("th", label));
  table.append(head);
  for (const item of value.detail.codePoints) {
    const row = element("tr");
    for (const cell of [item.indexCodeUnit, item.value, item.character, item.utf8Hex ?? "invalid"]) row.append(element("td", cell, "mono"));
    table.append(row);
  }
  result.append(element("h3", "Code points"), scrollingTable(table, "Code point detail"));
  renderRuntime(value);
}

function renderNormalize(value) {
  result.append(element("h2", `${value.form}: ${value.changed ? "changed" : "unchanged"}`));
  summary(metric("Canonical equivalent", value.canonicalEquivalent ? "Yes" : "No"), metric("Compatibility equivalent", value.compatibilityEquivalent ? "Yes" : "No"), metric("UTF-8 bytes", `${value.bytes.originalUtf8} → ${value.bytes.normalizedUtf8}`));
  result.append(element("h3", "Normalized text"), element("p", value.normalized, "mono text-value"));
  renderRuntime(value);
}

function renderCompare(value) {
  result.append(element("h2", value.relation === "equal" ? "Equal for this collation" : `First text sorts ${value.relation}`));
  summary(metric("Order", value.order), metric("Code-unit equal", value.codeUnitEqual ? "Yes" : "No"), metric("Canonical equivalent", value.canonicalEquivalent ? "Yes" : "No"), metric("Resolved locale", value.resolvedOptions.locale));
  renderRuntime(value);
}

function renderDifference(value) {
  result.append(element("h2", value.exact.equal ? "The strings are exactly equal" : "The difference is mapped"));
  const point = value.firstDifference.codePoint;
  summary(
    metric("Exact", value.exact.equal ? "Yes" : "No"),
    metric("NFC equal", value.normalization.NFC.equal ? "Yes" : "No"),
    metric("NFKC casefold equal", value.nfkcCasefold.equal ? "Yes" : "No"),
    metric("Identifier relation", value.identifierConfusableComparison.relation.replaceAll("_", " "))
  );
  if (point) result.append(element("p", `First code-point difference at #${point.index}: ${point.left.value ?? "end"} / ${point.right.value ?? "end"}.`));
  renderRuntime(value);
}

function renderIndex(value) {
  result.append(element("h2", "Coordinate map"));
  summary(metric("UTF-8 bytes", value.counts.utf8Bytes), metric("UTF-16 units", value.counts.utf16CodeUnits), metric("Code points", value.counts.codePoints), metric("Graphemes", value.counts.graphemes), metric("Lines", value.counts.lines));
  if (value.chunking) {
    result.append(element("h3", `${value.chunking.chunks.length} grapheme-safe chunks`));
    for (const chunk of value.chunking.chunks) result.append(element("pre", chunk.text, "mono text-value chunk"));
  }
  renderRuntime(value);
}

function renderTranscode(value) {
  result.append(element("h2", `${value.byteLength} bytes in ${value.targetEncoding}`));
  summary(metric("Lossy", value.lossy ? "Yes" : "No"), metric("Byte length", value.byteLength), metric("BOM", value.source.bom ?? "None"));
  result.append(element("h3", "Text"), element("p", value.text, "mono text-value"));
  const representation = value.byteRepresentation;
  const heading = representation === "bytes" ? "Bytes" : representation === "base64" ? "Base64" : "Hex";
  result.append(element("h3", heading), element("p", representation === "bytes" ? value.bytes.join(", ") : value[representation], "mono"));
  for (const warning of value.warnings) result.append(element("p", warning, "warning"));
  renderRuntime(value);
}

function renderSecurity(value) {
  const observations = value.observations;
  result.append(element("h2", "Unicode observations"));
  const scripts = observations.scriptResolution.kind === "set" ? observations.scriptResolution.scripts.join(", ") : observations.scriptResolution.kind.toUpperCase();
  summary(metric("Bidi controls", observations.signalCounts.bidiControls), metric("Default ignorables", observations.signalCounts.defaultIgnorables), metric("Format characters", observations.signalCounts.formatCharacters), metric("Resolved scripts", scripts || "—"));
  if (value.identifierProfile) summary(metric("Profile", value.identifierProfile.name.replaceAll("_", " ")), metric("Conforms", value.identifierProfile.conforms ? "Yes" : "No"), metric("Restriction", value.identifierProfile.restrictionLevel));
  if (value.confusableComparison) summary(metric("Identifier relation", value.confusableComparison.relation.replaceAll("_", " ")));
  renderRuntime(value);
}

function renderProtocol(value) {
  result.append(element("h2", value.equal === undefined ? (value.changed ? "Profile changed the text" : "Profile left the text unchanged") : (value.equal ? "Equal under this profile" : "Different under this profile")));
  result.append(element("h3", "Output"), element("p", value.output, "mono text-value"));
  if (value.comparisonOutput !== undefined) result.append(element("h3", "Comparison output"), element("p", value.comparisonOutput, "mono text-value"));
  renderRuntime(value);
}

function render(value) {
  result.replaceChildren();
  result.hidden = false;
  if (value.status === "error") {
    result.append(element("h2", value.error.code, "error"), element("p", value.error.message));
    return;
  }
  const renderers = {
    inspect: renderInspect, normalize: renderNormalize, compare: renderCompare,
    explain_difference: renderDifference, index: renderIndex, transcode: renderTranscode,
    security: renderSecurity, protocol_profile: renderProtocol
  };
  renderers[value.operation]?.(value);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  activeRequest?.abort();
  const controller = new AbortController();
  activeRequest = controller;
  const serial = ++requestSerial;
  result.hidden = true;
  result.replaceChildren();
  const button = form.querySelector("button");
  button.disabled = true;
  try {
    const args = requestArguments();
    const response = await fetch("/api/run", {
      method: "POST", headers: { "content-type": "application/json" }, signal: controller.signal,
      body: JSON.stringify({ operation: operation.value, arguments: args })
    });
    const value = await response.json();
    if (serial === requestSerial) render(value);
  } catch (error) {
    if (error.name !== "AbortError" && serial === requestSerial) {
      render({ status: "error", error: { code: "INVALID_INPUT", message: error.message || "The local service is unavailable." } });
    }
  } finally {
    if (serial === requestSerial) {
      button.disabled = false;
      activeRequest = undefined;
    }
  }
});
