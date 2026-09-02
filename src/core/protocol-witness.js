import { UTS46_ENGINE_IDENTITY, UTS46_ENGINE_LABEL } from "./protocol-engine.js";

const TRANSFORMATION_KEYS = Object.freeze({
  width_mapping: "widthMapping",
  additional_mapping: "additionalMapping",
  case_mapping: "caseMapping",
  nfc: "nfc"
});

const VALIDATION_KEYS = Object.freeze({
  identifier_class: "profileClass",
  freeform_class: "profileClass",
  bidi_rule: "bidiRule",
  non_empty: "nonEmpty"
});

function countTemplate(keys) {
  return Object.fromEntries(keys.map((key) => [key, { applications: 0, changes: 0 }]));
}

function validationTemplate() {
  return { profileClass: 0, bidiRule: 0, nonEmpty: 0 };
}

export function createPrecisSideTrace(mode, side) {
  const transformations = countTemplate(Object.values(TRANSFORMATION_KEYS));
  const validations = validationTemplate();
  const passes = [];
  let current = null;
  let stabilizedAfterPass = null;
  let stabilityCheckPerformed = false;

  return {
    startPass(input, verificationOnly = false) {
      if (current !== null) throw new Error("A PRECIS witness pass is already active.");
      stabilityCheckPerformed ||= verificationOnly;
      current = {
        index: passes.length + 1,
        verificationOnly,
        input,
        currentText: input,
        events: []
      };
    },
    transform(stage, input, output) {
      if (current === null || current.currentText !== input || !Object.hasOwn(TRANSFORMATION_KEYS, stage)) {
        throw new Error("The PRECIS witness transformation is inconsistent with execution.");
      }
      const counter = transformations[TRANSFORMATION_KEYS[stage]];
      counter.applications += 1;
      counter.changes += input === output ? 0 : 1;
      if (mode === "full_required") {
        current.events.push({ kind: "transform", stage, output, changed: input !== output });
      }
      current.currentText = output;
    },
    validate(stage) {
      if (current === null || !Object.hasOwn(VALIDATION_KEYS, stage)) {
        throw new Error("The PRECIS witness validation is inconsistent with execution.");
      }
      validations[VALIDATION_KEYS[stage]] += 1;
      if (mode === "full_required") {
        current.events.push({ kind: "validation", stage, outcome: "passed" });
      }
    },
    finishPass(output, stabilized) {
      if (current === null || current.currentText !== output) {
        throw new Error("The PRECIS witness pass output is inconsistent with execution.");
      }
      if (stabilized) stabilizedAfterPass = current.index;
      passes.push({
        index: current.index,
        verificationOnly: current.verificationOnly,
        input: current.input,
        events: current.events,
        output,
        changed: current.input !== output,
        stabilized
      });
      current = null;
    },
    result() {
      if (current !== null || stabilizedAfterPass === null) {
        throw new Error("The PRECIS witness is incomplete.");
      }
      return {
        side,
        passCount: passes.length,
        stabilizedAfterPass,
        stabilityCheckPerformed,
        transformations,
        validations,
        ...(mode === "full_required" ? { passes } : {})
      };
    }
  };
}

export function buildPrecisWitness(mode, profile, traces) {
  return {
    kind: "precis",
    mode,
    framework: "RFC 8264",
    profile: "RFC 8265",
    selectedProfile: profile,
    sides: traces.map((trace) => trace.result())
  };
}

function isAscii(value) {
  return [...value].every((character) => character.codePointAt(0) <= 0x7f);
}

function uts46Stage(stage, text) {
  return { stage, text, codePointCount: [...text].length, ascii: isAscii(text) };
}

export function buildUts46Witness(mode, action, input, output) {
  const summary = {
    kind: "uts46",
    mode,
    specification: UTS46_ENGINE_IDENTITY.specification,
    engine: UTS46_ENGINE_LABEL,
    action,
    inputCodePointCount: [...input].length,
    outputCodePointCount: [...output].length,
    inputAscii: isAscii(input),
    outputAscii: isAscii(output),
    inputTrailingRoot: input.endsWith("."),
    outputTrailingRoot: output.endsWith("."),
    changed: input !== output
  };
  return mode === "full_required"
    ? { ...summary, stages: [uts46Stage("input", input), uts46Stage("engine_output", output)] }
    : summary;
}
