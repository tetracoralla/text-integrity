import {
  arrayOf,
  boolean,
  closed,
  integer,
  runtime,
  string,
  success
} from "./common.js";
import { UTS46_ENGINE_IDENTITY, UTS46_ENGINE_LABEL } from "../core/protocol-engine.js";

const precisProfile = {
  type: "string",
  enum: ["precis_username_case_mapped", "precis_username_case_preserved", "precis_opaque_string"]
};

const witnessModeSummary = { const: "summary" };
const witnessModeFull = { const: "full_required" };

const uts46WitnessBase = (action) => ({
  kind: { const: "uts46" },
  specification: { const: UTS46_ENGINE_IDENTITY.specification },
  engine: { const: UTS46_ENGINE_LABEL },
  action: { const: action },
  inputCodePointCount: integer,
  outputCodePointCount: integer,
  inputAscii: boolean,
  outputAscii: boolean,
  inputTrailingRoot: boolean,
  outputTrailingRoot: boolean,
  changed: boolean
});

const uts46Witness = (action) => {
  const base = uts46WitnessBase(action);
  return {
    oneOf: [
      closed(["kind", "mode", ...Object.keys(base).filter((key) => key !== "kind")], {
        kind: base.kind,
        mode: witnessModeSummary,
        ...Object.fromEntries(Object.entries(base).filter(([key]) => key !== "kind"))
      }),
      closed(["kind", "mode", ...Object.keys(base).filter((key) => key !== "kind"), "stages"], {
        kind: base.kind,
        mode: witnessModeFull,
        ...Object.fromEntries(Object.entries(base).filter(([key]) => key !== "kind")),
        stages: {
          type: "array",
          minItems: 2,
          maxItems: 2,
          items: closed(
            ["stage", "text", "codePointCount", "ascii"],
            {
              stage: { type: "string", enum: ["input", "engine_output"] },
              text: string,
              codePointCount: integer,
              ascii: boolean
            }
          )
        }
      })
    ]
  };
};

const applicationCount = closed(["applications", "changes"], { applications: integer, changes: integer });
const transformations = closed(
  ["widthMapping", "additionalMapping", "caseMapping", "nfc"],
  {
    widthMapping: applicationCount,
    additionalMapping: applicationCount,
    caseMapping: applicationCount,
    nfc: applicationCount
  }
);
const validations = closed(
  ["profileClass", "bidiRule", "nonEmpty"],
  { profileClass: integer, bidiRule: integer, nonEmpty: integer }
);

const transformEvent = closed(
  ["kind", "stage", "output", "changed"],
  {
    kind: { const: "transform" },
    stage: { type: "string", enum: ["width_mapping", "additional_mapping", "case_mapping", "nfc"] },
    output: string,
    changed: boolean
  }
);
const validationEvent = closed(
  ["kind", "stage", "outcome"],
  {
    kind: { const: "validation" },
    stage: { type: "string", enum: ["identifier_class", "freeform_class", "bidi_rule", "non_empty"] },
    outcome: { const: "passed" }
  }
);
const precisPass = closed(
  ["index", "verificationOnly", "input", "events", "output", "changed", "stabilized"],
  {
    index: integer,
    verificationOnly: boolean,
    input: string,
    events: { type: "array", minItems: 4, maxItems: 6, items: { oneOf: [transformEvent, validationEvent] } },
    output: string,
    changed: boolean,
    stabilized: boolean
  }
);

const precisSideBase = {
  side: { type: "string", enum: ["text", "comparison"] },
  passCount: integer,
  stabilizedAfterPass: integer,
  stabilityCheckPerformed: boolean,
  transformations,
  validations
};
const precisSide = (full) => closed(
  [...Object.keys(precisSideBase), ...(full ? ["passes"] : [])],
  { ...precisSideBase, ...(full ? { passes: { type: "array", minItems: 1, maxItems: 5, items: precisPass } } : {}) }
);

const precisWitnessBase = {
  kind: { const: "precis" },
  framework: { const: "RFC 8264" },
  profile: { const: "RFC 8265" },
  selectedProfile: precisProfile
};
const precisWitness = {
  oneOf: [
    closed(["kind", "mode", "framework", "profile", "selectedProfile", "sides"], {
      ...precisWitnessBase,
      mode: witnessModeSummary,
      sides: { type: "array", minItems: 1, maxItems: 2, items: precisSide(false) }
    }),
    closed(["kind", "mode", "framework", "profile", "selectedProfile", "sides"], {
      ...precisWitnessBase,
      mode: witnessModeFull,
      sides: { type: "array", minItems: 1, maxItems: 2, items: precisSide(true) }
    })
  ]
};

const uts46OptionsBase = {
  checkBidi: boolean,
  checkHyphens: boolean,
  checkJoiners: boolean,
  ignoreInvalidPunycode: boolean,
  transitionalProcessing: boolean,
  useSTD3ASCIIRules: boolean
};

const uts46Standards = closed(
  ["specification", "unicodeVersion", "engine"],
  {
    specification: { const: UTS46_ENGINE_IDENTITY.specification },
    unicodeVersion: { const: UTS46_ENGINE_IDENTITY.unicodeVersion },
    engine: { const: UTS46_ENGINE_LABEL }
  }
);

export function uts46(action) {
  const options = action === "to_ascii"
    ? { ...uts46OptionsBase, verifyDNSLength: boolean }
    : uts46OptionsBase;
  return success("protocol_profile", {
    profile: { const: "uts46_domain" },
    action: { const: action },
    output: string,
    changed: boolean,
    options: closed(Object.keys(options), options),
    standards: uts46Standards,
    runtime
  }, { witness: uts46Witness(action) });
}

const precisStandards = closed(
  ["framework", "profile", "unicodeVersion"],
  { framework: { const: "RFC 8264" }, profile: { const: "RFC 8265" }, unicodeVersion: { const: "17.0.0" } }
);

export const precisEnforce = success("protocol_profile", {
  profile: precisProfile,
  action: { const: "enforce" },
  output: string,
  changed: boolean,
  standards: precisStandards,
  runtime
}, { witness: precisWitness });

export const precisCompare = success("protocol_profile", {
  profile: precisProfile,
  action: { const: "compare" },
  output: string,
  changed: boolean,
  comparisonOutput: string,
  comparisonChanged: boolean,
  equal: boolean,
  standards: precisStandards,
  runtime
}, { witness: precisWitness });
