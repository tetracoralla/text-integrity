use serde_json::{Value, json};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WitnessMode {
    None,
    Summary,
    FullRequired,
}

impl WitnessMode {
    pub(crate) fn parse(value: Option<&str>) -> Option<Self> {
        match value.unwrap_or("none") {
            "none" => Some(Self::None),
            "summary" => Some(Self::Summary),
            "full_required" => Some(Self::FullRequired),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Summary => "summary",
            Self::FullRequired => "full_required",
        }
    }
}

#[derive(Default)]
struct Counter {
    applications: usize,
    changes: usize,
}

impl Counter {
    fn record(&mut self, changed: bool) {
        self.applications += 1;
        self.changes += usize::from(changed);
    }

    fn value(&self) -> Value {
        json!({ "applications": self.applications, "changes": self.changes })
    }
}

struct CurrentPass {
    index: usize,
    verification_only: bool,
    input: String,
    current_text: String,
    events: Vec<Value>,
}

pub(crate) struct SideTrace {
    mode: WitnessMode,
    side: &'static str,
    width_mapping: Counter,
    additional_mapping: Counter,
    case_mapping: Counter,
    nfc: Counter,
    profile_class: usize,
    bidi_rule: usize,
    non_empty: usize,
    pass_count: usize,
    passes: Vec<Value>,
    current: Option<CurrentPass>,
    stabilized_after_pass: Option<usize>,
    stability_check_performed: bool,
}

impl SideTrace {
    pub(crate) fn new(mode: WitnessMode, side: &'static str) -> Self {
        Self {
            mode,
            side,
            width_mapping: Counter::default(),
            additional_mapping: Counter::default(),
            case_mapping: Counter::default(),
            nfc: Counter::default(),
            profile_class: 0,
            bidi_rule: 0,
            non_empty: 0,
            pass_count: 0,
            passes: Vec::new(),
            current: None,
            stabilized_after_pass: None,
            stability_check_performed: false,
        }
    }

    pub(crate) fn start_pass(&mut self, input: &str, verification_only: bool) {
        debug_assert!(self.current.is_none());
        self.stability_check_performed |= verification_only;
        self.current = Some(CurrentPass {
            index: self.pass_count + 1,
            verification_only,
            input: input.to_owned(),
            current_text: input.to_owned(),
            events: Vec::new(),
        });
    }

    pub(crate) fn transform(&mut self, stage: &'static str, input: &str, output: &str) {
        let current = self
            .current
            .as_mut()
            .expect("PRECIS witness pass is active");
        debug_assert_eq!(current.current_text, input);
        let changed = input != output;
        match stage {
            "width_mapping" => self.width_mapping.record(changed),
            "additional_mapping" => self.additional_mapping.record(changed),
            "case_mapping" => self.case_mapping.record(changed),
            "nfc" => self.nfc.record(changed),
            _ => unreachable!("PRECIS transformation stage is closed"),
        }
        if self.mode == WitnessMode::FullRequired {
            current.events.push(json!({
                "kind": "transform",
                "stage": stage,
                "output": output,
                "changed": changed
            }));
        }
        current.current_text = output.to_owned();
    }

    pub(crate) fn validate(&mut self, stage: &'static str) {
        let current = self
            .current
            .as_mut()
            .expect("PRECIS witness pass is active");
        match stage {
            "identifier_class" | "freeform_class" => self.profile_class += 1,
            "bidi_rule" => self.bidi_rule += 1,
            "non_empty" => self.non_empty += 1,
            _ => unreachable!("PRECIS validation stage is closed"),
        }
        if self.mode == WitnessMode::FullRequired {
            current.events.push(json!({
                "kind": "validation",
                "stage": stage,
                "outcome": "passed"
            }));
        }
    }

    pub(crate) fn finish_pass(&mut self, output: &str, stabilized: bool) {
        let current = self.current.take().expect("PRECIS witness pass is active");
        debug_assert_eq!(current.current_text, output);
        if stabilized {
            self.stabilized_after_pass = Some(current.index);
        }
        self.pass_count = current.index;
        if self.mode == WitnessMode::FullRequired {
            self.passes.push(json!({
                "index": current.index,
                "verificationOnly": current.verification_only,
                "input": current.input,
                "events": current.events,
                "output": output,
                "changed": current.input != output,
                "stabilized": stabilized
            }));
        }
    }

    fn result(self) -> Value {
        debug_assert!(self.current.is_none());
        let mut result = json!({
            "side": self.side,
            "passCount": self.pass_count,
            "stabilizedAfterPass": self.stabilized_after_pass.expect("PRECIS witness stabilized"),
            "stabilityCheckPerformed": self.stability_check_performed,
            "transformations": {
                "widthMapping": self.width_mapping.value(),
                "additionalMapping": self.additional_mapping.value(),
                "caseMapping": self.case_mapping.value(),
                "nfc": self.nfc.value()
            },
            "validations": {
                "profileClass": self.profile_class,
                "bidiRule": self.bidi_rule,
                "nonEmpty": self.non_empty
            }
        });
        if self.mode == WitnessMode::FullRequired {
            result["passes"] = Value::Array(self.passes);
        }
        result
    }
}

pub(crate) fn build_witness(mode: WitnessMode, profile: &str, traces: Vec<SideTrace>) -> Value {
    json!({
        "kind": "precis",
        "mode": mode.label(),
        "framework": "RFC 8264",
        "profile": "RFC 8265",
        "selectedProfile": profile,
        "sides": traces.into_iter().map(SideTrace::result).collect::<Vec<_>>()
    })
}
