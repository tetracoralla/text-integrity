mod bidi_data;
mod bidi_reorder;
mod confusable;
mod difference;
mod difference_alignment;
mod difference_support;
mod index;
mod index_types;
mod inspect;
mod model;
mod namespace_integrity;
mod nfkc_casefold;
mod nfkc_casefold_data;
mod normalize;
mod precis_core;
mod precis_data;
mod precis_witness;
mod protocol;
mod protocol_precis;
mod protocol_uts46;
mod script_data;
mod security;
mod security_data;
mod source_diagnostics;
mod transcode;
mod transcode_decode;
mod uts39_skeleton;
mod uts39_skeleton_data;
mod validation;

#[cfg(test)]
mod bidi_conformance_tests;

use std::alloc::{Layout, alloc, dealloc};
use std::fmt;
use std::slice;
use std::sync::Mutex;

use model::{Request, error};
use serde_json::{Value, json};

pub const RAW_ABI_VERSION: u32 = 2;
pub const MAX_RAW_INPUT_BYTES: usize = 1_048_576;
pub const MAX_RAW_BATCH_REQUESTS: usize = 1_024;
pub const MAX_RAW_RESULT_BYTES: usize = 8_388_608;
pub const MAX_RAW_DIFFERENCE_ALIGNMENT_CELLS: u64 =
    2 * model::MAX_TEXT_BYTES as u64 * model::MAX_TEXT_BYTES as u64;
pub const MAX_RAW_SOURCE_DIAGNOSTIC_UNITS: u64 = model::MAX_TEXT_BYTES as u64
    * (1 + source_diagnostics::MAX_SOURCE_SPANS as u64
        + 2 * source_diagnostics::MAX_DETAIL_ITEMS as u64);
pub const MAX_RAW_UTS46_PUNYCODE_SCAN_UNITS: u64 =
    model::MAX_TEXT_BYTES as u64 * model::MAX_TEXT_BYTES as u64;

pub const RAW_STATUS_OK: i32 = 0;
pub const RAW_STATUS_INVALID_INPUT_BUFFER: i32 = 1;
pub const RAW_STATUS_INPUT_TOO_LARGE: i32 = 2;
pub const RAW_STATUS_BATCH_TOO_LARGE: i32 = 3;
pub const RAW_STATUS_RESULT_TOO_LARGE: i32 = 4;
pub const RAW_STATUS_DIFFERENCE_ALIGNMENT_WORK_TOO_LARGE: i32 = 5;
pub const RAW_STATUS_SOURCE_DIAGNOSTIC_WORK_TOO_LARGE: i32 = 6;
pub const RAW_STATUS_UTS46_PUNYCODE_WORK_TOO_LARGE: i32 = 7;

#[derive(Clone, Copy)]
struct WasmInputAllocation {
    pointer: usize,
    length: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RawFrameError {
    InputTooLarge,
    BatchTooLarge,
    ResultTooLarge,
    DifferenceAlignmentWorkTooLarge,
    SourceDiagnosticWorkTooLarge,
    Uts46PunycodeWorkTooLarge,
}

impl RawFrameError {
    pub fn status(&self) -> i32 {
        match self {
            Self::InputTooLarge => RAW_STATUS_INPUT_TOO_LARGE,
            Self::BatchTooLarge => RAW_STATUS_BATCH_TOO_LARGE,
            Self::ResultTooLarge => RAW_STATUS_RESULT_TOO_LARGE,
            Self::DifferenceAlignmentWorkTooLarge => RAW_STATUS_DIFFERENCE_ALIGNMENT_WORK_TOO_LARGE,
            Self::SourceDiagnosticWorkTooLarge => RAW_STATUS_SOURCE_DIAGNOSTIC_WORK_TOO_LARGE,
            Self::Uts46PunycodeWorkTooLarge => RAW_STATUS_UTS46_PUNYCODE_WORK_TOO_LARGE,
        }
    }
}

impl fmt::Display for RawFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => write!(
                formatter,
                "raw request frame exceeds the {MAX_RAW_INPUT_BYTES}-byte limit"
            ),
            Self::BatchTooLarge => write!(
                formatter,
                "raw request frame exceeds the {MAX_RAW_BATCH_REQUESTS}-request batch limit"
            ),
            Self::ResultTooLarge => write!(
                formatter,
                "raw result frame exceeds the {MAX_RAW_RESULT_BYTES}-byte limit"
            ),
            Self::DifferenceAlignmentWorkTooLarge => write!(
                formatter,
                "raw request frame exceeds the {MAX_RAW_DIFFERENCE_ALIGNMENT_CELLS}-cell difference-alignment work limit"
            ),
            Self::SourceDiagnosticWorkTooLarge => write!(
                formatter,
                "raw request frame exceeds the {MAX_RAW_SOURCE_DIAGNOSTIC_UNITS}-unit source-diagnostic work limit"
            ),
            Self::Uts46PunycodeWorkTooLarge => write!(
                formatter,
                "raw request frame exceeds the {MAX_RAW_UTS46_PUNYCODE_SCAN_UNITS}-unit UTS #46 Punycode scan work limit"
            ),
        }
    }
}

static WASM_INPUT_ALLOCATION: Mutex<Option<WasmInputAllocation>> = Mutex::new(None);
static WASM_RESULT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn serialize(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("runner value serializes")
}

fn run_request(value: Value) -> Vec<u8> {
    let request: Request = match serde_json::from_value(value) {
        Ok(value) => value,
        Err(_) => {
            return serialize(&error(
                "INVALID_INPUT",
                "request must contain only operation and arguments.",
                json!({ "field": "request" }),
            ));
        }
    };
    match request.operation.as_str() {
        "inspect" => inspect::inspect(request.arguments),
        "reference_explain_difference_spine" => serialize(&difference::run(request.arguments)),
        "index" => serialize(&index::index(request.arguments)),
        "normalize" => serialize(&normalize::normalize(request.arguments)),
        "namespace_integrity" => serialize(&namespace_integrity::run(request.arguments)),
        "protocol_profile" => serialize(&protocol::run(request.arguments)),
        "reference_nfkc_casefold" => serialize(&nfkc_casefold::run(request.arguments)),
        "reference_uts39_post_reorder_skeleton" => {
            serialize(&uts39_skeleton::run(request.arguments))
        }
        "reference_bidi_skeleton" => serialize(&bidi_reorder::run(request.arguments)),
        "reference_confusable_comparison" => serialize(&confusable::run(request.arguments)),
        "security" => {
            if request.arguments.get("mode").and_then(Value::as_str) == Some("source") {
                serialize(&source_diagnostics::run(request.arguments))
            } else {
                serialize(&security::run(request.arguments))
            }
        }
        "transcode" => serialize(&transcode::transcode(request.arguments)),
        _ => serialize(&error(
            "UNKNOWN_OPERATION",
            format!("Unknown operation: {}.", request.operation),
            json!({ "allowed": ["index", "inspect", "namespace_integrity", "normalize", "protocol_profile", "reference_bidi_skeleton", "reference_confusable_comparison", "reference_explain_difference_spine", "reference_nfkc_casefold", "reference_uts39_post_reorder_skeleton", "security", "transcode"] }),
        )),
    }
}

fn enforce_raw_work_budget(requests: &[Value]) -> Result<(), RawFrameError> {
    let mut difference_alignment_cells = 0_u64;
    let mut source_diagnostic_units = 0_u64;
    let mut uts46_punycode_scan_units = 0_u64;
    for request in requests {
        let Some(object) = request.as_object() else {
            continue;
        };
        let Some(operation) = object.get("operation").and_then(Value::as_str) else {
            continue;
        };
        let Some(arguments) = object.get("arguments") else {
            continue;
        };
        if operation == "reference_explain_difference_spine" {
            difference_alignment_cells = difference_alignment_cells
                .checked_add(difference::raw_alignment_grid_cells(arguments))
                .ok_or(RawFrameError::DifferenceAlignmentWorkTooLarge)?;
            if difference_alignment_cells > MAX_RAW_DIFFERENCE_ALIGNMENT_CELLS {
                return Err(RawFrameError::DifferenceAlignmentWorkTooLarge);
            }
        } else if operation == "security"
            && arguments.get("mode").and_then(Value::as_str) == Some("source")
        {
            source_diagnostic_units = source_diagnostic_units
                .checked_add(source_diagnostics::raw_source_diagnostic_units(arguments))
                .ok_or(RawFrameError::SourceDiagnosticWorkTooLarge)?;
            if source_diagnostic_units > MAX_RAW_SOURCE_DIAGNOSTIC_UNITS {
                return Err(RawFrameError::SourceDiagnosticWorkTooLarge);
            }
        } else if operation == "protocol_profile"
            && arguments.get("profile").and_then(Value::as_str) == Some("uts46_domain")
        {
            uts46_punycode_scan_units = uts46_punycode_scan_units
                .checked_add(protocol_uts46::raw_punycode_scan_units(arguments))
                .ok_or(RawFrameError::Uts46PunycodeWorkTooLarge)?;
            if uts46_punycode_scan_units > MAX_RAW_UTS46_PUNYCODE_SCAN_UNITS {
                return Err(RawFrameError::Uts46PunycodeWorkTooLarge);
            }
        }
    }
    Ok(())
}

fn run_value(value: Value) -> Result<Vec<u8>, RawFrameError> {
    if let Value::Array(requests) = value {
        if requests.len() > MAX_RAW_BATCH_REQUESTS {
            return Err(RawFrameError::BatchTooLarge);
        }
        enforce_raw_work_budget(&requests)?;
        let mut output = Vec::from(b"[".as_slice());
        for (index, request) in requests.into_iter().enumerate() {
            let result = run_request(request);
            let separator_bytes = usize::from(index > 0);
            let framed_bytes = output
                .len()
                .checked_add(separator_bytes)
                .and_then(|length| length.checked_add(result.len()))
                .and_then(|length| length.checked_add(1))
                .ok_or(RawFrameError::ResultTooLarge)?;
            if framed_bytes > MAX_RAW_RESULT_BYTES {
                return Err(RawFrameError::ResultTooLarge);
            }
            if index > 0 {
                output.push(b',');
            }
            output.extend(result);
        }
        output.push(b']');
        Ok(output)
    } else {
        enforce_raw_work_budget(std::slice::from_ref(&value))?;
        let output = run_request(value);
        if output.len() > MAX_RAW_RESULT_BYTES {
            return Err(RawFrameError::ResultTooLarge);
        }
        Ok(output)
    }
}

pub fn run_json_bytes(input: &[u8]) -> Result<Vec<u8>, RawFrameError> {
    if input.len() > MAX_RAW_INPUT_BYTES {
        return Err(RawFrameError::InputTooLarge);
    }
    let value: Value = match serde_json::from_slice(input) {
        Ok(value) => value,
        Err(_) => {
            return Ok(serde_json::to_vec(&error(
                "INVALID_INPUT",
                "input must be one JSON request or an array of JSON requests.",
                json!({ "field": "input" }),
            ))
            .expect("static error serializes"));
        }
    };
    run_value(value)
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_alloc(length: usize) -> *mut u8 {
    WASM_RESULT
        .lock()
        .expect("result mutex is not poisoned")
        .clear();
    if length == 0 || length > MAX_RAW_INPUT_BYTES {
        return std::ptr::null_mut();
    }
    let mut current = WASM_INPUT_ALLOCATION
        .lock()
        .expect("input-allocation mutex is not poisoned");
    if current.is_some() {
        return std::ptr::null_mut();
    }
    let layout = Layout::array::<u8>(length).expect("bounded input allocation");
    let pointer = unsafe { alloc(layout) };
    if !pointer.is_null() {
        *current = Some(WasmInputAllocation {
            pointer: pointer as usize,
            length,
        });
    }
    pointer
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_dealloc(pointer: *mut u8, length: usize) {
    let allocation = {
        let mut current = WASM_INPUT_ALLOCATION
            .lock()
            .expect("input-allocation mutex is not poisoned");
        match *current {
            Some(allocation)
                if allocation.pointer == pointer as usize && allocation.length == length =>
            {
                current.take()
            }
            _ => None,
        }
    };
    let Some(allocation) = allocation else {
        return;
    };
    let layout = Layout::array::<u8>(allocation.length).expect("bounded input allocation");
    unsafe { dealloc(allocation.pointer as *mut u8, layout) };
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_run(pointer: *const u8, length: usize) -> i32 {
    WASM_RESULT
        .lock()
        .expect("result mutex is not poisoned")
        .clear();
    if length > MAX_RAW_INPUT_BYTES {
        return RAW_STATUS_INPUT_TOO_LARGE;
    }
    let allocation = *WASM_INPUT_ALLOCATION
        .lock()
        .expect("input-allocation mutex is not poisoned");
    if length == 0
        || allocation.is_none_or(|allocation| {
            allocation.pointer != pointer as usize || allocation.length != length
        })
    {
        return RAW_STATUS_INVALID_INPUT_BUFFER;
    }
    let input = unsafe { slice::from_raw_parts(pointer, length) };
    match run_json_bytes(input) {
        Ok(output) => {
            *WASM_RESULT.lock().expect("result mutex is not poisoned") = output;
            RAW_STATUS_OK
        }
        Err(error) => error.status(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_abi_version() -> u32 {
    RAW_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_max_input_len() -> usize {
    MAX_RAW_INPUT_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_max_batch_len() -> usize {
    MAX_RAW_BATCH_REQUESTS
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_max_result_len() -> usize {
    MAX_RAW_RESULT_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_max_difference_alignment_cells() -> usize {
    MAX_RAW_DIFFERENCE_ALIGNMENT_CELLS as usize
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_max_source_diagnostic_units() -> usize {
    MAX_RAW_SOURCE_DIAGNOSTIC_UNITS as usize
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_max_uts46_punycode_scan_units() -> usize {
    MAX_RAW_UTS46_PUNYCODE_SCAN_UNITS as usize
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_result_ptr() -> *const u8 {
    WASM_RESULT
        .lock()
        .expect("result mutex is not poisoned")
        .as_ptr()
}

#[unsafe(no_mangle)]
pub extern "C" fn ti_result_len() -> usize {
    WASM_RESULT
        .lock()
        .expect("result mutex is not poisoned")
        .len()
}

#[cfg(test)]
mod tests {
    use super::{MAX_RAW_BATCH_REQUESTS, MAX_RAW_INPUT_BYTES, RawFrameError, run_json_bytes};
    use serde_json::json;

    #[test]
    fn accepts_batches_and_preserves_invalid_utf8_witness_ranges() {
        let input = br#"[{"operation":"transcode","arguments":{"sourceKind":"bytes","bytes":[97,225,128,65,128],"sourceEncoding":"utf-8","targetEncoding":"utf-8","allowLossy":true,"byteRepresentation":"hex","witnessMode":"full_required"}}]"#;
        let output = run_json_bytes(input).unwrap();
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result[0]["text"], "a\u{fffd}A\u{fffd}");
        assert_eq!(result[0]["witness"]["segments"][1]["sourceStart"], 1);
        assert_eq!(result[0]["witness"]["segments"][1]["sourceEnd"], 3);
        assert_eq!(result[0]["witness"]["segments"][3]["sourceStart"], 4);
        assert_eq!(result[0]["witness"]["segments"][3]["sourceEnd"], 5);
    }

    #[test]
    fn bounds_raw_input_batch_and_aggregate_result_frames() {
        assert_eq!(
            run_json_bytes(&vec![b' '; MAX_RAW_INPUT_BYTES + 1]),
            Err(RawFrameError::InputTooLarge)
        );

        let too_many = serde_json::to_vec(&vec![json!({}); MAX_RAW_BATCH_REQUESTS + 1]).unwrap();
        assert_eq!(run_json_bytes(&too_many), Err(RawFrameError::BatchTooLarge));

        let request = json!({
            "operation": "inspect",
            "arguments": {
                "text": { "$text": { "kind": "unicode_scalar_string", "value": "A".repeat(64) } },
                "detailLimit": 64
            }
        });
        let output_amplification =
            serde_json::to_vec(&vec![request; MAX_RAW_BATCH_REQUESTS]).unwrap();
        assert!(output_amplification.len() < MAX_RAW_INPUT_BYTES);
        assert_eq!(
            run_json_bytes(&output_amplification),
            Err(RawFrameError::ResultTooLarge)
        );
    }

    #[test]
    fn bounds_cumulative_difference_and_source_diagnostic_work_before_execution() {
        let difference_request = json!({
            "operation": "reference_explain_difference_spine",
            "arguments": {
                "left": { "$text": { "kind": "unicode_scalar_string", "value": "A".repeat(4096) } },
                "right": { "$text": { "kind": "unicode_scalar_string", "value": "B".repeat(4096) } },
                "locale": "en",
                "options": {
                    "usage": "sort",
                    "sensitivity": "variant",
                    "ignorePunctuation": false,
                    "numeric": false,
                    "caseFirst": "false",
                    "localeMatcher": "lookup",
                    "collation": "default"
                },
                "confusableDirection": "LTR",
                "detailLimit": 0,
                "witnessMode": "summary"
            }
        });
        let difference_batch = serde_json::to_vec(&vec![difference_request; 2]).unwrap();
        assert!(difference_batch.len() < MAX_RAW_INPUT_BYTES);
        assert_eq!(
            run_json_bytes(&difference_batch),
            Err(RawFrameError::DifferenceAlignmentWorkTooLarge)
        );

        let source_request = json!({
            "operation": "security",
            "arguments": {
                "source": { "$text": { "kind": "unicode_scalar_string", "value": "A".repeat(4096) } },
                "mode": "source",
                "spans": (0..128).map(|_| json!({
                    "kind": "identifier",
                    "startUtf16": 0,
                    "endUtf16": 4096,
                    "scope": "same"
                })).collect::<Vec<_>>(),
                "confusableDirection": "LTR",
                "detailLimit": 128
            }
        });
        let source_batch = serde_json::to_vec(&vec![source_request; 2]).unwrap();
        assert!(source_batch.len() < MAX_RAW_INPUT_BYTES);
        assert_eq!(
            run_json_bytes(&source_batch),
            Err(RawFrameError::SourceDiagnosticWorkTooLarge)
        );
    }

    #[test]
    fn bounds_cumulative_uts46_punycode_scan_work_before_execution() {
        let text: String = (0..1365)
            .map(|index| char::from_u32(0x4e00 + index).unwrap())
            .collect();
        let request = json!({
            "operation": "protocol_profile",
            "arguments": {
                "profile": "uts46_domain",
                "action": "to_ascii",
                "text": { "$text": { "kind": "unicode_scalar_string", "value": text } },
                "options": {
                    "checkBidi": false,
                    "checkHyphens": true,
                    "checkJoiners": true,
                    "ignoreInvalidPunycode": false,
                    "transitionalProcessing": false,
                    "useSTD3ASCIIRules": true,
                    "verifyDNSLength": false
                },
                "witnessMode": "full_required"
            }
        });
        let batch = serde_json::to_vec(&vec![request; 10]).unwrap();
        assert!(batch.len() < MAX_RAW_INPUT_BYTES);
        assert_eq!(
            run_json_bytes(&batch),
            Err(RawFrameError::Uts46PunycodeWorkTooLarge)
        );
    }

    #[test]
    fn malformed_json_remains_a_bounded_semantic_error_envelope() {
        let output = run_json_bytes(b"{").unwrap();
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["status"], "error");
        assert_eq!(result["error"]["code"], "INVALID_INPUT");
        assert!(output.len() < 256);
    }
}
