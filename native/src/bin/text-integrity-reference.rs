use std::io::{self, Read, Write};

use text_integrity_reference::{MAX_RAW_INPUT_BYTES, RawFrameError};

fn exit_frame_error(error: RawFrameError) -> ! {
    eprintln!("raw frame error {}: {error}", error.status());
    std::process::exit(error.status());
}

fn main() {
    let mut input = Vec::with_capacity(MAX_RAW_INPUT_BYTES + 1);
    let stdin = io::stdin();
    let mut bounded_stdin = stdin.lock().take((MAX_RAW_INPUT_BYTES + 1) as u64);
    if bounded_stdin.read_to_end(&mut input).is_err() {
        std::process::exit(1);
    }
    if input.len() > MAX_RAW_INPUT_BYTES {
        exit_frame_error(RawFrameError::InputTooLarge);
    }
    match text_integrity_reference::run_json_bytes(&input) {
        Ok(output) => {
            if io::stdout().write_all(&output).is_err() {
                std::process::exit(1);
            }
        }
        Err(error) => exit_frame_error(error),
    }
}
