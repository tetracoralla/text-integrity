#[derive(Clone, Debug)]
pub(crate) struct RawSegment {
    pub(crate) code_point: u32,
    pub(crate) replacement: bool,
    pub(crate) source_start: usize,
    pub(crate) source_end: usize,
}

fn replacement(start: usize, end: usize) -> RawSegment {
    RawSegment {
        code_point: 0xfffd,
        replacement: true,
        source_start: start,
        source_end: end,
    }
}

fn scalar(code_point: u32, start: usize, end: usize) -> RawSegment {
    RawSegment {
        code_point,
        replacement: false,
        source_start: start,
        source_end: end,
    }
}

fn is_continuation(value: u8) -> bool {
    (0x80..=0xbf).contains(&value)
}

pub(crate) fn utf8_segments(bytes: &[u8]) -> Vec<RawSegment> {
    let mut segments = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        if first <= 0x7f {
            segments.push(scalar(first.into(), index, index + 1));
            index += 1;
            continue;
        }
        let (length, minimum_second, maximum_second) = match first {
            0xc2..=0xdf => (2, 0x80, 0xbf),
            0xe0 => (3, 0xa0, 0xbf),
            0xe1..=0xec | 0xee..=0xef => (3, 0x80, 0xbf),
            0xed => (3, 0x80, 0x9f),
            0xf0 => (4, 0x90, 0xbf),
            0xf1..=0xf3 => (4, 0x80, 0xbf),
            0xf4 => (4, 0x80, 0x8f),
            _ => {
                segments.push(replacement(index, index + 1));
                index += 1;
                continue;
            }
        };
        let Some(&second) = bytes.get(index + 1) else {
            segments.push(replacement(index, bytes.len()));
            break;
        };
        if second < minimum_second || second > maximum_second {
            segments.push(replacement(index, index + 1));
            index += 1;
            continue;
        }
        let mut end = index + 2;
        while end < index + length && end < bytes.len() && is_continuation(bytes[end]) {
            end += 1;
        }
        if end < index + length {
            segments.push(replacement(index, end));
            index = end;
            continue;
        }
        let code_point = match length {
            2 => (((first & 0x1f) as u32) << 6) | ((second & 0x3f) as u32),
            3 => {
                (((first & 0x0f) as u32) << 12)
                    | (((second & 0x3f) as u32) << 6)
                    | ((bytes[index + 2] & 0x3f) as u32)
            }
            _ => {
                (((first & 0x07) as u32) << 18)
                    | (((second & 0x3f) as u32) << 12)
                    | (((bytes[index + 2] & 0x3f) as u32) << 6)
                    | ((bytes[index + 3] & 0x3f) as u32)
            }
        };
        segments.push(scalar(code_point, index, index + length));
        index += length;
    }
    segments
}

pub(crate) fn utf16le_segments(bytes: &[u8]) -> Vec<RawSegment> {
    let mut segments = Vec::new();
    let mut index = 0;
    while index + 1 < bytes.len() {
        let unit = u16::from_le_bytes([bytes[index], bytes[index + 1]]);
        if (0xd800..=0xdbff).contains(&unit) {
            if index + 3 < bytes.len() {
                let next = u16::from_le_bytes([bytes[index + 2], bytes[index + 3]]);
                if (0xdc00..=0xdfff).contains(&next) {
                    let code_point =
                        0x10000 + (((unit as u32) - 0xd800) << 10) + ((next as u32) - 0xdc00);
                    segments.push(scalar(code_point, index, index + 4));
                    index += 4;
                    continue;
                }
            } else if index + 2 < bytes.len() {
                segments.push(replacement(index, bytes.len()));
                index = bytes.len();
                break;
            }
            segments.push(replacement(index, index + 2));
            index += 2;
            continue;
        }
        if (0xdc00..=0xdfff).contains(&unit) {
            segments.push(replacement(index, index + 2));
            index += 2;
            continue;
        }
        segments.push(scalar(unit.into(), index, index + 2));
        index += 2;
    }
    if index < bytes.len() {
        segments.push(replacement(index, bytes.len()));
    }
    segments
}

pub(crate) fn utf16_segments(units: &[u16]) -> Vec<RawSegment> {
    let mut segments = Vec::new();
    let mut index = 0;
    while index < units.len() {
        let unit = units[index];
        if (0xd800..=0xdbff).contains(&unit) {
            if let Some(&next) = units.get(index + 1) {
                if (0xdc00..=0xdfff).contains(&next) {
                    let code_point =
                        0x10000 + (((unit as u32) - 0xd800) << 10) + ((next as u32) - 0xdc00);
                    segments.push(scalar(code_point, index, index + 2));
                    index += 2;
                    continue;
                }
            }
            segments.push(replacement(index, index + 1));
            index += 1;
            continue;
        }
        if (0xdc00..=0xdfff).contains(&unit) {
            segments.push(replacement(index, index + 1));
            index += 1;
            continue;
        }
        segments.push(scalar(unit.into(), index, index + 1));
        index += 1;
    }
    segments
}

pub(crate) fn decoded_text(segments: &[RawSegment]) -> String {
    segments
        .iter()
        .map(|segment| {
            char::from_u32(segment.code_point).expect("segments contain only Unicode scalar values")
        })
        .collect()
}

pub(crate) fn encode_text(text: &str, encoding: &str) -> Vec<u8> {
    if encoding == "utf-8" {
        text.as_bytes().to_vec()
    } else {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }
}

pub(crate) fn bom_kind(bytes: &[u8], encoding: &str) -> Option<&'static str> {
    if encoding == "utf-8" && bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        Some("utf-8")
    } else if encoding == "utf-16le" && bytes.starts_with(&[0xff, 0xfe]) {
        Some("utf-16le")
    } else {
        None
    }
}

pub(crate) fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            ALPHABET[(third & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    output
}
