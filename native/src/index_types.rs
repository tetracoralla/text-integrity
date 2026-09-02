use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Coordinate {
    pub(crate) utf8_byte: usize,
    pub(crate) utf16_code_unit: usize,
    pub(crate) code_point: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) grapheme: Option<usize>,
    pub(crate) line: usize,
    pub(crate) column_code_point: usize,
    pub(crate) column_utf16_code_unit: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct CodePointEntry {
    pub(crate) character: String,
    pub(crate) value: String,
    pub(crate) grapheme: usize,
    pub(crate) start: Coordinate,
    pub(crate) end: Coordinate,
}

#[derive(Clone, Debug)]
pub(crate) struct GraphemeEntry {
    pub(crate) text: String,
    pub(crate) index: usize,
    pub(crate) start_utf16: usize,
    pub(crate) end_utf16: usize,
}

#[derive(Serialize)]
pub(crate) struct PairDetail {
    pub(crate) character: String,
    pub(crate) value: String,
    pub(crate) grapheme: usize,
    pub(crate) start: Coordinate,
    pub(crate) end: Coordinate,
}

#[derive(Serialize)]
pub(crate) struct GraphemeDetail {
    pub(crate) index: usize,
    pub(crate) text: String,
    pub(crate) start: Coordinate,
    pub(crate) end: Coordinate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Detail {
    pub(crate) limit: usize,
    pub(crate) code_points: Vec<PairDetail>,
    pub(crate) code_points_truncated: bool,
    pub(crate) graphemes: Vec<GraphemeDetail>,
    pub(crate) graphemes_truncated: bool,
}

#[derive(Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LineEndingCounts {
    pub(crate) crlf: usize,
    pub(crate) lf: usize,
    pub(crate) cr: usize,
    pub(crate) nel: usize,
    pub(crate) line_separator: usize,
    pub(crate) paragraph_separator: usize,
}

#[derive(Clone, Serialize)]
pub(crate) struct LineEndingItem {
    pub(crate) kind: &'static str,
    pub(crate) start: Coordinate,
    pub(crate) end: Coordinate,
}

#[derive(Clone, Serialize)]
pub(crate) struct LineEndings {
    pub(crate) counts: LineEndingCounts,
    pub(crate) total: usize,
    pub(crate) items: Vec<LineEndingItem>,
    pub(crate) truncated: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Counts {
    pub(crate) utf8_bytes: usize,
    pub(crate) utf16_code_units: usize,
    pub(crate) code_points: usize,
    pub(crate) graphemes: usize,
    pub(crate) lines: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Chunk {
    pub(crate) index: usize,
    pub(crate) text: String,
    pub(crate) utf8_bytes: usize,
    pub(crate) start: Coordinate,
    pub(crate) end: Coordinate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Chunking {
    pub(crate) max_chunk_utf8_bytes: usize,
    pub(crate) boundary: &'static str,
    pub(crate) chunks: Vec<Chunk>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IndexResult {
    pub(crate) status: &'static str,
    pub(crate) operation: &'static str,
    pub(crate) counts: Counts,
    pub(crate) detail: Detail,
    pub(crate) line_endings: LineEndings,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) chunking: Option<Chunking>,
}
