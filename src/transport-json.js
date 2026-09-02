const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

export function parseUtf8Json(bytes) {
  return JSON.parse(UTF8_DECODER.decode(bytes));
}
