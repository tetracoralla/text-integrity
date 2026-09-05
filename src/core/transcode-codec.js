function replacement(start, end) {
  return { text: "\ufffd", kind: "replacement", sourceStart: start, sourceEnd: end };
}

function scalar(text, start, end) {
  return { text, kind: "scalar", sourceStart: start, sourceEnd: end };
}

function isContinuation(value) {
  return value >= 0x80 && value <= 0xbf;
}

function utf8Segments(bytes) {
  const segments = [];
  for (let index = 0; index < bytes.length;) {
    const first = bytes[index];
    if (first <= 0x7f) {
      segments.push(scalar(String.fromCodePoint(first), index, index + 1));
      index += 1;
      continue;
    }

    let length;
    let minimumSecond = 0x80;
    let maximumSecond = 0xbf;
    if (first >= 0xc2 && first <= 0xdf) length = 2;
    else if (first >= 0xe0 && first <= 0xef) {
      length = 3;
      if (first === 0xe0) minimumSecond = 0xa0;
      if (first === 0xed) maximumSecond = 0x9f;
    } else if (first >= 0xf0 && first <= 0xf4) {
      length = 4;
      if (first === 0xf0) minimumSecond = 0x90;
      if (first === 0xf4) maximumSecond = 0x8f;
    } else {
      segments.push(replacement(index, index + 1));
      index += 1;
      continue;
    }

    const second = bytes[index + 1];
    if (second === undefined) {
      segments.push(replacement(index, bytes.length));
      break;
    }
    if (second < minimumSecond || second > maximumSecond) {
      segments.push(replacement(index, index + 1));
      index += 1;
      continue;
    }

    let end = index + 2;
    while (end < index + length && end < bytes.length && isContinuation(bytes[end])) end += 1;
    if (end < index + length) {
      segments.push(replacement(index, end));
      index = end;
      continue;
    }

    let codePoint;
    if (length === 2) codePoint = ((first & 0x1f) << 6) | (second & 0x3f);
    else if (length === 3) codePoint = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (bytes[index + 2] & 0x3f);
    else codePoint = ((first & 0x07) << 18) | ((second & 0x3f) << 12)
      | ((bytes[index + 2] & 0x3f) << 6) | (bytes[index + 3] & 0x3f);
    segments.push(scalar(String.fromCodePoint(codePoint), index, index + length));
    index += length;
  }
  return segments;
}

function utf16leSegments(bytes) {
  const segments = [];
  let index = 0;
  while (index + 1 < bytes.length) {
    const unit = bytes[index] | (bytes[index + 1] << 8);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 3 < bytes.length) {
        const next = bytes[index + 2] | (bytes[index + 3] << 8);
        if (next >= 0xdc00 && next <= 0xdfff) {
          const codePoint = 0x10000 + ((unit - 0xd800) << 10) + (next - 0xdc00);
          segments.push(scalar(String.fromCodePoint(codePoint), index, index + 4));
          index += 4;
          continue;
        }
      } else if (index + 2 < bytes.length) {
        segments.push(replacement(index, bytes.length));
        index = bytes.length;
        break;
      }
      segments.push(replacement(index, index + 2));
      index += 2;
      continue;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      segments.push(replacement(index, index + 2));
      index += 2;
      continue;
    }
    segments.push(scalar(String.fromCodePoint(unit), index, index + 2));
    index += 2;
  }
  if (index < bytes.length) segments.push(replacement(index, bytes.length));
  return segments;
}

export function decodeTextSegments(text) {
  const segments = [];
  for (let index = 0; index < text.length;) {
    const first = text.charCodeAt(index);
    if (first >= 0xd800 && first <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        segments.push(scalar(text.slice(index, index + 2), index, index + 2));
        index += 2;
      } else {
        segments.push(replacement(index, index + 1));
        index += 1;
      }
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      segments.push(replacement(index, index + 1));
      index += 1;
    } else {
      segments.push(scalar(text[index], index, index + 1));
      index += 1;
    }
  }
  return segments;
}

export function decodeByteSegments(bytes, encoding) {
  return encoding === "utf-8" ? utf8Segments(bytes) : utf16leSegments(bytes);
}

export function decodedText(segments) {
  return segments.map((segment) => segment.text).join("");
}
