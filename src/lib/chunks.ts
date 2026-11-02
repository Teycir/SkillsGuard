/**
 * SkillsGuard — chunking for files above the single-pass size limit
 *
 * Rules run per line plus a sliding multi-line window, so a large file can be
 * scanned piece by piece as long as no window is cut in half. Chunks therefore
 * overlap by (window - 1) lines, always hold at least a full window, and
 * over-long lines are split into overlapping pieces. Each chunk records the
 * original line number of every line it contains so findings map back.
 */

/** Lines the scanner merges for multi-line patterns (see scanText). */
export const MULTILINE_WINDOW = 5;

/** Target size of one chunk, in characters. */
export const CHUNK_CHARS = 256 * 1024;

// A single line longer than this is cut into overlapping pieces so no regex
// ever runs over megabytes of unbroken text. The overlap keeps a payload that
// straddles a cut visible in at least one piece.
const PIECE_OVERLAP_CHARS = 4 * 1024;
export const PIECE_CHARS = 64 * 1024;

/**
 * Most lines a file above the single-pass size limit may have and still be scanned.
 * The rules run once per line, so scan time grows with the line count, not the byte
 * count: before the size limit was raised, the worst file the scanner would read was
 * 512 KB of newlines (524,288 lines, about 17 s). The same count caps the cost now, so
 * an 8 MB file of blank lines cannot take 16 times as long. A file over it is reported
 * as not analyzed (SG-SKIP-001), never passed as clean.
 */
export const MAX_SCAN_LINES = 512 * 1024;

/** Number of lines in `bytes` (a final line without a newline counts). */
export function countLines(bytes: Uint8Array): number {
  let lines = 1;
  let from = 0;
  const buffer = Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let at = buffer.indexOf(0x0a, from); at !== -1; at = buffer.indexOf(0x0a, from)) {
    lines++;
    from = at + 1;
  }
  return lines;
}

export interface TextChunk {
  readonly text: string;
  /** 1-based original line number of each line in `text`. */
  readonly lineNumbers: readonly number[];
}

export function splitIntoChunks(text: string, chunkChars = CHUNK_CHARS): readonly TextChunk[] {
  // 1. Segments: whole lines, or overlapping pieces of an over-long line.
  const segments: string[] = [];
  const segmentLine: number[] = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    if (line.length <= PIECE_CHARS) {
      segments.push(line);
      segmentLine.push(i + 1);
      continue;
    }
    for (let p = 0; ; p += PIECE_CHARS - PIECE_OVERLAP_CHARS) {
      segments.push(line.slice(p, p + PIECE_CHARS));
      segmentLine.push(i + 1);
      if (p + PIECE_CHARS >= line.length) break;
    }
  }

  // 2. Chunks of ~chunkChars (never fewer than one full window of segments),
  //    each starting (window - 1) segments before the previous one ended.
  const chunks: TextChunk[] = [];
  let start = 0;
  while (start < segments.length) {
    let end = start;
    let chars = 0;
    while (
      end < segments.length &&
      (end - start < MULTILINE_WINDOW || chars + segments[end]!.length + 1 <= chunkChars)
    ) {
      chars += segments[end]!.length + 1;
      end++;
    }
    chunks.push({
      text: segments.slice(start, end).join("\n"),
      lineNumbers: segmentLine.slice(start, end),
    });
    if (end >= segments.length) break;
    start = Math.max(start + 1, end - (MULTILINE_WINDOW - 1));
  }
  return chunks;
}
