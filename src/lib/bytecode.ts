/**
 * SkillsGuard — Python bytecode inspection
 *
 * Compiled Python (.pyc / .pyo) is what the interpreter actually executes, yet
 * it cannot be reviewed like source. A skill can ship harmless-looking .py
 * decoys next to a hostile __pycache__/*.pyc; with PEP 552 "unchecked hash"
 * invalidation the interpreter loads the .pyc without ever comparing it to the
 * source, so what the scanner reads is not what runs.
 *
 * Bytecode is therefore never skipped silently:
 *   - every .pyc/.pyo yields a finding (SG-BYTECODE-001), even when oversized;
 *   - unchecked-hash bytecode is escalated to CRITICAL (SG-BYTECODE-002);
 *   - printable strings recovered from the file are returned to the caller so
 *     the normal rule set and the blob decoder still see embedded commands,
 *     URLs and encoded payloads.
 *
 * Only Uint8Array / TextDecoder are used so the module also runs in Workers.
 */

import type { Finding } from "../types.js";

export const BYTECODE_EXTENSIONS: ReadonlySet<string> = new Set([".pyc", ".pyo"]);

/** Largest bytecode file read into memory. Bigger files are still reported. */
export const MAX_BYTECODE_BYTES = 8 * 1024 * 1024;

// `strings`-style recovery bounds: keep rule scanning cheap on hostile input.
const MIN_STRING_LENGTH = 4;
const MAX_STRINGS = 5_000;
const MAX_STRING_CHARS = 512 * 1024;

// CPython magic numbers: 3.6 is 3379, 3.7 starts at 3390. From 3.7 on the header
// is 16 bytes: magic(2) + "\r\n" + flags(4) + mtime/size or source hash (8).
const FIRST_FLAGS_MAGIC = 3390;

export type PycMode =
  | "timestamp"
  | "unchecked-hash"
  | "checked-hash"
  | "legacy"
  | "unknown"
  | "invalid";

export interface PycHeader {
  readonly mode: PycMode;
  readonly magic?: number;
}

/** Classify a .pyc by its header (PEP 552 flags, mirroring CPython's importlib). */
export function parsePycHeader(bytes: Uint8Array): PycHeader {
  if (bytes.length < 8 || bytes[2] !== 0x0d || bytes[3] !== 0x0a) return { mode: "invalid" };
  const magic = bytes[0]! | (bytes[1]! << 8);
  if (magic < FIRST_FLAGS_MAGIC) return { mode: "legacy", magic };
  const flags = bytes[4]! | (bytes[5]! << 8) | (bytes[6]! << 16) | (bytes[7]! << 24);
  if (flags & ~0b11) return { mode: "unknown", magic }; // CPython rejects unknown flag bits
  if ((flags & 0b01) === 0) return { mode: "timestamp", magic };
  return (flags & 0b10) !== 0 ? { mode: "checked-hash", magic } : { mode: "unchecked-hash", magic };
}

/** Printable ASCII runs (like `strings -n 4`), bounded in count and total size. */
export function extractStrings(bytes: Uint8Array): readonly string[] {
  const decoder = new TextDecoder();
  const out: string[] = [];
  let chars = 0;
  let start = -1;
  for (let i = 0; i <= bytes.length; i++) {
    const c = i < bytes.length ? bytes[i]! : 0;
    if (c >= 0x20 && c <= 0x7e) {
      if (start < 0) start = i;
      continue;
    }
    if (start >= 0 && i - start >= MIN_STRING_LENGTH) {
      const end = Math.min(i, start + MAX_STRING_CHARS);
      out.push(decoder.decode(bytes.subarray(start, end)));
      chars += end - start;
      if (out.length >= MAX_STRINGS || chars >= MAX_STRING_CHARS) break;
    }
    start = -1;
  }
  return out;
}

export interface BytecodeInspection {
  readonly findings: readonly Finding[];
  /** Recovered strings, one per line, ready for the regular rule scan. */
  readonly text: string;
}

const MODE_LABEL: Record<PycMode, string> = {
  "timestamp": "timestamp-based",
  "unchecked-hash": "unchecked-hash (PEP 552)",
  "checked-hash": "checked-hash (PEP 552)",
  "legacy": "pre-3.7 format",
  "unknown": "unrecognised header flags",
  "invalid": "no valid .pyc header",
};

/**
 * Report on a bytecode file. `bytes` is null when the file was too large to
 * read; it is still reported, just without header classification or strings.
 */
export function inspectBytecode(
  bytes: Uint8Array | null,
  relPath: string,
  size: number,
): BytecodeInspection {
  const header = bytes ? parsePycHeader(bytes) : undefined;

  const evidence = header
    ? `${size} bytes, ${MODE_LABEL[header.mode]}${header.magic !== undefined ? `, magic ${header.magic}` : ""}`
    : `${size} bytes — over the ${MAX_BYTECODE_BYTES / (1024 * 1024)} MB inspection limit, contents not analyzed`;

  const findings: Finding[] = [{
    ruleId: "SG-BYTECODE-001",
    category: "obfuscation",
    severity: "HIGH",
    message:
      "Precompiled Python bytecode shipped in skill — the interpreter runs it, but it cannot be " +
      "reviewed as source and need not match the .py files next to it",
    file: relPath,
    line: 1,
    evidence,
    pattern: "",
    // bytes === null: over the read limit, so neither header nor strings were reviewed.
    ...(bytes === null ? { unanalyzed: true } : {}),
  }];

  if (header?.mode === "unchecked-hash") {
    findings.push({
      ruleId: "SG-BYTECODE-002",
      category: "obfuscation",
      severity: "CRITICAL",
      message:
        "Bytecode uses PEP 552 unchecked-hash invalidation — it is loaded without being compared " +
        "to its .py source, so reviewed source can differ from the code that runs",
      file: relPath,
      line: 1,
      evidence: `header flags 0b01 (UNCHECKED_HASH), magic ${header.magic}`,
      pattern: "",
    });
  }

  return { findings, text: bytes ? extractStrings(bytes).join("\n") : "" };
}
