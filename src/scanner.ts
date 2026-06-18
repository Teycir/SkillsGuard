/**
 * SkillsGuard — Scanner
 * Walks a target directory (or single file), reads each candidate file,
 * runs all rules against raw content AND decoded blobs, deduplicates,
 * and returns a ScanResult.
 */

import { readdir, readFile, stat, realpath } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import type { Finding, ScanResult, ScanOptions, CustomRule, Rule, RiskScore } from "./types.js";
import { RULES } from "./rules.js";
import { findDecodedBlobs } from "./decode.js";
import { shouldIgnoreLine, isCommentLine, isPlaceholderLine, isTestFilePath } from "./lib/ignore.js";
import { runConcurrent } from "./lib/concurrency.js";

// Files we care about: SKILL.md, any markdown, shell scripts, Python, JS/TS,
// yaml/toml configs, and text files. We skip binary and lock files.
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

const SKIP_DIRS = new Set<string>([
  "node_modules", ".git", ".trunk", "dist", "build",
  "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
  ".next", ".open-next", ".wrangler", "target", ".cargo",
  ".venv", "venv", "env", ".tox",
  ".skillsguard", // baseline + config artifacts — never scan our own output
]);

const MAX_FILE_SIZE = 512 * 1024; // 512 KB — skip suspiciously large files

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
        category: "scanner",
        severity: "HIGH",
        message: `Failed to resolve directory path: ${msg}`,
        file: relative(rootDir, dir) || ".",
        line: 1,
        evidence: "Path resolution error",
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
        category: "scanner",
        severity: "HIGH",
        message: `Failed to read directory entries: ${msg}`,
        file: relative(rootDir, dir) || ".",
        line: 1,
        evidence: "Directory read error",
      });
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);

      let isDir = entry.isDirectory();
      if (entry.isSymbolicLink()) {
        try {
          const symStat = await stat(full);
          isDir = symStat.isDirectory();
        } catch (err: unknown) {
          if (err instanceof Error && "code" in err && err.code === "ENOENT") {
            continue;
          }
          const msg = err instanceof Error ? err.message : String(err);
          errors.push({
            ruleId: "SG-READ-ERR",
            category: "scanner",
            severity: "HIGH",
            message: `Failed to stat symbolic link target: ${msg}`,
            file: relative(rootDir, full),
            line: 1,
            evidence: "Symbolic link stat error",
          });
          continue;
        }
      }

      if (isDir) {
        if (!SKIP_DIRS.has(entry.name) && !excludeSet.has(entry.name)) {
          queue.push(full);
        }
      } else {
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
          ALLOWED_EXTENSIONS.has(ext)
        ) {
          files.push(full);
        }
      }
    }
  }

  return { files, errors };
}

// ─── Scanning logic ─────────────────────────────────────────────────────────

export function scanText(
  text: string,
  filePath: string,
  decodedFrom?: string,
  options?: ScanOptions,
): readonly Finding[] {
  const findings: Finding[] = [];
  const lines = text.split("\n");
  const rules = resolveRules(options);
  const inTestFile = isTestFilePath(filePath);

  for (const rule of rules) {
    const regex = rule.pattern.flags.includes("g")
      ? new RegExp(rule.pattern.source, rule.pattern.flags)
      : rule.pattern;

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

      // 3. Placeholder / stopword filter — skip when the rule opts in.
      //    Only applies to raw scan, not decoded blobs (encoded payloads with
      //    "example" in them are still suspicious).
      if (rule.skipPlaceholderLines && !decodedFrom && isPlaceholderLine(line)) continue;

      if (regex.test(line)) {
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
          decodedFrom,
        });
        if (regex.flags.includes("g")) {
          regex.lastIndex = 0;
        }
      }
    }
  }

  return findings;
}

async function scanFile(filePath: string, rootDir: string, options?: ScanOptions): Promise<readonly Finding[]> {
  const relPath = relative(rootDir, filePath);
  let content: string;
  try {
    const s = await stat(filePath);
    if (s.size > MAX_FILE_SIZE) {
      return [{
        ruleId: "SG-SKIP-001",
        category: "scanner",
        severity: "INFO",
        message: `File skipped — exceeds 512 KB size limit (${(s.size / 1024).toFixed(1)} KB)`,
        file: relPath,
        line: 1,
        evidence: `File size: ${s.size} bytes`,
      }];
    }
    content = await readFile(filePath, "utf-8");
  } catch (err: unknown) {
    if (err instanceof Error && "code" in err && err.code === "ENOENT") {
      return [];
    }
    const errMsg = err instanceof Error ? err.message : String(err);
    return [{
      ruleId: "SG-READ-ERR",
      category: "scanner",
      severity: "HIGH",
      message: `Failed to read file: ${errMsg}`,
      file: relPath,
      line: 1,
      evidence: `Read error`,
    }];
  }

  const findings: Finding[] = [];
  findings.push(...scanText(content, relPath, undefined, options));

  const blobs = findDecodedBlobs(content);
  for (const blob of blobs) {
    const blobFindings = scanText(blob.decoded, relPath, `${blob.encoding}:${blob.raw.slice(0, 40)}`, options);
    findings.push(...blobFindings);
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

export function computeRiskScore(findings: readonly Finding[]): RiskScore {
  // Bucket findings by severity, cap each bucket at 4 to prevent a flood of
  // identical findings from dominating the score.
  const buckets: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) buckets[f.severity] = (buckets[f.severity] ?? 0) + 1;

  let raw = 0;
  for (const [sev, count] of Object.entries(buckets)) {
    raw += Math.min(count, 4) * (RISK_WEIGHTS[sev] ?? 0);
  }
  const score = Math.min(100, raw);

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
      allFindings.push(...findings);
    }
  } else {
    const scanResults = await runConcurrent(files, 16, (file) => scanFile(file, rootDir, options));
    for (const findings of scanResults) {
      allFindings.push(...findings);
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
