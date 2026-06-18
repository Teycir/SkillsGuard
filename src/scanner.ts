/**
 * SkillsGuard — Scanner
 * Walks a target directory (or single file), reads each candidate file,
 * runs all rules against raw content AND decoded blobs, deduplicates,
 * and returns a ScanResult.
 */

import { readdir, readFile, stat, realpath } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import type { Finding, ScanResult } from "./types.js";
import { RULES } from "./rules.js";
import { findDecodedBlobs } from "./decode.js";
import { shouldIgnoreLine } from "./lib/ignore.js";
import { runConcurrent } from "./lib/concurrency.js";

// Files we care about: SKILL.md, any markdown, shell scripts, Python, JS/TS,
// yaml/toml configs, and text files. We skip binary and lock files.
const ALLOWED_EXTENSIONS = new Set<string>([
  ".md", ".txt", ".sh", ".bash", ".zsh", ".fish",
  ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
  ".json", ".yaml", ".yml", ".toml", ".env", ".conf", ".cfg",
  ".html", ".xml",
]);

const SKIP_DIRS = new Set<string>([
  "node_modules", ".git", ".trunk", "dist", "build",
  "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
  ".next", ".open-next", ".wrangler", "target", ".cargo",
  ".venv", "venv", "env", ".tox",
]);

const MAX_FILE_SIZE = 512 * 1024; // 512 KB — skip suspiciously large files

// ─── File discovery ──────────────────────────────────────────────────────────

async function collectFiles(target: string): Promise<readonly string[]> {
  const s = await stat(target);
  if (s.isFile()) return [target];

  const results: string[] = [];
  const queue: string[] = [target];
  const visited = new Set<string>();

  while (queue.length > 0) {
    const dir = queue.pop()!;
    let realDir: string;
    try {
      realDir = await realpath(dir);
    } catch {
      continue;
    }
    if (visited.has(realDir)) continue;
    visited.add(realDir);

    let entries: { name: string; isDirectory(): boolean; isFile(): boolean; isSymbolicLink(): boolean }[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);

      let isDir = entry.isDirectory();
      if (entry.isSymbolicLink()) {
        try {
          const symStat = await stat(full);
          isDir = symStat.isDirectory();
        } catch {
          continue;
        }
      }

      if (isDir) {
        if (!SKIP_DIRS.has(entry.name)) {
          queue.push(full);
        }
      } else {
        const ext = extname(entry.name).toLowerCase();
        if (entry.name === "SKILL.md" || ALLOWED_EXTENSIONS.has(ext)) {
          results.push(full);
        }
      }
    }
  }

  return results;
}

// ─── Scanning logic ─────────────────────────────────────────────────────────

function scanText(
  text: string,
  filePath: string,
  decodedFrom?: string,
): readonly Finding[] {
  const findings: Finding[] = [];
  const lines = text.split("\n");

  for (const rule of RULES) {
    const regex = rule.pattern.flags.includes("g")
      ? new RegExp(rule.pattern.source, rule.pattern.flags)
      : rule.pattern;

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (line !== undefined) {
        if (shouldIgnoreLine(line, rule.id)) {
          continue;
        }

        if (regex.test(line)) {
          findings.push({
            ruleId: rule.id,
            category: rule.category,
            severity: rule.severity,
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
  }

  return findings;
}

async function scanFile(filePath: string, rootDir: string): Promise<readonly Finding[]> {
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
  } catch {
    return [];
  }

  const findings: Finding[] = [];
  findings.push(...scanText(content, relPath));

  const blobs = findDecodedBlobs(content);
  for (const blob of blobs) {
    const blobFindings = scanText(blob.decoded, relPath, `${blob.encoding}:${blob.raw.slice(0, 40)}`);
    findings.push(...blobFindings);
  }

  return findings;
}

// ─── Deduplication ───────────────────────────────────────────────────────────

function dedup(findings: readonly Finding[]): readonly Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.ruleId}:${f.file}:${f.line}:${f.decodedFrom ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Public API ──────────────────────────────────────────────────────────────

export async function scan(target: string): Promise<ScanResult> {
  const start = Date.now();

  let rootDir: string;
  try {
    const s = await stat(target);
    rootDir = s.isDirectory() ? target : join(target, "..");
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Cannot access target '${target}': ${msg}`);
  }

  const files = await collectFiles(target);
  const scanResults = await runConcurrent(files, 16, (file) => scanFile(file, rootDir));
  
  const allFindings: Finding[] = [];
  for (const findings of scanResults) {
    allFindings.push(...findings);
  }

  return {
    target,
    filesScanned: files.length,
    findings: [...dedup(allFindings)],
    durationMs: Date.now() - start,
  };
}
