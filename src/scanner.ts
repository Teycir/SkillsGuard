/**
 * SkillsGuard — Scanner
 * Walks a target directory (or single file), reads each candidate file,
 * runs all rules against raw content AND decoded blobs, deduplicates,
 * and returns a ScanResult.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, extname } from "node:path";
import type { Finding, ScanResult } from "./types.js";
import { RULES } from "./rules.js";
import { findDecodedBlobs } from "./decode.js";

// Files we care about: SKILL.md, any markdown, shell scripts, Python, JS/TS,
// yaml/toml configs, and text files. We skip binary and lock files.
const ALLOWED_EXTENSIONS = new Set([
  ".md", ".txt", ".sh", ".bash", ".zsh", ".fish",
  ".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts",
  ".json", ".yaml", ".yml", ".toml", ".env", ".conf", ".cfg",
  ".html", ".xml",
]);

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".trunk", "dist", "build",
  "__pycache__", ".mypy_cache", ".pytest_cache", "coverage",
  ".next", ".open-next", ".wrangler", "target", ".cargo",
]);

const MAX_FILE_SIZE = 512 * 1024; // 512 KB — skip suspiciously large files

// ─── File discovery ──────────────────────────────────────────────────────────

async function collectFiles(target: string): Promise<string[]> {
  const s = await stat(target);
  if (s.isFile()) return [target];

  const results: string[] = [];
  const queue: string[] = [target];

  while (queue.length > 0) {
    const dir = queue.pop()!;
    let entries: { name: string; isDirectory(): boolean; isFile(): boolean }[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) queue.push(full);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        // Always include SKILL.md regardless of naming; also include by extension
        if (entry.name === "SKILL.md" || ALLOWED_EXTENSIONS.has(ext)) {
          results.push(full);
        }
      }
    }
  }

  return results;
}

// ─── Line indexer ────────────────────────────────────────────────────────────

function indexToLine(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

function getLineContent(content: string, lineNum: number): string {
  const lines = content.split("\n");
  return (lines[lineNum - 1] ?? "").trim().slice(0, 200);
}

// ─── Single file scan ────────────────────────────────────────────────────────

function scanText(
  text: string,
  filePath: string,
  decodedFrom?: string,
): Finding[] {
  const findings: Finding[] = [];
  const lines = text.split("\n");

  for (const rule of RULES) {
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (rule.pattern.test(line)) {
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
        // Reset stateful regex after match
        rule.pattern.lastIndex = 0;
      }
    }
  }

  return findings;
}

async function scanFile(filePath: string, rootDir: string): Promise<Finding[]> {
  let content: string;
  try {
    const s = await stat(filePath);
    if (s.size > MAX_FILE_SIZE) return [];
    content = await readFile(filePath, "utf-8");
  } catch {
    return [];
  }

  const relPath = relative(rootDir, filePath);
  const findings: Finding[] = [];

  // 1. Scan raw content
  findings.push(...scanText(content, relPath));

  // 2. Scan decoded blobs (catches obfuscated payloads)
  const blobs = findDecodedBlobs(content);
  for (const blob of blobs) {
    const blobFindings = scanText(blob.decoded, relPath, `${blob.encoding}:${blob.raw.slice(0, 40)}`);
    findings.push(...blobFindings);
  }

  return findings;
}

// ─── Deduplication ───────────────────────────────────────────────────────────

function dedup(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  return findings.filter((f) => {
    const key = `${f.ruleId}:${f.file}:${f.line}`;
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
  const allFindings: Finding[] = [];

  for (const file of files) {
    const findings = await scanFile(file, rootDir);
    allFindings.push(...findings);
  }

  return {
    target,
    filesScanned: files.length,
    findings: dedup(allFindings),
    durationMs: Date.now() - start,
  };
}
