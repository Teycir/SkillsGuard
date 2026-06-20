/**
 * SkillsGuard — Git diff scanner
 *
 * Scans only files that are staged (--staged) or changed since a base ref
 * (e.g. "main", "HEAD~1"), so CI can report findings only on changed files
 * rather than the whole repo.
 *
 * Note: Each changed file is scanned in full; line-level filtering is not
 * currently implemented.
 *
 * Usage (programmatic):
 *   const result = await scanGitDiff({ base: "main", staged: false });
 *
 * Usage (CLI):
 *   skillsguard --diff              # staged files only (pre-commit hook)
 *   skillsguard --diff main         # files changed vs main branch
 *   skillsguard --diff HEAD~1       # files changed in last commit
 */

import { readFile, stat } from "node:fs/promises";
import { join, dirname } from "node:path";
import { spawn } from "node:child_process";
import { scan } from "./scanner.js";
import type { ScanResult, ScanOptions, Finding } from "./types.js";
import { computeRiskScore } from "./scanner.js";

// ─── Git helpers ──────────────────────────────────────────────────────────────

function runGit(args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = spawn("git", args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    proc.stdout.on("data", (d: Buffer) => (stdout += d.toString()));
    proc.stderr.on("data", (d: Buffer) => (stderr += d.toString()));
    proc.on("close", (code) => {
      if (code !== 0) reject(new Error(`git ${args[0]} failed: ${stderr.trim()}`));
      else resolve(stdout);
    });
    proc.on("error", (err) => reject(new Error(`Failed to spawn git: ${err.message}`)));
  });
}

async function findGitRoot(startDir: string): Promise<string> {
  let dir = startDir;
  while (true) {
    try {
      await stat(join(dir, ".git"));
      return dir;
    } catch (err: unknown) {
      if (err instanceof Error && "code" in err && err.code !== "ENOENT") {
        throw err;
      }
      const parent = dirname(dir);
      if (parent === dir) throw new Error("Not a git repository (could not find .git)");
      dir = parent;
    }
  }
}

/**
 * Return the list of files changed relative to `base`, or staged files if
 * `staged` is true. Paths are absolute.
 */
async function getChangedFiles(opts: { base?: string; staged: boolean; cwd: string }): Promise<string[]> {
  const { base, staged, cwd } = opts;
  let args: string[];

  if (staged) {
    args = ["diff", "--cached", "--name-only", "--diff-filter=ACMR"];
  } else if (base) {
    args = ["diff", base, "--name-only", "--diff-filter=ACMR"];
  } else {
    args = ["diff", "HEAD", "--name-only", "--diff-filter=ACMR"];
  }

  const raw = await runGit(args, cwd);
  return raw
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((rel) => join(cwd, rel));
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface GitDiffOptions extends ScanOptions {
  /** Ref to compare against, e.g. "main", "HEAD~1". Defaults to HEAD. */
  base?: string;
  /** When true, scan only staged (index) changes — useful for pre-commit hooks. */
  staged?: boolean;
  /** Working directory / git root to resolve relative paths from. Defaults to process.cwd(). */
  cwd?: string;
}

export async function scanGitDiff(opts: GitDiffOptions = {}): Promise<ScanResult & { changedFiles: string[] }> {
  const start = Date.now();
  const cwd = opts.cwd ?? process.cwd();
  const gitRoot = await findGitRoot(cwd);

  const changedFiles = await getChangedFiles({
    base: opts.base,
    staged: opts.staged ?? false,
    cwd: gitRoot,
  });

  if (changedFiles.length === 0) {
    return {
      target: gitRoot,
      filesScanned: 0,
      findings: [],
      durationMs: Date.now() - start,
      riskScore: computeRiskScore([]),
      changedFiles: [],
    };
  }

  // Scan each file individually, then merge results
  const allFindings: Finding[] = [];
  let scannedCount = 0;
  for (const file of changedFiles) {
    try {
      const sub = await scan(file, opts);
      allFindings.push(...sub.findings);
      scannedCount += sub.filesScanned;
    } catch (err: unknown) {
      if (err instanceof Error && "code" in err && err.code === "ENOENT") {
        // File was deleted/renamed since diff — skip silently
        continue;
      }
      throw err;
    }
  }

  return {
    target: gitRoot,
    filesScanned: scannedCount,
    findings: allFindings,
    durationMs: Date.now() - start,
    riskScore: computeRiskScore(allFindings),
    changedFiles,
  };
}
