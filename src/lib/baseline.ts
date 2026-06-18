/**
 * SkillsGuard — Baseline management
 *
 * A baseline is a snapshot of findings from a previous scan, stored as JSON.
 * It lets teams adopt SkillsGuard incrementally: save current findings as
 * the baseline, then gate CI only on NEW findings introduced after that point.
 *
 * Workflow:
 *   skillsguard ./skill --save-baseline          # snapshot current state
 *   skillsguard ./skill --diff-baseline          # only show new findings
 *   skillsguard ./skill --update-baseline        # merge new findings in
 *
 * File format: .skillsguard/baseline.json (git-trackable)
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname } from "node:path";
import type { Finding } from "../types.js";

const BASELINE_DIR  = ".skillsguard";
const BASELINE_FILE = "baseline.json";

export interface BaselineEntry {
  ruleId:   string;
  file:     string;
  line:     number;
  evidence: string;
}

export interface BaselineDiff {
  /** Findings present in current scan but NOT in the baseline — genuinely new. */
  newFindings: Finding[];
  /** Findings present in baseline but NOT in current scan — resolved. */
  resolvedEntries: BaselineEntry[];
  /** Findings present in both — unchanged. */
  unchangedCount: number;
}

// ─── Stable fingerprint ───────────────────────────────────────────────────────

/**
 * Fingerprint a finding for stable baseline comparison.
 * We intentionally exclude `severity` and `message` so that rule-text changes
 * don't force re-triaging of previously baselined findings.
 * We use `evidence` (truncated line text) so that the same rule firing on a
 * different line with the same content is still considered the same finding.
 */
function fingerprint(f: Finding | BaselineEntry): string {
  return `${f.ruleId}::${f.file}::${f.evidence.trim().slice(0, 120)}`;
}

// ─── IO helpers ──────────────────────────────────────────────────────────────

function baselinePath(root: string): string {
  return join(root, BASELINE_DIR, BASELINE_FILE);
}

export async function loadBaseline(root: string): Promise<BaselineEntry[]> {
  const path = baselinePath(root);
  let text: string;
  try {
    text = await readFile(path, "utf-8");
  } catch (err: unknown) {
    if (err instanceof Error && "code" in err && err.code === "ENOENT") {
      return [];
    }
    throw new Error(`Cannot read baseline at ${path}: ${String(err)}`);
  }
  try {
    const parsed = JSON.parse(text) as unknown;
    if (!Array.isArray(parsed)) throw new Error("Baseline JSON must be an array");
    return parsed as BaselineEntry[];
  } catch (err) {
    throw new Error(`Corrupt baseline at ${path}: ${String(err)}`);
  }
}

export async function saveBaseline(root: string, findings: Finding[]): Promise<string> {
  const entries: BaselineEntry[] = findings.map((f) => ({
    ruleId:   f.ruleId,
    file:     f.file,
    line:     f.line,
    evidence: f.evidence,
  }));
  const path = baselinePath(root);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(entries, null, 2) + "\n", "utf-8");
  return path;
}

export async function updateBaseline(root: string, currentFindings: Finding[]): Promise<string> {
  const existing  = await loadBaseline(root);
  const existingFP = new Set(existing.map(fingerprint));

  // Add entries for findings that aren't already in the baseline
  const newEntries: BaselineEntry[] = currentFindings
    .filter((f) => !existingFP.has(fingerprint(f)))
    .map((f) => ({
      ruleId:   f.ruleId,
      file:     f.file,
      line:     f.line,
      evidence: f.evidence,
    }));

  const merged = [...existing, ...newEntries];
  const path   = baselinePath(root);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, JSON.stringify(merged, null, 2) + "\n", "utf-8");
  return path;
}

// ─── Diff ─────────────────────────────────────────────────────────────────────

export function diffBaseline(baseline: BaselineEntry[], currentFindings: Finding[]): BaselineDiff {
  const baselineFP   = new Set(baseline.map(fingerprint));
  const currentFP    = new Set(currentFindings.map(fingerprint));

  const newFindings      = currentFindings.filter((f) => !baselineFP.has(fingerprint(f)));
  const resolvedEntries  = baseline.filter((e)    => !currentFP.has(fingerprint(e)));
  const unchangedCount   = currentFindings.length - newFindings.length;

  return { newFindings, resolvedEntries, unchangedCount };
}
