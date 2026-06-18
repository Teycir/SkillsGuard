/**
 * SkillsGuard — Reporter
 * Output modes:
 *   human  — colored, grouped by severity, readable in terminal
 *   json   — machine-parseable, one JSON object to stdout
 *   quiet  — no output; only exit code matters (for scripts)
 *   stats  — brief category/severity breakdown, no individual findings
 */

import type { ScanResult, Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";

// ANSI color codes (no external dep)
const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  bgRed: "\x1b[41m",
  bgYellow: "\x1b[43m",
  green: "\x1b[32m",
  magenta: "\x1b[35m",
} as const;

function colorForSeverity(s: Severity): string {
  switch (s) {
    case "CRITICAL": return `${C.bold}${C.bgRed}${C.white}`;
    case "HIGH":     return `${C.bold}${C.red}`;
    case "MEDIUM":   return `${C.bold}${C.yellow}`;
    case "LOW":      return `${C.bold}${C.cyan}`;
    case "INFO":     return C.dim;
  }
}

function badge(s: Severity): string {
  return `${colorForSeverity(s)} ${s.padEnd(8)} ${C.reset}`;
}

export function reportHuman(result: ScanResult, noColor: boolean): void {
  const use = noColor
    ? (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "")
    : (s: string) => s;

  const { target, filesScanned, findings, durationMs } = result;

  console.log(use(`\n${C.bold}SkillsGuard${C.reset} scanning ${C.cyan}${target}${C.reset}`));
  console.log(use(`${C.dim}${filesScanned} file(s) · ${durationMs}ms${C.reset}\n`));

  if (findings.length === 0) {
    console.log(use(`${C.green}${C.bold}✓ No issues found.${C.reset}`));
    console.log(use(`${C.dim}Risk score: 0/100 NONE  [░░░░░░░░░░░░░░░░░░░░]${C.reset}\n`));
    return;
  }

  // Sort: highest severity first, then by file, then by line
  const sorted = [...findings].sort((a, b) => {
    const sd = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sd !== 0) return sd;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });

  for (const f of sorted) {
    console.log(
      use(
        `${badge(f.severity)} ${C.bold}[${f.ruleId}]${C.reset} ${f.message}`,
      ),
    );
    console.log(
      use(
        `  ${C.dim}${f.file}:${f.line}${C.reset}`,
      ),
    );
    if (f.evidence) {
      console.log(use(`  ${C.dim}▶ ${f.evidence}${C.reset}`));
    }
    if (f.decodedFrom) {
      console.log(use(`  ${C.magenta}⚡ decoded from: ${f.decodedFrom}${C.reset}`));
    }
    console.log();
  }

  // Summary counts per severity
  const counts: Partial<Record<Severity, number>> = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] ?? 0) + 1;

  const parts: string[] = [];
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]) {
    if (counts[sev]) {
      parts.push(use(`${colorForSeverity(sev)}${counts[sev]} ${sev}${C.reset}`));
    }
  }

  console.log(use(`${C.bold}Summary:${C.reset} ${findings.length} finding(s) — ${parts.join(", ")}\n`));

  // Risk score gauge
  const { score, label } = result.riskScore;
  const riskColor = label === "CRITICAL" ? `${C.bold}${C.bgRed}${C.white}`
    : label === "HIGH"     ? `${C.bold}${C.red}`
    : label === "MEDIUM"   ? `${C.bold}${C.yellow}`
    : label === "LOW"      ? `${C.bold}${C.cyan}`
    : C.dim;
  const filled = Math.round(score / 5);  // 0-20 blocks
  const bar = "█".repeat(filled) + "░".repeat(20 - filled);
  console.log(use(`${C.bold}Risk score:${C.reset} ${riskColor}${score}/100 ${label}${C.reset}  ${C.dim}[${bar}]${C.reset}\n`));
}

export function reportJson(result: ScanResult): void {
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}

// ─── Stats mode ───────────────────────────────────────────────────────────────

export function reportStats(result: ScanResult, noColor: boolean): void {
  const use = noColor
    ? (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "")
    : (s: string) => s;

  const { findings, filesScanned, durationMs } = result;
  process.stdout.write(use(`\n${C.bold}SkillsGuard stats${C.reset}  ${C.dim}${filesScanned} file(s) · ${durationMs}ms${C.reset}\n\n`));

  if (findings.length === 0) {
    process.stdout.write(use(`${C.green}${C.bold}✓ No findings.${C.reset}\n\n`));
    return;
  }

  // By severity
  const bySev: Partial<Record<Severity, number>> = {};
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] ?? 0) + 1;

  process.stdout.write(use(`${C.bold}By severity:${C.reset}\n`));
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]) {
    if (bySev[sev]) {
      const col = sev === "CRITICAL" ? `${C.bold}${C.bgRed}${C.white}`
        : sev === "HIGH"   ? `${C.bold}${C.red}`
        : sev === "MEDIUM" ? `${C.bold}${C.yellow}`
        : sev === "LOW"    ? `${C.bold}${C.cyan}`
        : C.dim;
      process.stdout.write(use(`  ${col}${sev.padEnd(8)}${C.reset}  ${bySev[sev]}\n`));
    }
  }

  // By category
  const byCat: Record<string, number> = {};
  for (const f of findings) byCat[f.category] = (byCat[f.category] ?? 0) + 1;
  const catsSorted = Object.entries(byCat).sort((a, b) => b[1] - a[1]);

  process.stdout.write(use(`\n${C.bold}By category:${C.reset}\n`));
  for (const [cat, n] of catsSorted) {
    process.stdout.write(use(`  ${C.dim}${cat.padEnd(24)}${C.reset}  ${n}\n`));
  }

  // Risk score
  const { score, label } = result.riskScore;
  const riskColor = label === "CRITICAL" ? `${C.bold}${C.bgRed}${C.white}`
    : label === "HIGH"   ? `${C.bold}${C.red}`
    : label === "MEDIUM" ? `${C.bold}${C.yellow}`
    : label === "LOW"    ? `${C.bold}${C.cyan}`
    : C.dim;
  const filled = Math.round(score / 5);
  const bar = "█".repeat(filled) + "░".repeat(20 - filled);
  process.stdout.write(use(`\n${C.bold}Risk score:${C.reset} ${riskColor}${score}/100 ${label}${C.reset}  ${C.dim}[${bar}]${C.reset}\n\n`));
}

// ─── Baseline diff reporter ───────────────────────────────────────────────────

import type { BaselineDiff } from "./lib/baseline.js";

export function reportBaselineDiff(diff: BaselineDiff, noColor: boolean): void {
  const use = noColor
    ? (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "")
    : (s: string) => s;

  if (diff.newFindings.length === 0 && diff.resolvedEntries.length === 0) {
    process.stdout.write(use(`${C.green}${C.bold}✓ No new findings vs baseline. ${diff.unchangedCount} existing.${C.reset}\n\n`));
    return;
  }

  if (diff.resolvedEntries.length > 0) {
    process.stdout.write(use(`${C.green}${C.bold}✓ ${diff.resolvedEntries.length} finding(s) resolved:${C.reset}\n`));
    for (const e of diff.resolvedEntries) {
      process.stdout.write(use(`  ${C.dim}• ${e.ruleId}  ${e.file}:${e.line}${C.reset}\n`));
    }
    process.stdout.write("\n");
  }

  if (diff.newFindings.length > 0) {
    process.stdout.write(use(`${C.bold}${C.red}✗ ${diff.newFindings.length} NEW finding(s):${C.reset}\n\n`));
    const sorted = [...diff.newFindings].sort((a, b) => {
      const sd = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
      return sd !== 0 ? sd : a.file.localeCompare(b.file) || a.line - b.line;
    });
    for (const f of sorted) {
      process.stdout.write(use(`${badge(f.severity)} ${C.bold}[${f.ruleId}]${C.reset} ${f.message}\n`));
      process.stdout.write(use(`  ${C.dim}${f.file}:${f.line}${C.reset}\n`));
      if (f.evidence) process.stdout.write(use(`  ${C.dim}▶ ${f.evidence}${C.reset}\n`));
      process.stdout.write("\n");
    }
  }
}
