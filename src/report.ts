/**
 * SkillsGuard — Reporter
 * Two output modes:
 *   human  — colored, grouped by severity, readable in terminal
 *   json   — machine-parseable, one JSON object to stdout
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
    console.log(use(`${C.green}${C.bold}✓ No issues found.${C.reset}\n`));
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
}

export function reportJson(result: ScanResult): void {
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}
