/**
 * SkillsGuard — Rule explorer
 *
 * Subcommand: `skillsguard rules [ID] [--category CAT] [--severity SEV]`
 *
 * Lists all built-in rules with their ID, severity, category, pattern source,
 * message, and (when available) remediation guidance.
 */

import type { Rule, Severity } from "./types.js";
import { RULES } from "./rules.js";

// ─── ANSI (self-contained) ────────────────────────────────────────────────────
const C = {
  reset:   "\x1b[0m",
  bold:    "\x1b[1m",
  dim:     "\x1b[2m",
  red:     "\x1b[31m",
  yellow:  "\x1b[33m",
  green:   "\x1b[32m",
  cyan:    "\x1b[36m",
  magenta: "\x1b[35m",
  white:   "\x1b[37m",
  bgRed:   "\x1b[41m",
} as const;

function strip(s: string): string { return s.replace(/\x1b\[[0-9;]*m/g, ""); }

function colorForSev(s: Severity, noColor: boolean): string {
  if (noColor) return "";
  switch (s) {
    case "CRITICAL": return `${C.bold}${C.bgRed}${C.white}`;
    case "HIGH":     return `${C.bold}${C.red}`;
    case "MEDIUM":   return `${C.bold}${C.yellow}`;
    case "LOW":      return `${C.bold}${C.cyan}`;
    case "INFO":     return C.dim;
  }
}

// ─── Formatting ───────────────────────────────────────────────────────────────

function printRule(rule: Rule, noColor: boolean): void {
  const use = noColor ? strip : (s: string) => s;
  const sevColor = colorForSev(rule.severity, noColor);

  process.stdout.write("\n");
  process.stdout.write(
    use(`${C.bold}${rule.id}${C.reset}  ${sevColor}${rule.severity}${C.reset}  ${C.dim}[${rule.category}]${C.reset}\n`),
  );
  process.stdout.write(use(`${C.dim}─────────────────────────────────────────${C.reset}\n`));
  process.stdout.write(use(`${C.bold}Message:${C.reset}  ${rule.message}\n`));
  process.stdout.write(use(`${C.bold}Pattern:${C.reset}  ${C.cyan}${rule.pattern.toString()}${C.reset}\n`));

  if (rule.remediation) {
    process.stdout.write(use(`${C.bold}Fix:${C.reset}      ${rule.remediation}\n`));
  }
  const flags: string[] = [];
  if (rule.skipCommentLines)    flags.push("skipCommentLines");
  if (rule.skipPlaceholderLines) flags.push("skipPlaceholderLines");
  if (flags.length > 0) {
    process.stdout.write(use(`${C.dim}Filters:  ${flags.join(", ")}${C.reset}\n`));
  }
}

function printRuleCompact(rule: Rule, noColor: boolean): void {
  const use = noColor ? strip : (s: string) => s;
  const sevColor = colorForSev(rule.severity, noColor);
  const id = rule.id.padEnd(12);
  const sev = rule.severity.padEnd(8);
  const cat = rule.category.padEnd(22);
  process.stdout.write(
    use(`${C.bold}${id}${C.reset}  ${sevColor}${sev}${C.reset}  ${C.dim}${cat}${C.reset}  ${rule.message}\n`),
  );
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface ExploreOptions {
  /** Specific rule ID to look up — prints full detail card. */
  id?:       string;
  /** Filter by category substring. */
  category?: string;
  /** Filter by exact severity. */
  severity?: string;
  noColor:   boolean;
}

export function exploreRules(opts: ExploreOptions): void {
  const use = opts.noColor ? strip : (s: string) => s;

  // ── Single rule lookup ───────────────────────────────────────────────────
  if (opts.id) {
    const rule = RULES.find((r) => r.id.toLowerCase() === opts.id!.toLowerCase());
    if (!rule) {
      process.stderr.write(`No rule found with ID "${opts.id}"\n`);
      process.stderr.write(`Run: skillsguard rules  (to list all)\n`);
      process.exit(1);
    }
    printRule(rule, opts.noColor);
    process.stdout.write("\n");
    return;
  }

  // ── Filtered listing ─────────────────────────────────────────────────────
  let filtered = [...RULES];

  if (opts.category) {
    const cat = opts.category.toLowerCase();
    filtered = filtered.filter((r) => r.category.toLowerCase().includes(cat));
  }
  if (opts.severity) {
    const sev = opts.severity.toUpperCase();
    filtered = filtered.filter((r) => r.severity === sev);
  }

  if (filtered.length === 0) {
    process.stdout.write("No rules match the given filters.\n");
    return;
  }

  const counts: Partial<Record<string, number>> = {};
  for (const r of filtered) counts[r.category] = (counts[r.category] ?? 0) + 1;
  const cats = Object.entries(counts)
    .sort((a, b) => b[1]! - a[1]!)
    .map(([c, n]) => `${c}(${n})`)
    .join("  ");

  process.stdout.write(use(`\n${C.bold}SkillsGuard — ${filtered.length} rule(s)${C.reset}  ${C.dim}${cats}${C.reset}\n\n`));

  // Header row
  const h = (s: string) => use(`${C.bold}${C.dim}${s}${C.reset}`);
  process.stdout.write(
    `${h("ID".padEnd(12))}  ${h("SEVERITY".padEnd(8))}  ${h("CATEGORY".padEnd(22))}  ${h("MESSAGE")}\n`,
  );
  process.stdout.write(use(`${C.dim}${"─".repeat(100)}${C.reset}\n`));

  for (const rule of filtered) {
    printRuleCompact(rule, opts.noColor);
  }
  process.stdout.write("\n");
  process.stdout.write(use(`${C.dim}Tip: skillsguard rules <ID>  — full detail + remediation guidance${C.reset}\n\n`));
}
