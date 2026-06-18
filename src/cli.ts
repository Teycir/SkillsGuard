#!/usr/bin/env node
/**
 * SkillsGuard CLI
 *
 * Usage:
 *   skillsguard <target> [options]
 *
 * Options:
 *   --json            Output JSON instead of human-readable text
 *   --no-color        Disable ANSI colors
 *   --min-severity    Only report at or above this level (CRITICAL|HIGH|MEDIUM|LOW|INFO)
 *   --exit-zero       Always exit 0 (useful in CI to collect results without failing)
 *   --help            Show this help
 *
 * Exit codes:
 *   0  No findings (or --exit-zero)
 *   1  One or more findings at/above --min-severity
 *   2  Usage error / target not found
 */

import { scan } from "./scanner.js";
import { reportHuman, reportJson } from "./report.js";
import type { Severity, ScanResult } from "./types.js";
import { SEVERITY_RANK } from "./types.js";
import { runMcpServer } from "./mcp.js";
import { setupMcp } from "./setup.js";

const VALID_SEVERITIES = new Set<string>(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

function usage(): void {
  console.error(`
SkillsGuard — static security scanner for AI agent skills

Usage:
  skillsguard <target> [options]

Arguments:
  <target>          Path to a directory or single file to scan

Options:
  --json            Emit JSON output (for CI / piping to other tools)
  --no-color        Disable ANSI color codes
  --min-severity    Filter findings below this level (default: INFO)
                    Values: CRITICAL HIGH MEDIUM LOW INFO
  --exit-zero       Exit 0 even when findings exist (CI report mode)
  --help            Show this help and exit

Examples:
  skillsguard /path/to/skills
  skillsguard ./SKILL.md --json
  skillsguard /skills --min-severity HIGH
  skillsguard /skills --json --exit-zero | jq '.findings[].severity'
`.trim());
}

function parseArgs(argv: string[]): {
  target: string;
  json: boolean;
  noColor: boolean;
  minSeverity: Severity;
  exitZero: boolean;
} | null {
  const args = argv.slice(2); // drop 'node' and script path

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }

  const json = args.includes("--json");
  const noColor = args.includes("--no-color") || !process.stdout.isTTY;
  const exitZero = args.includes("--exit-zero");

  let minSeverity: Severity = "INFO";
  const minIdx = args.indexOf("--min-severity");
  if (minIdx !== -1) {
    const val = args[minIdx + 1]?.toUpperCase();
    if (!val || !VALID_SEVERITIES.has(val)) {
      console.error(`Error: --min-severity must be one of: CRITICAL HIGH MEDIUM LOW INFO`);
      return null;
    }
    minSeverity = val as Severity;
  }

  const positionals = args.filter((a) => !a.startsWith("--"));
  if (positionals.length === 0) {
    console.error("Error: <target> argument is required");
    return null;
  }
  if (positionals.length > 1) {
    console.error("Error: only one target may be specified");
    return null;
  }

  return { target: positionals[0], json, noColor, minSeverity, exitZero };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.includes("--mcp")) {
    await runMcpServer();
    return;
  }
  if (args.includes("setup") || args.includes("--setup")) {
    const dryRun = args.includes("--dry-run");
    setupMcp(dryRun);
    return;
  }

  const opts = parseArgs(process.argv);
  if (!opts) {
    usage();
    process.exit(2);
  }

  let result: ScanResult;
  try {
    result = await scan(opts.target);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${msg}`);
    process.exit(2);
  }

  // Filter by minimum severity
  const minRank = SEVERITY_RANK[opts.minSeverity];
  result = {
    ...result,
    findings: result.findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank),
  };

  if (opts.json) {
    reportJson(result);
  } else {
    reportHuman(result, opts.noColor);
  }

  if (!opts.exitZero && result.findings.length > 0) {
    process.exit(1);
  }
}

main();
