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
 *   --rule <spec>     Add a custom regex rule (repeatable). Format:
 *                       "PATTERN"                   — bare regex, HIGH severity
 *                       "id:sev:cat:msg:PATTERN"    — fully specified
 *   --rules-only      Run ONLY the custom --rule patterns; skip built-in rules
 *   --help            Show this help
 *
 * Exit codes:
 *   0  No findings (or --exit-zero)
 *   1  One or more findings at/above --min-severity
 *   2  Usage error / target not found
 */

import { scan } from "./scanner.js";
import { reportHuman, reportJson } from "./report.js";
import type { Severity, ScanResult, CustomRule } from "./types.js";
import { SEVERITY_RANK } from "./types.js";
import { runMcpServer } from "./mcp.js";
import { setupMcp } from "./setup.js";

const VALID_SEVERITIES = new Set<string>(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

function usage(): void {
  console.error(`
SkillsGuard — static security scanner for AI agent skills

Usage:
  skillsguard <target> [options]
  skillsguard server [port]

Arguments:
  <target>          Path to a directory or single file to scan

Options:
  --json            Emit JSON output (for CI / piping to other tools)
  --no-color        Disable ANSI color codes
  --min-severity    Filter findings below this level (default: INFO)
                    Values: CRITICAL HIGH MEDIUM LOW INFO
  --exit-zero       Exit 0 even when findings exist (CI report mode)
  --server          Start local HTTP server to scan files via curl POST
  --port <number>   Port to listen on for HTTP server (default: 3000)
  --rule <spec>     Add a custom regex rule. Repeatable. Two formats:
                      "PATTERN"               bare regex, severity HIGH
                      "id:sev:cat:msg:PATTERN" fully specified rule
                    Example: --rule "my-secret-token"
                    Example: --rule "MY-001:CRITICAL:custom:Found secret:my-secret-token"
  --rules-only      Run ONLY the custom --rule patterns; skip built-ins
  --help            Show this help and exit

Examples:
  skillsguard /path/to/skills
  skillsguard ./SKILL.md --json
  skillsguard ./SKILL.md --rule "evil_pattern" --rule "another_pattern"
  skillsguard ./SKILL.md --rule "MY-001:HIGH:custom:Bad thing found:bad_thing" --rules-only
  skillsguard server 4000
  curl --data-binary @SKILL.md http://localhost:3000/scan
`.trim());
}

/**
 * Parse a --rule spec string into a CustomRule.
 *
 * Supported formats:
 *   "PATTERN"                         — bare regex, defaults applied
 *   "id:sev:cat:msg:PATTERN"          — fully specified (5 colon-separated parts)
 *
 * The PATTERN segment itself may contain colons, so we only split on the first 4.
 */
function parseRuleSpec(spec: string): CustomRule | null {
  // Count leading colon-separated segments. Split at most 4 times so the
  // remainder (the pattern) can contain colons freely.
  const parts = spec.split(":");
  if (parts.length >= 5) {
    const [id, sev, cat, msg, ...rest] = parts;
    const pattern = rest.join(":");
    const sevUpper = sev!.toUpperCase();
    if (!VALID_SEVERITIES.has(sevUpper)) {
      console.error(`Error: invalid severity "${sev}" in --rule spec. Must be one of: CRITICAL HIGH MEDIUM LOW INFO`);
      return null;
    }
    return {
      id: id || undefined,
      severity: sevUpper as Severity,
      category: cat || "custom",
      message: msg || undefined,
      pattern,
    };
  }
  // Bare pattern — no colons as delimiters
  return { pattern: spec };
}

function parseArgs(argv: string[]): {
  target: string;
  json: boolean;
  noColor: boolean;
  minSeverity: Severity;
  exitZero: boolean;
  extraRules: CustomRule[];
  rulesOnly: boolean;
} | null {
  const args = argv.slice(2); // drop 'node' and script path

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }

  const json = args.includes("--json");
  const noColor = args.includes("--no-color") || !process.stdout.isTTY;
  const exitZero = args.includes("--exit-zero");
  const rulesOnly = args.includes("--rules-only");

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

  // Collect all --rule <spec> occurrences
  const extraRules: CustomRule[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--rule") {
      const spec = args[i + 1];
      if (!spec || spec.startsWith("--")) {
        console.error(`Error: --rule requires a pattern argument`);
        return null;
      }
      const rule = parseRuleSpec(spec);
      if (!rule) return null;
      extraRules.push(rule);
      i++; // skip the value token
    }
  }

  if (rulesOnly && extraRules.length === 0) {
    console.error(`Error: --rules-only requires at least one --rule to be specified`);
    return null;
  }

  // Positional args: skip flag values (tokens that follow a known flag)
  const flagsWithValues = new Set(["--min-severity", "--port", "--rule"]);
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (flagsWithValues.has(a)) {
      i++; // skip value
    } else if (!a.startsWith("--")) {
      positionals.push(a);
    }
  }

  if (positionals.length === 0) {
    console.error("Error: <target> argument is required");
    return null;
  }
  if (positionals.length > 1) {
    console.error("Error: only one target may be specified");
    return null;
  }

  return { target: positionals[0]!, json, noColor, minSeverity, exitZero, extraRules, rulesOnly };
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
  if (args.includes("--server") || args.includes("server")) {
    const portIdx = args.indexOf("--port");
    let port = 3000;
    if (portIdx !== -1) {
      const val = parseInt(args[portIdx + 1] ?? "3000", 10);
      if (!isNaN(val)) port = val;
    } else {
      const serverIdx = args.indexOf("server");
      if (serverIdx !== -1 && args[serverIdx + 1] !== undefined) {
        const val = parseInt(args[serverIdx + 1]!, 10);
        if (!isNaN(val)) port = val;
      }
    }
    const { startServer } = await import("./server.js");
    startServer(port);
    return;
  }

  const opts = parseArgs(process.argv);
  if (!opts) {
    usage();
    process.exit(2);
  }

  let result: ScanResult;
  try {
    result = await scan(opts.target, {
      extraRules: opts.extraRules.length > 0 ? opts.extraRules : undefined,
      rulesOnly: opts.rulesOnly,
    });
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
