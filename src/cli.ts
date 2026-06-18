#!/usr/bin/env node
/**
 * SkillsGuard CLI
 *
 * Usage:
 *   skillsguard <target> [options]
 *
 * Options:
 *   --json            Output JSON instead of human-readable text
 *   --sarif           Output SARIF 2.1.0 (GitHub Code Scanning)
 *   --no-color        Disable ANSI colors
 *   --min-severity    Only report at or above this level (CRITICAL|HIGH|MEDIUM|LOW|INFO)
 *   --exit-zero       Always exit 0 (useful in CI to collect results without failing)
 *   --max-risk        Fail (exit 1) if risk score exceeds this value [0-100]
 *   --rule <spec>     Add a custom regex rule (repeatable). Format:
 *                       "PATTERN"                   — bare regex, HIGH severity
 *                       "id:sev:cat:msg:PATTERN"    — fully specified
 *   --rules-only      Run ONLY the custom --rule patterns; skip built-in rules
 *   --no-config       Skip loading skillsguard.config.json
 *   --help            Show this help
 *
 * Exit codes:
 *   0  No findings (or --exit-zero)
 *   1  One or more findings at/above --min-severity  OR  risk score > --max-risk
 *   2  Usage error / target not found
 */

import { scan } from "./scanner.js";
import { scanGitDiff } from "./diff.js";
import { reportHuman, reportJson } from "./report.js";
import { reportSarif } from "./sarif.js";
import { loadConfig } from "./config.js";
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
  <target>            Path to a directory or single file to scan

Options:
  --json              Emit JSON output (for CI / piping to other tools)
  --sarif             Emit SARIF 2.1.0 output (GitHub Code Scanning)
  --no-color          Disable ANSI color codes
  --min-severity      Filter findings below this level (default: INFO)
                      Values: CRITICAL HIGH MEDIUM LOW INFO
  --exit-zero         Exit 0 even when findings exist (CI report mode)
  --max-risk <n>      Exit 1 if risk score exceeds n [0-100] (e.g. --max-risk 40)
  --server            Start local HTTP server to scan files via curl POST
  --port <number>     Port to listen on for HTTP server (default: 3000)
  --rule <spec>       Add a custom regex rule. Repeatable. Two formats:
                        "PATTERN"               bare regex, severity HIGH
                        "id:sev:cat:msg:PATTERN" fully specified rule
  --diff [<base>]     Scan only files changed vs <base> ref (default HEAD).
                      Use --diff --staged for pre-commit hooks (staged files only).
  --staged            With --diff: scan only staged files (index vs HEAD)
  --no-config         Skip auto-loading skillsguard.config.json
  --help              Show this help and exit

Config file: SkillsGuard auto-loads skillsguard.config.json walking up from
  the target directory. CLI flags override config values. Use --no-config to
  disable. See README for the full schema.

Examples:
  skillsguard /path/to/skills
  skillsguard ./SKILL.md --json
  skillsguard ./SKILL.md --sarif > results.sarif
  skillsguard ./SKILL.md --max-risk 40
  skillsguard ./SKILL.md --rule "evil_pattern" --rule "another_pattern"
  skillsguard ./SKILL.md --rule "MY-001:HIGH:custom:Bad thing found:bad_thing" --rules-only
  skillsguard --diff                      # staged files
  skillsguard --diff main                 # changed vs main
  skillsguard --diff HEAD~1 --sarif > out.sarif
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
  sarif: boolean;
  noColor: boolean;
  minSeverity: Severity;
  exitZero: boolean;
  maxRisk: number | null;
  extraRules: CustomRule[];
  rulesOnly: boolean;
  noConfig: boolean;
} | null {
  const args = argv.slice(2); // drop 'node' and script path

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }

  const json     = args.includes("--json");
  const sarif    = args.includes("--sarif");
  const noColor  = args.includes("--no-color") || !process.stdout.isTTY;
  const exitZero = args.includes("--exit-zero");
  const rulesOnly = args.includes("--rules-only");
  const noConfig  = args.includes("--no-config");

  if (json && sarif) {
    console.error("Error: --json and --sarif are mutually exclusive");
    return null;
  }

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

  let maxRisk: number | null = null;
  const maxRiskIdx = args.indexOf("--max-risk");
  if (maxRiskIdx !== -1) {
    const val = Number(args[maxRiskIdx + 1]);
    if (isNaN(val) || val < 0 || val > 100) {
      console.error(`Error: --max-risk must be a number between 0 and 100`);
      return null;
    }
    maxRisk = val;
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
  const flagsWithValues = new Set(["--min-severity", "--port", "--rule", "--max-risk"]);
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

  return { target: positionals[0]!, json, sarif, noColor, minSeverity, exitZero, maxRisk, extraRules, rulesOnly, noConfig };
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

  // ── Git diff mode ───────────────────────────────────────────────────────────
  if (args.includes("--diff")) {
    const diffIdx = args.indexOf("--diff");
    const nextArg = args[diffIdx + 1];
    // base ref is the token after --diff if it doesn't start with '--'
    const base = nextArg && !nextArg.startsWith("--") ? nextArg : undefined;
    const staged = args.includes("--staged");
    const json   = args.includes("--json");
    const sarif  = args.includes("--sarif");
    const noColor = args.includes("--no-color") || !process.stdout.isTTY;
    try {
      const result = await scanGitDiff({ base, staged });
      if (sarif) {
        reportSarif(result);
      } else if (json) {
        reportJson(result);
      } else {
        const label = staged ? "staged changes" : base ? `changes vs ${base}` : "changes vs HEAD";
        process.stdout.write(`\nSkillsGuard — git diff (${label})\n`);
        process.stdout.write(`Changed files scanned: ${result.changedFiles.length}\n\n`);
        reportHuman(result, noColor);
      }
      if (result.findings.length > 0 && !args.includes("--exit-zero")) process.exit(1);
    } catch (err: unknown) {
      console.error(`Error: ${String(err)}`);
      process.exit(2);
    }
    return;
  }

  const opts = parseArgs(process.argv);
  if (!opts) {
    usage();
    process.exit(2);
  }

  // ── Load config (unless suppressed) ────────────────────────────────────────
  let cfgMinSeverity: Severity      = opts.minSeverity;
  let cfgExitZero: boolean           = opts.exitZero;
  let cfgSarif: boolean              = opts.sarif;
  let cfgNoColor: boolean            = opts.noColor;
  let cfgMaxRisk: number | null      = opts.maxRisk;
  let cfgIgnoreRules: string[]       = [];
  let cfgExtraRules: CustomRule[]    = opts.extraRules;
  let cfgRulesOnly: boolean          = opts.rulesOnly;

  if (!opts.noConfig) {
    try {
      const fileConfig = await loadConfig(opts.target);
      if (fileConfig) {
        // Config file sets defaults; CLI flags override
        if (fileConfig.minSeverity  && !process.argv.includes("--min-severity")) cfgMinSeverity = fileConfig.minSeverity;
        if (fileConfig.exitZero     && !process.argv.includes("--exit-zero"))    cfgExitZero    = fileConfig.exitZero;
        if (fileConfig.sarif        && !process.argv.includes("--sarif"))        cfgSarif       = fileConfig.sarif;
        if (fileConfig.noColor      && !process.argv.includes("--no-color"))     cfgNoColor     = fileConfig.noColor;
        if (fileConfig.maxRiskScore != null && !process.argv.includes("--max-risk")) cfgMaxRisk = fileConfig.maxRiskScore;
        if (fileConfig.rulesOnly    && !process.argv.includes("--rules-only"))   cfgRulesOnly   = fileConfig.rulesOnly;
        if (fileConfig.ignoreRules) cfgIgnoreRules = fileConfig.ignoreRules;
        // Merge config extraRules BEFORE cli extraRules (cli takes precedence by appearing last)
        if (fileConfig.extraRules?.length) cfgExtraRules = [...fileConfig.extraRules, ...opts.extraRules];
      }
    } catch (err: unknown) {
      console.error(`Warning: ${String(err)}`);
    }
  }

  // ── Scan ───────────────────────────────────────────────────────────────────
  let result: ScanResult;
  try {
    result = await scan(opts.target, {
      extraRules: cfgExtraRules.length > 0 ? cfgExtraRules : undefined,
      rulesOnly: cfgRulesOnly,
      ignoreRules: cfgIgnoreRules.length > 0 ? cfgIgnoreRules : undefined,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${msg}`);
    process.exit(2);
  }

  // ── Filter by minimum severity ─────────────────────────────────────────────
  const minRank = SEVERITY_RANK[cfgMinSeverity];
  result = {
    ...result,
    findings: result.findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank),
  };

  // ── Report ─────────────────────────────────────────────────────────────────
  if (cfgSarif) {
    reportSarif(result);
  } else if (opts.json) {
    reportJson(result);
  } else {
    reportHuman(result, cfgNoColor);
  }

  // ── Exit code ──────────────────────────────────────────────────────────────
  if (!cfgExitZero) {
    if (result.findings.length > 0) process.exit(1);
    if (cfgMaxRisk !== null && result.riskScore.score > cfgMaxRisk) {
      console.error(`Risk score ${result.riskScore.score} exceeds --max-risk threshold ${cfgMaxRisk}`);
      process.exit(1);
    }
  }
}

main();
