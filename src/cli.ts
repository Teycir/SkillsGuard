#!/usr/bin/env node
/**
 * SkillsGuard CLI
 *
 * Usage:
 *   skillsguard <target> [options]
 *   skillsguard install-hook [hook-options]
 *   skillsguard uninstall-hook [--dry-run]
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
 * Pre-commit hook subcommands:
 *   skillsguard install-hook [--hook-severity LEVEL] [--hook-max-risk N]
 *                            [--hook-exit-zero] [--hook-json] [--hook-sarif] [--dry-run]
 *   skillsguard uninstall-hook [--dry-run]
 *
 * Exit codes:
 *   0  No findings (or --exit-zero)
 *   1  One or more findings at/above --min-severity  OR  risk score > --max-risk
 *   2  Usage error / target not found
 */

import { scan, computeRiskScore } from "./scanner.js";
import { scanGitDiff } from "./diff.js";
import { reportHuman, reportJson } from "./report.js";
import { reportSarif } from "./sarif.js";
import { loadConfig } from "./config.js";
import type { Severity, ScanResult, CustomRule } from "./types.js";
import { SEVERITY_RANK } from "./types.js";
import { runMcpServer } from "./mcp.js";
import { setupMcp } from "./setup.js";
import { installHook, uninstallHook } from "./hook.js";
import type { UninstallOutcome } from "./hook.js";

const VALID_SEVERITIES = new Set<string>(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

function usage(): void {
  console.error(`
SkillsGuard — static security scanner for AI agent skills

Usage:
  skillsguard <target> [options]
  skillsguard server [port]
  skillsguard install-hook [hook-options]
  skillsguard uninstall-hook [--dry-run]

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

Pre-commit hook options (used with install-hook):
  --hook-severity <LEVEL>   Minimum severity that blocks the commit (default: HIGH)
  --hook-max-risk <n>       Block commit if risk score exceeds n [0-100]
  --hook-exit-zero          Install in report-only mode (never blocks commits)
  --hook-json               Hook emits JSON output
  --hook-sarif              Hook emits SARIF output
  --dry-run                 Print what would be done without writing files

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
  skillsguard install-hook
  skillsguard install-hook --hook-severity CRITICAL --hook-max-risk 40
  skillsguard uninstall-hook
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
  const args = argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }

  const json      = args.includes("--json");
  const sarif     = args.includes("--sarif");
  const noColor   = args.includes("--no-color") || !process.stdout.isTTY;
  const exitZero  = args.includes("--exit-zero");
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
      i++;
    }
  }

  if (rulesOnly && extraRules.length === 0) {
    console.error(`Error: --rules-only requires at least one --rule to be specified`);
    return null;
  }

  const flagsWithValues = new Set(["--min-severity", "--port", "--rule", "--max-risk"]);
  const positionals: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (flagsWithValues.has(a)) {
      i++;
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

  // ── Pre-commit hook install ────────────────────────────────────────────────
  if (args.includes("install-hook")) {
    const dryRun = args.includes("--dry-run");

    let hookSeverity: Severity = "HIGH";
    const hookSevIdx = args.indexOf("--hook-severity");
    if (hookSevIdx !== -1) {
      const val = args[hookSevIdx + 1]?.toUpperCase();
      if (!val || !VALID_SEVERITIES.has(val)) {
        console.error("Error: --hook-severity must be one of: CRITICAL HIGH MEDIUM LOW INFO");
        process.exit(2);
      }
      hookSeverity = val as Severity;
    }

    let hookMaxRisk: number | undefined;
    const hookRiskIdx = args.indexOf("--hook-max-risk");
    if (hookRiskIdx !== -1) {
      const val = Number(args[hookRiskIdx + 1]);
      if (isNaN(val) || val < 0 || val > 100) {
        console.error("Error: --hook-max-risk must be a number between 0 and 100");
        process.exit(2);
      }
      hookMaxRisk = val;
    }

    const hookExitZero = args.includes("--hook-exit-zero");
    const hookJson     = args.includes("--hook-json");
    const hookSarif    = args.includes("--hook-sarif");

    if (hookJson && hookSarif) {
      console.error("Error: --hook-json and --hook-sarif are mutually exclusive");
      process.exit(2);
    }

    try {
      console.log("\nSkillsGuard — installing pre-commit hook");
      const res = await installHook({
        minSeverity: hookSeverity,
        maxRisk:     hookMaxRisk,
        exitZero:    hookExitZero,
        json:        hookJson,
        sarif:       hookSarif,
        dryRun,
      });

      if (!dryRun) {
        const action = res.created ? "Installed" : "Updated";
        console.log(`  ${action}: ${res.hookPath}`);
        if (res.backupPath) console.log(`  Previous hook backed up to: ${res.backupPath}`);
        console.log("");
        const riskPart = hookMaxRisk != null ? ` --max-risk ${hookMaxRisk}` : "";
        const zeroPart = hookExitZero ? " --exit-zero" : "";
        console.log(`  Every commit will now run:`);
        console.log(`    skillsguard --diff --staged --min-severity ${hookSeverity}${riskPart}${zeroPart}`);
        console.log("");
        console.log("  To remove:  skillsguard uninstall-hook");
      }
    } catch (err: unknown) {
      console.error(`Error: ${String(err)}`);
      process.exit(2);
    }
    return;
  }

  // ── Pre-commit hook uninstall ──────────────────────────────────────────────
  if (args.includes("uninstall-hook")) {
    const dryRun = args.includes("--dry-run");
    try {
      console.log("\nSkillsGuard — removing pre-commit hook");
      const outcome: UninstallOutcome = await uninstallHook({ dryRun });
      if (outcome === "foreign-hook") {
        // Hook exists but isn't ours — treat as a usage error so the caller
        // knows they need to remove it manually before SkillsGuard can manage it.
        process.exit(2);
      }
      if (outcome === "not-found" && !dryRun) process.exit(1);
    } catch (err: unknown) {
      console.error(`Error: ${String(err)}`);
      process.exit(2);
    }
    return;
  }

  // ── Git diff mode ──────────────────────────────────────────────────────────
  if (args.includes("--diff")) {
    const diffIdx = args.indexOf("--diff");
    const nextArg = args[diffIdx + 1];
    const base    = nextArg && !nextArg.startsWith("--") ? nextArg : undefined;
    const staged  = args.includes("--staged");
    const json    = args.includes("--json");
    const sarif   = args.includes("--sarif");
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

  // ── Full scan mode ─────────────────────────────────────────────────────────
  const opts = parseArgs(process.argv);
  if (!opts) {
    // parseArgs already printed a specific error message; just exit.
    process.exit(2);
  }

  let cfgMinSeverity: Severity   = opts.minSeverity;
  let cfgExitZero: boolean        = opts.exitZero;
  let cfgSarif: boolean           = opts.sarif;
  let cfgNoColor: boolean         = opts.noColor;
  let cfgMaxRisk: number | null   = opts.maxRisk;
  let cfgIgnoreRules: string[]    = [];
  let cfgExtraRules: CustomRule[] = opts.extraRules;
  let cfgRulesOnly: boolean       = opts.rulesOnly;

  if (!opts.noConfig) {
    try {
      const fileConfig = await loadConfig(opts.target);
      if (fileConfig) {
        if (fileConfig.minSeverity  && !process.argv.includes("--min-severity")) cfgMinSeverity = fileConfig.minSeverity;
        if (fileConfig.exitZero     && !process.argv.includes("--exit-zero"))    cfgExitZero    = fileConfig.exitZero;
        if (fileConfig.sarif        && !process.argv.includes("--sarif"))        cfgSarif       = fileConfig.sarif;
        if (fileConfig.noColor      && !process.argv.includes("--no-color"))     cfgNoColor     = fileConfig.noColor;
        if (fileConfig.maxRiskScore != null && !process.argv.includes("--max-risk")) cfgMaxRisk = fileConfig.maxRiskScore;
        if (fileConfig.rulesOnly    && !process.argv.includes("--rules-only"))   cfgRulesOnly   = fileConfig.rulesOnly;
        if (fileConfig.ignoreRules) cfgIgnoreRules = fileConfig.ignoreRules;
        if (fileConfig.extraRules?.length) cfgExtraRules = [...fileConfig.extraRules, ...opts.extraRules];
      }
    } catch (err: unknown) {
      console.error(`Warning: ${String(err)}`);
    }
  }

  let result: ScanResult;
  try {
    result = await scan(opts.target, {
      extraRules:   cfgExtraRules.length > 0  ? cfgExtraRules   : undefined,
      rulesOnly:    cfgRulesOnly,
      ignoreRules:  cfgIgnoreRules.length > 0 ? cfgIgnoreRules  : undefined,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${msg}`);
    process.exit(2);
  }

  const minRank = SEVERITY_RANK[cfgMinSeverity];
  const filteredFindings = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank);
  result = {
    ...result,
    findings: filteredFindings,
    // Recompute risk score using only the findings that survive the severity filter
    // so that --min-severity HIGH doesn't show an inflated score from LOW/MEDIUM findings.
    riskScore: computeRiskScore(filteredFindings),
  };

  if (cfgSarif) {
    reportSarif(result);
  } else if (opts.json) {
    reportJson(result);
  } else {
    reportHuman(result, cfgNoColor);
  }

  if (!cfgExitZero) {
    if (result.findings.length > 0) process.exit(1);
    if (cfgMaxRisk !== null && result.riskScore.score > cfgMaxRisk) {
      console.error(`Risk score ${result.riskScore.score} exceeds --max-risk threshold ${cfgMaxRisk}`);
      process.exit(1);
    }
  }
}

main();
