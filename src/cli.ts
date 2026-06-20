#!/usr/bin/env node
/**
 * SkillsGuard CLI
 *
 * Usage:
 *   skillsguard <target> [options]
 *   skillsguard rules [ID] [--category CAT] [--severity SEV]
 *   skillsguard tune <RULE-ID> --severity <SEV> [--config <path>]
 *   skillsguard install-hook [hook-options]
 *   skillsguard uninstall-hook [--dry-run]
 *
 * Options:
 *   --json                  Output JSON
 *   --sarif                 Output SARIF 2.1.0
 *   --no-color              Disable ANSI colors
 *   --min-severity          Only report at or above level (CRITICAL|HIGH|MEDIUM|LOW|INFO)
 *   --exit-zero             Always exit 0
 *   --max-risk <n>          Fail if risk score exceeds n [0-100]
 *   --quiet                 Suppress all output; only exit code matters
 *   --stats                 Print category/severity breakdown instead of full findings
 *   --max-findings <n>      Stop after n findings (fast-fail)
 *   --exclude <pattern>     Exclude path segment from scan (repeatable)
 *   --severity-override     Override rule severity: id:SEV (repeatable)
 *   --save-baseline         Snapshot current findings as the baseline
 *   --diff-baseline         Only show NEW findings vs saved baseline
 *   --update-baseline       Merge new findings into existing baseline
 *   --watch                 Re-scan on file changes, print delta
 *   --rule <spec>           Add a custom regex rule (repeatable)
 *   --rules-only            Run ONLY the custom --rule patterns
 *   --no-config             Skip loading skillsguard.config.json
 *   --help                  Show this help
 */

import { scan, computeRiskScore } from "./scanner.js";
import { scanGitDiff } from "./diff.js";
import { reportHuman, reportJson, reportStats, reportBaselineDiff } from "./report.js";
import { reportSarif } from "./sarif.js";
import { loadConfig } from "./config.js";
import type { Severity, ScanResult, CustomRule } from "./types.js";
import { SEVERITY_RANK } from "./types.js";
import { runMcpServer } from "./mcp.js";
import { setupMcp } from "./setup.js";
import { installHook, uninstallHook } from "./hook.js";
import { exploreRules } from "./explorer.js";
import { startWatch } from "./watch.js";
import { loadBaseline, saveBaseline, updateBaseline, diffBaseline } from "./lib/baseline.js";
import type { UninstallOutcome } from "./hook.js";

const VALID_SEVERITIES = new Set<string>(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);


function usage(): void {
  console.error(`
SkillsGuard — static security scanner for AI agent skills

Usage:
  skillsguard <target> [options]
  skillsguard rules [ID] [--category CAT] [--severity SEV]
  skillsguard tune <RULE-ID> --severity <SEV> [--config <path>]
  skillsguard server [port]
  skillsguard install-hook [hook-options]
  skillsguard uninstall-hook [--dry-run]

Arguments:
  <target>            Path to a directory or single file to scan

Options:
  --json              Emit JSON output
  --sarif             Emit SARIF 2.1.0 output (GitHub Code Scanning)
  --no-color          Disable ANSI color codes
  --min-severity      Filter findings below this level (default: INFO)
                      Values: CRITICAL HIGH MEDIUM LOW INFO
  --exit-zero         Exit 0 even when findings exist
  --max-risk <n>      Exit 1 if risk score exceeds n [0-100]
  --quiet             Suppress all output; only exit code matters
  --stats             Print category/severity breakdown (no individual findings)
  --max-findings <n>  Stop after n findings and exit 1 (fast-fail for CI)
  --exclude <seg>     Exclude files whose path contains this segment (repeatable)
                      e.g. --exclude vendor --exclude generated
  --severity-override Override a rule's severity: <id>:<SEV> (repeatable)
                      e.g. --severity-override EX-008:CRITICAL
  --save-baseline     Snapshot current findings to .skillsguard/baseline.json
  --diff-baseline     Only report NEW findings vs saved baseline
  --update-baseline   Merge new findings into existing baseline
  --watch             Re-scan target on file changes; print only deltas
  --diff [<base>]     Scan files changed vs <base> ref (default HEAD)
                      Scans entire changed files, not line-by-line diffs
  --staged            With --diff: scan only staged files
  --server            Start local HTTP server to scan files via curl POST
  --port <number>     Port for HTTP server (default: 3000)
  --rule <spec>       Add a custom regex rule. Repeatable. Two formats:
                        "PATTERN"               bare regex, severity HIGH
                        "id:sev:cat:msg:PATTERN" fully specified
  --rules-only        Run ONLY the custom --rule patterns; skip built-ins
  --no-config         Skip auto-loading skillsguard.config.json
  --help              Show this help and exit

Subcommands:
  rules [ID]          List all rules, or show full detail for a single rule
    --category CAT    Filter by category substring
    --severity SEV    Filter by exact severity

  tune <RULE-ID> --severity <SEV>
                      Write a severity override for RULE-ID into the config file
    --config <path>   Config file to write to (default: auto-discovered or ./skillsguard.config.json)

Pre-commit hook options (used with install-hook):
  --hook-severity <LEVEL>   Minimum severity that blocks the commit (default: HIGH)
  --hook-max-risk <n>       Block commit if risk score exceeds n
  --hook-exit-zero          Install in report-only mode (never blocks commits)
  --hook-json               Hook emits JSON output
  --hook-sarif              Hook emits SARIF output
  --dry-run                 Print what would be done without writing files

Examples:
  skillsguard /path/to/skills
  skillsguard ./SKILL.md --min-severity HIGH --stats
  skillsguard ./SKILL.md --save-baseline
  skillsguard ./SKILL.md --diff-baseline           # CI gate on new findings only
  skillsguard ./SKILL.md --exclude vendor --exclude generated
  skillsguard ./SKILL.md --max-findings 10         # fast-fail after 10 findings
  skillsguard ./SKILL.md --severity-override EX-008:CRITICAL
  skillsguard ./SKILL.md --watch
  skillsguard rules
  skillsguard rules PI-001
  skillsguard rules --category exfiltration
  skillsguard tune EX-008 --severity CRITICAL
  skillsguard install-hook --hook-severity CRITICAL --hook-max-risk 40
  skillsguard uninstall-hook
`.trim());
}


/**
 * Parse a --rule spec string into a CustomRule.
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

/**
 * Parse --severity-override id:SEV into a [id, Severity] pair.
 */
function parseSeverityOverride(spec: string): [string, Severity] | null {
  const colon = spec.indexOf(":");
  if (colon <= 0) {
    console.error(`Error: --severity-override must be in the format "RULE-ID:SEVERITY", got: "${spec}"`);
    return null;
  }
  const id  = spec.slice(0, colon).trim();
  const sev = spec.slice(colon + 1).trim().toUpperCase();
  if (!VALID_SEVERITIES.has(sev)) {
    console.error(`Error: invalid severity "${sev}" in --severity-override. Must be one of: CRITICAL HIGH MEDIUM LOW INFO`);
    return null;
  }
  return [id, sev as Severity];
}

interface ParsedArgs {
  target: string;
  json: boolean;
  sarif: boolean;
  noColor: boolean;
  minSeverity: Severity;
  exitZero: boolean;
  maxRisk: number | null;
  quiet: boolean;
  stats: boolean;
  maxFindings: number;
  excludePatterns: string[];
  severityOverrides: Partial<Record<string, Severity>>;
  saveBaseline: boolean;
  diffBaseline: boolean;
  updateBaseline: boolean;
  watch: boolean;
  extraRules: CustomRule[];
  rulesOnly: boolean;
  noConfig: boolean;
}

function parseArgs(argv: string[]): ParsedArgs | null {
  const args = argv.slice(2);

  if (args.includes("--help") || args.includes("-h")) {
    usage();
    process.exit(0);
  }

  const json            = args.includes("--json");
  const sarif           = args.includes("--sarif");
  const noColor         = args.includes("--no-color") || !process.stdout.isTTY;
  const exitZero        = args.includes("--exit-zero");
  const rulesOnly       = args.includes("--rules-only");
  const noConfig        = args.includes("--no-config");
  const quiet           = args.includes("--quiet");
  const stats           = args.includes("--stats");
  const saveBaseline    = args.includes("--save-baseline");
  const diffBaseline    = args.includes("--diff-baseline");
  const updateBaseline  = args.includes("--update-baseline");
  const watch           = args.includes("--watch");

  if (json && sarif) {
    console.error("Error: --json and --sarif are mutually exclusive");
    return null;
  }
  if (quiet && (json || sarif || stats)) {
    console.error("Error: --quiet is mutually exclusive with --json, --sarif, and --stats");
    return null;
  }
  if (json && stats) {
    console.error("Error: --stats is mutually exclusive with --json and --sarif");
    return null;
  }

  const baselineFlags = [saveBaseline, diffBaseline, updateBaseline].filter(Boolean).length;
  if (baselineFlags > 1) {
    console.error("Error: --save-baseline, --diff-baseline, and --update-baseline are mutually exclusive");
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

  let maxFindings = 0;
  const maxFIdx = args.indexOf("--max-findings");
  if (maxFIdx !== -1) {
    const val = Number(args[maxFIdx + 1]);
    if (!Number.isInteger(val) || val < 1) {
      console.error(`Error: --max-findings must be a positive integer`);
      return null;
    }
    maxFindings = val;
  }

  const excludePatterns: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--exclude") {
      const seg = args[i + 1];
      if (!seg || seg.startsWith("--")) {
        console.error(`Error: --exclude requires a path segment argument`);
        return null;
      }
      excludePatterns.push(seg);
      i++;
    }
  }

  const severityOverrides: Partial<Record<string, Severity>> = {};
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--severity-override") {
      const spec = args[i + 1];
      if (!spec || spec.startsWith("--")) {
        console.error(`Error: --severity-override requires an argument (e.g. EX-008:CRITICAL)`);
        return null;
      }
      const parsed = parseSeverityOverride(spec);
      if (!parsed) return null;
      severityOverrides[parsed[0]] = parsed[1];
      i++;
    }
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

  const flagsWithValues = new Set([
    "--min-severity", "--port", "--rule", "--max-risk",
    "--max-findings", "--exclude", "--severity-override",
  ]);
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

  return {
    target: positionals[0]!,
    json,
    sarif,
    noColor,
    minSeverity,
    exitZero,
    maxRisk,
    quiet,
    stats,
    maxFindings,
    excludePatterns,
    severityOverrides,
    saveBaseline,
    diffBaseline,
    updateBaseline,
    watch,
    extraRules,
    rulesOnly,
    noConfig,
  };
}


// ─── tune subcommand: write a severityOverride to the config file ─────────────

import { readFile as fsReadFile, writeFile as fsWriteFile, stat as fsStat } from "node:fs/promises";
import { join as pathJoin } from "node:path";

async function runTune(args: string[]): Promise<void> {
  // `skillsguard tune <RULE-ID> --severity <SEV> [--config <path>]`
  const tuneIdx = args.indexOf("tune");
  const ruleId  = args[tuneIdx + 1];
  if (!ruleId || ruleId.startsWith("--")) {
    console.error("Error: tune requires a rule ID, e.g.  skillsguard tune EX-008 --severity CRITICAL");
    process.exit(2);
  }

  const sevIdx = args.indexOf("--severity");
  if (sevIdx === -1) {
    console.error("Error: tune requires --severity, e.g.  skillsguard tune EX-008 --severity CRITICAL");
    process.exit(2);
  }
  const sev = args[sevIdx + 1]?.toUpperCase();
  if (!sev || !VALID_SEVERITIES.has(sev)) {
    console.error("Error: --severity must be one of: CRITICAL HIGH MEDIUM LOW INFO");
    process.exit(2);
  }

  // Determine config file path
  let configPath: string;
  const cfgIdx = args.indexOf("--config");
  if (cfgIdx !== -1 && args[cfgIdx + 1] && !args[cfgIdx + 1]!.startsWith("--")) {
    configPath = args[cfgIdx + 1]!;
  } else {
    // Try to find existing config, else use cwd
    const candidate = pathJoin(process.cwd(), "skillsguard.config.json");
    configPath = candidate;
  }

  // Load existing config or start fresh
  let config: Record<string, unknown> = {};
  try {
    await fsStat(configPath);
    const text = await fsReadFile(configPath, "utf-8");
    config = JSON.parse(text) as Record<string, unknown>;
  } catch {
    // File doesn't exist — will create it
  }

  if (typeof config["severityOverrides"] !== "object" || config["severityOverrides"] === null) {
    config["severityOverrides"] = {};
  }
  (config["severityOverrides"] as Record<string, string>)[ruleId] = sev;

  await fsWriteFile(configPath, JSON.stringify(config, null, 2) + "\n", "utf-8");
  console.log(`✓ Set ${ruleId} → ${sev} in ${configPath}`);
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

  // ── rules subcommand ───────────────────────────────────────────────────────
  if (args[0] === "rules") {
    const noColor = args.includes("--no-color") || !process.stdout.isTTY;

    const catIdx  = args.indexOf("--category");
    const category = catIdx !== -1 ? args[catIdx + 1] : undefined;

    const sevIdx  = args.indexOf("--severity");
    const severity = sevIdx !== -1 ? args[sevIdx + 1] : undefined;

    // Flag-value positions to skip when looking for the positional rule ID
    const skipPositions = new Set<number>();
    if (catIdx !== -1) { skipPositions.add(catIdx); skipPositions.add(catIdx + 1); }
    if (sevIdx !== -1) { skipPositions.add(sevIdx); skipPositions.add(sevIdx + 1); }

    const id = args
      .slice(1)
      .map((a, i) => ({ a, i: i + 1 })) // i is index in args (shifted by 1 for "rules")
      .find(({ a, i }) => !a.startsWith("--") && !skipPositions.has(i))?.a;

    exploreRules({ id, category, severity, noColor });
    return;
  }

  // ── tune subcommand ────────────────────────────────────────────────────────
  if (args[0] === "tune") {
    await runTune(args);
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
      if (outcome === "foreign-hook") process.exit(2);
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
    process.exit(2);
  }

  // ── Merge config file (CLI flags win) ─────────────────────────────────────
  let cfgMinSeverity: Severity                         = opts.minSeverity;
  let cfgExitZero: boolean                             = opts.exitZero;
  let cfgSarif: boolean                                = opts.sarif;
  let cfgNoColor: boolean                              = opts.noColor;
  let cfgMaxRisk: number | null                        = opts.maxRisk;
  let cfgIgnoreRules: string[]                         = [];
  let cfgExtraRules: CustomRule[]                      = opts.extraRules;
  let cfgRulesOnly: boolean                            = opts.rulesOnly;
  let cfgSeverityOverrides: Partial<Record<string, Severity>> = opts.severityOverrides;
  let cfgExcludePatterns: string[]                     = opts.excludePatterns;
  let cfgMaxFindings: number                           = opts.maxFindings;

  if (!opts.noConfig) {
    try {
      const fileConfig = await loadConfig(opts.target);
      if (fileConfig) {
        if (fileConfig.minSeverity  && !process.argv.includes("--min-severity"))    cfgMinSeverity = fileConfig.minSeverity;
        if (fileConfig.exitZero     && !process.argv.includes("--exit-zero"))       cfgExitZero    = fileConfig.exitZero;
        if (fileConfig.sarif        && !process.argv.includes("--sarif"))           cfgSarif       = fileConfig.sarif;
        if (fileConfig.noColor      && !process.argv.includes("--no-color"))        cfgNoColor     = fileConfig.noColor;
        if (fileConfig.maxRiskScore != null && !process.argv.includes("--max-risk")) cfgMaxRisk    = fileConfig.maxRiskScore;
        if (fileConfig.rulesOnly    && !process.argv.includes("--rules-only"))      cfgRulesOnly   = fileConfig.rulesOnly;
        if (fileConfig.maxFindings  && !process.argv.includes("--max-findings"))    cfgMaxFindings = fileConfig.maxFindings;
        if (fileConfig.ignoreRules) cfgIgnoreRules = fileConfig.ignoreRules;
        if (fileConfig.extraRules?.length) cfgExtraRules = [...fileConfig.extraRules, ...opts.extraRules];
        // Merge: CLI overrides win over config-file overrides for individual rules
        if (fileConfig.severityOverrides) {
          cfgSeverityOverrides = { ...fileConfig.severityOverrides, ...opts.severityOverrides };
        }
        if (fileConfig.excludePatterns?.length) {
          cfgExcludePatterns = [...new Set([...fileConfig.excludePatterns, ...opts.excludePatterns])];
        }
      }
    } catch (err: unknown) {
      console.error(`Warning: ${String(err)}`);
    }
  }

  // ── Watch mode ─────────────────────────────────────────────────────────────
  if (opts.watch) {
    startWatch({
      target: opts.target,
      scanOptions: {
        extraRules:        cfgExtraRules.length > 0        ? cfgExtraRules        : undefined,
        rulesOnly:         cfgRulesOnly,
        ignoreRules:       cfgIgnoreRules.length > 0       ? cfgIgnoreRules       : undefined,
        severityOverrides: Object.keys(cfgSeverityOverrides).length > 0 ? cfgSeverityOverrides : undefined,
        excludePatterns:   cfgExcludePatterns.length > 0   ? cfgExcludePatterns   : undefined,
      },
      minSeverity: cfgMinSeverity,
      noColor: cfgNoColor,
    });
    return; // startWatch keeps the process alive
  }

  // ── Run scan ───────────────────────────────────────────────────────────────
  let result: ScanResult;
  try {
    result = await scan(opts.target, {
      extraRules:        cfgExtraRules.length > 0        ? cfgExtraRules        : undefined,
      rulesOnly:         cfgRulesOnly,
      ignoreRules:       cfgIgnoreRules.length > 0       ? cfgIgnoreRules       : undefined,
      severityOverrides: Object.keys(cfgSeverityOverrides).length > 0 ? cfgSeverityOverrides : undefined,
      excludePatterns:   cfgExcludePatterns.length > 0   ? cfgExcludePatterns   : undefined,
      maxFindings:       cfgMaxFindings > 0              ? cfgMaxFindings        : undefined,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Error: ${msg}`);
    process.exit(2);
  }

  // ── Severity filter ────────────────────────────────────────────────────────
  const minRank = SEVERITY_RANK[cfgMinSeverity];
  const filteredFindings = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank);
  result = {
    ...result,
    findings: filteredFindings,
    riskScore: computeRiskScore(filteredFindings),
  };

  // ── Baseline operations ────────────────────────────────────────────────────
  if (opts.saveBaseline) {
    const savedPath = await saveBaseline(opts.target, result.findings);
    if (!opts.quiet) {
      const c = cfgNoColor ? (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "") : (s: string) => s;
      process.stdout.write(c(`\x1b[32m✓ Baseline saved: ${savedPath} (${result.findings.length} finding(s))\x1b[0m\n`));
    }
    process.exit(0);
  }

  if (opts.updateBaseline) {
    const savedPath = await updateBaseline(opts.target, result.findings);
    if (!opts.quiet) {
      const c = cfgNoColor ? (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "") : (s: string) => s;
      process.stdout.write(c(`\x1b[32m✓ Baseline updated: ${savedPath}\x1b[0m\n`));
    }
    process.exit(0);
  }

  if (opts.diffBaseline) {
    const baseline = await loadBaseline(opts.target);
    const diff = diffBaseline(baseline, result.findings);

    if (!opts.quiet) {
      if (cfgSarif) {
        // Diff as SARIF — only emit the new findings
        reportSarif({ ...result, findings: diff.newFindings });
      } else if (opts.json) {
        process.stdout.write(JSON.stringify({ ...diff, target: result.target, filesScanned: result.filesScanned }, null, 2) + "\n");
      } else {
        process.stdout.write(`\nSkillsGuard — diff vs baseline  ${result.filesScanned} file(s)\n\n`);
        reportBaselineDiff(diff, cfgNoColor);
      }
    }

    if (!cfgExitZero && diff.newFindings.length > 0) process.exit(1);
    return;
  }

  // ── Output ─────────────────────────────────────────────────────────────────
  if (!opts.quiet) {
    if (cfgSarif) {
      reportSarif(result);
    } else if (opts.json) {
      reportJson(result);
    } else if (opts.stats) {
      reportStats(result, cfgNoColor);
    } else {
      reportHuman(result, cfgNoColor);
    }
  }

  // ── Exit code ──────────────────────────────────────────────────────────────
  if (!cfgExitZero) {
    if (result.findings.length > 0) process.exit(1);
    if (cfgMaxRisk !== null && result.riskScore.score > cfgMaxRisk) {
      if (!opts.quiet) {
        console.error(`Risk score ${result.riskScore.score} exceeds --max-risk threshold ${cfgMaxRisk}`);
      }
      process.exit(1);
    }
  }
}

main();
