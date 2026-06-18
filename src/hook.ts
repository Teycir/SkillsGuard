/**
 * SkillsGuard — Pre-commit hook installer
 *
 * Writes (or removes) a Git pre-commit hook that runs
 *   skillsguard --diff --staged [options]
 * over every staged file before a commit is accepted.
 *
 * Usage (programmatic):
 *   import { installHook, uninstallHook } from "skillsguard";
 *   await installHook();
 *   await uninstallHook();
 *
 * Usage (CLI):
 *   skillsguard install-hook [--hook-severity HIGH] [--hook-max-risk 40]
 *   skillsguard uninstall-hook
 */

import {
  readFileSync,
  writeFileSync,
  existsSync,
  copyFileSync,
  chmodSync,
  mkdirSync,
  unlinkSync,
} from "node:fs";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import type { Severity } from "./types.js";

// ─── Sentinel so we can detect / clean our own hooks ────────────────────────
const HOOK_SENTINEL = "# skillsguard:pre-commit";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HookOptions {
  /**
   * Minimum severity to report (and fail on). Defaults to "HIGH".
   * Set to "INFO" to catch everything.
   */
  minSeverity?: Severity;
  /**
   * Fail the commit if the risk score exceeds this threshold [0-100].
   * Omit to disable the risk-score gate.
   */
  maxRisk?: number;
  /**
   * Exit 0 even when findings exist (report-only mode).
   * Useful during rollout: see the noise without blocking commits.
   */
  exitZero?: boolean;
  /**
   * Emit JSON output instead of human-readable ANSI output.
   * Handy if you have a downstream log ingestor.
   */
  json?: boolean;
  /**
   * Emit SARIF 2.1.0 output. Mutually exclusive with json.
   */
  sarif?: boolean;
  /**
   * Path to the git repository root. Defaults to process.cwd().
   */
  repoDir?: string;
  /**
   * If true, print what would be done without writing any files.
   */
  dryRun?: boolean;
}

export interface HookResult {
  /** Absolute path to .git/hooks/pre-commit */
  hookPath: string;
  /** Whether this is a new install (true) or an update to an existing hook (false). */
  created: boolean;
  /** Path to the backup of the previous non-SkillsGuard hook, if one existed. */
  backupPath?: string;
}

/**
 * Outcome of an uninstall attempt, distinguishing the three possible states
 * so callers can act or report accurately without parsing console output.
 */
export type UninstallOutcome =
  | "removed"        // hook was ours and has been deleted (or would be in dry-run)
  | "not-found"      // no pre-commit hook exists at all
  | "foreign-hook";  // a hook exists but was not created by SkillsGuard

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function findGitRoot(startDir: string): Promise<string> {
  return new Promise((res, rej) => {
    const proc = spawn("git", ["rev-parse", "--show-toplevel"], {
      cwd: startDir,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    proc.stdout.on("data", (d: Buffer) => (out += d.toString()));
    proc.stderr.on("data", (d: Buffer) => (err += d.toString()));
    proc.on("close", (code) => {
      if (code !== 0) rej(new Error(`Not a git repository (git: ${err.trim()})`));
      else res(out.trim());
    });
    proc.on("error", (e) => rej(new Error(`Failed to run git: ${e.message}`)));
  });
}

/**
 * Resolve the invocation for the generated hook script.
 *
 * Priority:
 *   1. The running process argv[1] when it points at our cli entry-point
 *      (ends with /dist/cli.js or /skillsguard). The path is shell-quoted
 *      to survive spaces in directory names.
 *   2. `npx skillsguard` — safe portable fallback after a global npm install.
 */
function resolveRunnerCommand(): { command: string; args: string[] } {
  const argv1 = process.argv[1] ?? "";
  const resolved = resolve(argv1);

  if (resolved.endsWith(`/dist/cli.js`) || resolved.endsWith(`/skillsguard`)) {
    // Shell-quote the absolute path so spaces or single quotes in directory
    // names don't break the generated hook script.
    const escaped = resolved.replace(/'/g, "'\\''");
    const quoted = `'${escaped}'`;
    return { command: "node", args: [quoted] };
  }

  // Fallback: npx resolves the globally installed binary at run-time, so the
  // hook stays valid even if the package is later reinstalled to a new path.
  return { command: "npx", args: ["skillsguard"] };
}

/** Build the shell script body for the pre-commit hook. */
function buildHookScript(opts: HookOptions): string {
  const { command, args } = resolveRunnerCommand();

  const extraFlags: string[] = ["--diff", "--staged"];
  if (opts.minSeverity) extraFlags.push("--min-severity", opts.minSeverity);
  if (opts.maxRisk != null) extraFlags.push("--max-risk", String(opts.maxRisk));
  if (opts.exitZero) extraFlags.push("--exit-zero");
  if (opts.sarif) extraFlags.push("--sarif");
  else if (opts.json) extraFlags.push("--json");

  const invocation = [command, ...args, ...extraFlags].join(" ");

  return `#!/bin/sh
${HOOK_SENTINEL}
# Auto-generated by: skillsguard install-hook
# Remove with:       skillsguard uninstall-hook
#
# Runs SkillsGuard over staged skill files before every commit.
# Prevention beats detection — catch malicious skills before they land.

${invocation}
exit $?
`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Install (or update) the SkillsGuard pre-commit hook.
 *
 * If a pre-commit hook already exists and was **not** created by SkillsGuard,
 * it is backed up to `pre-commit.bak` before being replaced.
 * If it **was** created by SkillsGuard, it is silently overwritten (update).
 */
export async function installHook(opts: HookOptions = {}): Promise<HookResult> {
  const repoDir = opts.repoDir ?? process.cwd();
  const gitRoot = await findGitRoot(repoDir);
  const hooksDir = join(gitRoot, ".git", "hooks");
  const hookPath = join(hooksDir, "pre-commit");
  const dryRun = opts.dryRun ?? false;

  // Ensure .git/hooks exists (bare repos, fresh clones may not have it)
  if (!dryRun && !existsSync(hooksDir)) {
    mkdirSync(hooksDir, { recursive: true });
  }

  let created = true;
  let backupPath: string | undefined;

  if (existsSync(hookPath)) {
    const existing = readFileSync(hookPath, "utf-8");
    const isMine = existing.includes(HOOK_SENTINEL);

    if (!isMine) {
      backupPath = `${hookPath}.bak`;
      if (!dryRun) {
        copyFileSync(hookPath, backupPath);
        console.log(`  Backed up existing hook → ${backupPath}`);
      } else {
        console.log(`  [dry-run] Would back up existing hook → ${backupPath}`);
      }
    }
    created = false;
  }

  const script = buildHookScript({
    minSeverity: opts.minSeverity ?? "HIGH",
    maxRisk:     opts.maxRisk,
    exitZero:    opts.exitZero  ?? false,
    json:        opts.json      ?? false,
    sarif:       opts.sarif     ?? false,
  });

  if (dryRun) {
    console.log(`  [dry-run] Would write hook to: ${hookPath}`);
    console.log("─────────────────────────────────────────────────────────");
    console.log(script);
    console.log("─────────────────────────────────────────────────────────");
  } else {
    writeFileSync(hookPath, script, "utf-8");
    chmodSync(hookPath, 0o755);
  }

  return { hookPath, created, backupPath };
}

/**
 * Remove the SkillsGuard pre-commit hook.
 *
 * Only removes hooks that contain the SkillsGuard sentinel comment.
 * If a `.bak` backup exists, it is restored automatically.
 *
 * Returns an {@link UninstallOutcome} so callers can distinguish between
 * "hook not present", "hook is foreign", and "hook removed" without
 * parsing console output.
 */
export async function uninstallHook(
  opts: { repoDir?: string; dryRun?: boolean } = {},
): Promise<UninstallOutcome> {
  const repoDir  = opts.repoDir ?? process.cwd();
  const dryRun   = opts.dryRun  ?? false;
  const gitRoot  = await findGitRoot(repoDir);
  const hookPath = join(gitRoot, ".git", "hooks", "pre-commit");
  const backupPath = `${hookPath}.bak`;

  if (!existsSync(hookPath)) {
    console.log("  No pre-commit hook found.");
    return "not-found";
  }

  const existing = readFileSync(hookPath, "utf-8");
  if (!existing.includes(HOOK_SENTINEL)) {
    console.log("  pre-commit hook exists but was not created by SkillsGuard — leaving it untouched.");
    return "foreign-hook";
  }

  if (dryRun) {
    console.log(`  [dry-run] Would remove: ${hookPath}`);
    if (existsSync(backupPath)) console.log(`  [dry-run] Would restore backup: ${backupPath}`);
    return "removed";
  }

  if (existsSync(backupPath)) {
    copyFileSync(backupPath, hookPath);
    unlinkSync(backupPath);
    console.log(`  Restored previous hook from backup: ${backupPath}`);
  } else {
    unlinkSync(hookPath);
    console.log(`  Removed: ${hookPath}`);
  }

  return "removed";
}
