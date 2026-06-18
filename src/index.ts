/**
 * SkillsGuard — public library API
 * Import this when using SkillsGuard as a module rather than a CLI tool.
 */

export { scan } from "./scanner.js";
export { scanText, resolveCustomRule, computeRiskScore } from "./scanner.js";
export { RULES } from "./rules.js";
export { MODEL_SPECIFIC_RULES } from "./rules/modelSpecific.js";
export { findDecodedBlobs } from "./decode.js";
export { reportHuman, reportJson } from "./report.js";
export { reportSarif, toSarif } from "./sarif.js";
export { loadConfig } from "./config.js";
export { scanGitDiff } from "./diff.js";
export type { Rule, Finding, ScanResult, Severity, CustomRule, ScanOptions, RiskScore } from "./types.js";
export type { SkillsGuardConfig } from "./config.js";
export type { GitDiffOptions } from "./diff.js";
export { setupMcp } from "./setup.js";
export { installHook, uninstallHook } from "./hook.js";
export type { HookOptions, HookResult } from "./hook.js";
export { isSafePath } from "./lib/path.js";
export { shouldIgnoreLine } from "./lib/ignore.js";
export { runConcurrent } from "./lib/concurrency.js";
