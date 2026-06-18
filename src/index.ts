/**
 * SkillsGuard — public library API
 * Import this when using SkillsGuard as a module rather than a CLI tool.
 */

export { scan } from "./scanner.js";
export { RULES } from "./rules.js";
export { findDecodedBlobs } from "./decode.js";
export { reportHuman, reportJson } from "./report.js";
export type { Rule, Finding, ScanResult, Severity } from "./types.js";
export { setupMcp } from "./setup.js";
