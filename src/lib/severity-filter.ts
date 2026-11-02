/**
 * SkillsGuard — minimum-severity threshold (--min-severity / min_severity)
 *
 * One implementation shared by the CLI, watch mode and the MCP server so they
 * cannot disagree about what a threshold hides.
 */

import { SEVERITY_RANK } from "../types.js";
import type { Finding } from "../types.js";

/**
 * Keep findings at or above `min`. An unrecognised level keeps everything.
 *
 * Findings flagged `unanalyzed` are never dropped, whatever their severity.
 * They do not describe something found in the skill, they describe something
 * that could not be checked, and a threshold must not turn "not reviewed" into
 * "No issues found". To silence one on purpose use ignoreRules.
 */
export function applyMinSeverity(findings: readonly Finding[], min: string): Finding[] {
  const minRank = (SEVERITY_RANK as Record<string, number>)[min] ?? 0;
  return findings.filter((f) => f.unanalyzed === true || SEVERITY_RANK[f.severity] >= minRank);
}
