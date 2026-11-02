/**
 * Directories SkillsGuard never reads and never reports: VCS metadata and its
 * own output. Nothing loads code from them.
 *
 * Shared by the scanner (which skips them while walking) and watch mode (which
 * ignores file events inside them), so the two cannot drift apart. Every other
 * directory, hidden or not, is either scanned or reported as unreviewed, so a
 * change inside it must trigger a re-scan.
 */
export const SILENT_SKIP_DIRS: ReadonlySet<string> = new Set<string>([
  ".git",
  ".skillsguard", // baseline + config artifacts — never scan our own output
]);

/** True when any segment of a relative path is a silently skipped directory. */
export function isSilentPath(relPath: string): boolean {
  return relPath.split(/[/\\]/).some((segment) => SILENT_SKIP_DIRS.has(segment));
}
