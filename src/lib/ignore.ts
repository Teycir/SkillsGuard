/**
 * Checks if a given line contains a linter suppression comment (e.g., skillsguard-ignore)
 * targeting either all rules or a specific rule ID.
 */
export function shouldIgnoreLine(line: string, ruleId: string): boolean {
  if (!line.includes("skillsguard-ignore")) return false;
  const hasSpecificIgnore = /skillsguard-ignore[:\s]+[A-Za-z0-9-]+/.test(line);
  return (
    !hasSpecificIgnore ||
    line.includes(`skillsguard-ignore ${ruleId}`) ||
    line.includes(`skillsguard-ignore: ${ruleId}`)
  );
}
