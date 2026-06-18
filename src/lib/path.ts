import { resolve } from "node:path";
import { homedir } from "node:os";
import { cwd } from "node:process";

/**
 * Validates if a target path is safe to scan. Enforces canonicalization,
 * size boundaries, and prevents traversing outside permitted workspace scopes
 * or into sensitive folders.
 */
export function isSafePath(targetPath: string): boolean {
  if (targetPath.length > 4096) return false;
  const resolved = resolve(targetPath);
  const home = resolve(homedir());
  const currentDir = resolve(cwd());
  const insideHome = resolved.startsWith(home);
  const insideCwd = resolved.startsWith(currentDir);

  if (!insideHome && !insideCwd) {
    return false;
  }

  const sensitivePatterns = [
    /[\/\\]\.(ssh|gnupg|aws|config|gemini|npm|cache|local)\b/,
    /[\/\\]\.bash_history$/,
    /[\/\\]\.(bashrc|zshrc|profile|bash_profile)$/,
    /\b(passwd|shadow|git-credentials|npmrc|pypirc|netrc)\b/,
  ];
  if (sensitivePatterns.some((pat) => pat.test(resolved))) {
    return false;
  }

  return true;
}
