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
    // Credential and config dotdirs — expanded to cover cloud CLIs and container tooling
    /[\/\\]\.(ssh|gnupg|aws|azure|config|gemini|npm|cache|local|kube|docker|terraform\.d)\b/,
    // gcloud stores credentials under .config/gcloud but some paths reference it directly
    /[\/\\]\.gcloud[\/\\]/,
    // Standalone sensitive dotfiles
    /[\/\\]\.bash_history$/,
    /[\/\\]\.(bashrc|zshrc|profile|bash_profile)$/,
    // Sensitive filenames that should never be scanned
    /\b(passwd|shadow|git-credentials|npmrc|pypirc|netrc|vault-token|pgpass)\b/,
  ];
  if (sensitivePatterns.some((pat) => pat.test(resolved))) {
    return false;
  }

  return true;
}
