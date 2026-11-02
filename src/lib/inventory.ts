/**
 * SkillsGuard — inventory of directories that are not scanned rule-by-rule.
 *
 * Dependency trees, virtualenvs and toolchain caches are too large and too
 * third-party to run the rule set over, but skipping them silently lets a
 * skill park code there (a decoy source file that imports a payload from
 * `venv/`, `node_modules/`, ...). This answers the one question that matters:
 * does the directory hold anything a runtime could load as code? The caller
 * turns a "yes" into an unreviewed-content finding instead of a clean pass.
 */

import { readdir } from "node:fs/promises";
import { join, extname } from "node:path";
import { BYTECODE_EXTENSIONS } from "./bytecode.js";
import { NATIVE_EXTENSIONS, SCRIPT_EXTENSIONS, sniffFile } from "./filekind.js";

/** Entries visited before giving up. A directory this big cannot be vouched for. */
export const MAX_INVENTORY_ENTRIES = 25_000;

// Extensions that are plainly data. Anything else (including no extension) has
// its header checked, so a binary renamed to `.dat` is still found.
const INERT_EXTENSIONS = new Set<string>([
  ".md", ".markdown", ".txt", ".rst", ".json", ".map", ".yaml", ".yml", ".toml",
  ".ini", ".cfg", ".conf", ".lock", ".html", ".htm", ".xml", ".css", ".scss",
  ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
  ".woff", ".woff2", ".ttf", ".otf", ".eot", ".pdf", ".csv", ".tsv", ".log",
  ".sample", ".license",
]);

export interface Inventory {
  /** Absolute path of one executable file found, or null if none. */
  readonly example: string | null;
  /** True when the tree could not be fully inventoried (size cap or unreadable subdirectory). */
  readonly truncated: boolean;
}

export async function findExecutableContent(root: string): Promise<Inventory> {
  const queue: string[] = [root];
  let visited = 0;
  let truncated = false;

  while (queue.length > 0) {
    const dir = queue.pop()!;
    let entries: { name: string; isDirectory(): boolean; isFile(): boolean }[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch (err: unknown) {
      if (!(err instanceof Error && "code" in err && err.code === "ENOENT")) truncated = true;
      continue;
    }

    for (const entry of entries) {
      if (++visited > MAX_INVENTORY_ENTRIES) return { example: null, truncated: true };
      const full = join(dir, entry.name);

      // Dirent flags are lstat-based: symlinks are neither, so they are never
      // followed (no loops, no escaping the tree). Their targets are visited
      // as ordinary entries when they live inside it.
      if (entry.isDirectory()) {
        queue.push(full);
        continue;
      }
      if (!entry.isFile()) continue;

      const ext = extname(entry.name).toLowerCase();
      if (SCRIPT_EXTENSIONS.has(ext) || BYTECODE_EXTENSIONS.has(ext) || NATIVE_EXTENSIONS.has(ext)) {
        return { example: full, truncated };
      }
      if (INERT_EXTENSIONS.has(ext)) continue;
      try {
        const sniff = await sniffFile(full);
        if (sniff.format !== null || sniff.shebang) return { example: full, truncated };
      } catch {
        // Unreadable file: nothing to learn from it here.
      }
    }
  }
  return { example: null, truncated };
}
