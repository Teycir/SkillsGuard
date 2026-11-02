/**
 * Checks if a given line contains a linter suppression comment (e.g., skillsguard-ignore)
 * targeting either all rules or a specific rule ID.
 * ponytail: word-boundary match prevents PI-00 from suppressing PI-001..PI-009
 */
export function shouldIgnoreLine(line: string, ruleId: string): boolean {
  if (!line.includes("skillsguard-ignore")) return false;
  const hasSpecificIgnore = /skillsguard-ignore[:\s]+[A-Za-z0-9-]+/.test(line);
  if (!hasSpecificIgnore) return true; // bare 'skillsguard-ignore' → suppress all
  // Check for word-boundary match: "PI-001" exactly, not substring of "PI-0010"
  const wordBoundaryRe = new RegExp(`skillsguard-ignore[:\\s]+${ruleId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
  return wordBoundaryRe.test(line);
}

// ─── Comment-line detection ───────────────────────────────────────────────────

/**
 * Returns true if the entire line is a comment in any of the supported
 * languages/formats.  Used to suppress rules that fire overwhelmingly on
 * example code in README / documentation sections.
 *
 * Only lines where the FIRST non-whitespace token is a comment marker are
 * considered pure comments.  Inline trailing comments like:
 *   chmod 777 /usr/bin/foo  # bad example
 * are NOT suppressed — the command is live code.
 *
 * Supported prefixes:
 *   Shell / Python / Ruby / YAML / TOML / Makefile  →  #
 *   JS / TS / Java / C / Rust / Go one-line         →  //
 *   C-style block comment continuation              →  * (inside /* *\/)
 *   HTML / XML comment                              →  <!-- ... -->
 *   Markdown blockquote (document prose)            →  >
 */
export function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  return (
    t.startsWith("#") ||
    t.startsWith("//") ||
    t.startsWith("* ") ||
    t.startsWith("*/") ||
    t.startsWith("/*") ||
    t.startsWith("<!--") ||
    t.startsWith(">")
  );
}

// ─── Placeholder detection ───────────────────────────────────────────────────
// Lives in ./placeholder.ts. The old line-level check (skip the whole line when
// a word such as "example" appeared anywhere on it) was removed on purpose: an
// attacker can append that word to any payload.

// ─── Test / fixture path detection ───────────────────────────────────────────

/**
 * Returns true if the file path looks like a test or example file.
 * Used for downgrading severity rather than suppressing.
 *
 * Path segments that qualify:
 *   test, tests, spec, specs, __tests__, fixture, fixtures,
 *   example, examples, sample, samples, mock, mocks, stub, stubs,
 *   demo, demos
 */
const TEST_PATH_RE =
  /(?:^|[/\\])(?:__tests__|tests?|specs?|fixtures?|examples?|samples?|mocks?|stubs?|demos?)(?:[/\\]|$)/i;

export function isTestFilePath(filePath: string): boolean {
  return TEST_PATH_RE.test(filePath);
}

/**
 * Extensions of files that cannot execute on their own: documentation and
 * plain data. Only these may have their severity lowered because of where
 * they live.
 */
const NON_EXECUTABLE_EXTENSIONS = new Set<string>([
  ".md", ".markdown", ".mdx", ".rst", ".txt",
  ".json", ".yaml", ".yml", ".csv",
]);

/**
 * Returns true when a finding in this file may be downgraded to INFO.
 *
 * A directory name never decides that code is harmless: a payload placed in
 * examples/run.sh or tests/helper.py runs exactly like one anywhere else, and
 * "put it under tests/" would otherwise be a one-step bypass (INFO, 0/100).
 * So the downgrade needs both a test-like path AND a file that cannot execute
 * by itself. Code files, extensionless scripts and unknown extensions keep
 * their full severity.
 */
export function isDampenedPath(filePath: string): boolean {
  if (!isTestFilePath(filePath)) return false;
  const base = filePath.split(/[/\\]/).pop() ?? "";
  const dot = base.lastIndexOf(".");
  if (dot <= 0) return false; // no extension, or a dotfile: treat as code
  return NON_EXECUTABLE_EXTENSIONS.has(base.slice(dot).toLowerCase());
}
