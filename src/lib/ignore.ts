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

// ─── Placeholder / stopword detection ────────────────────────────────────────

/**
 * Well-known placeholder/example strings from gitleaks, TruffleHog, and GitLab
 * secret-scanner allowlists.  If a matched line contains any of these as a
 * substring (case-insensitive), the match is almost certainly from docs,
 * test fixtures, or README examples rather than live malicious code.
 *
 * Criteria for inclusion:
 *   - Must be a word/phrase that virtually never appears in live attack code
 *   - Must have a clear, documented track record of causing FPs in SAST tools
 *   - Must not risk suppressing real findings (no generic words like "test")
 */
const PLACEHOLDER_PATTERNS = [
  /\bexample\b/i,
  /\bplaceholder\b/i,
  /\bdummy\b/i,
  /\bfake\b/i,
  /\bchangeme\b/i,
  /\byour[_-]?(?:token|key|secret|password|api[_-]?key)\b/i,
  /<(?:your[_-]?)?(?:token|key|secret|password|api[_-]?key)>/i,
  /\bREPLACE(?:_WITH|_ME|_THIS)?\b/,
  /xxxx+/i,
  /0000+/,
  /1234(?:56)?/,
  /\bsample\b/i,
];

/**
 * Returns true if the line is almost certainly a documentation example or
 * placeholder, not live code.  Only used for rules where placeholders are a
 * dominant FP source (supply-chain, secret-harvesting, network).
 */
export function isPlaceholderLine(line: string): boolean {
  return PLACEHOLDER_PATTERNS.some((p) => p.test(line));
}

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
