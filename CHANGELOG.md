# Changelog

All notable changes to SkillsGuard are documented here.  
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).  
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

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

---

## [Unreleased]

_Nothing pending._
