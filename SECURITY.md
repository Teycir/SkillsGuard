# Security Policy

## Reporting Security Vulnerabilities

If you discover a security vulnerability in SkillsGuard itself, please report it via:

- **GitHub Security Advisories**: https://github.com/Teycir/SkillsGuard/security/advisories/new
- **Email**: Create an issue and we'll provide a secure contact method

Please do **not** open public issues for security vulnerabilities.

## What SkillsGuard Scans For

SkillsGuard is a static security scanner for AI agent skills. It detects:

- **Prompt injection** — Instructions that hijack agent behavior
- **Exfiltration** — Secret leaks via curl, DNS, GitHub API
- **Command injection** — `eval()`, `exec()`, shell=True, `os.system()`
- **Persistence** — Cron jobs, .bashrc mods, systemd services
- **Privilege escalation** — sudo, SUID, container escapes
- **Obfuscation** — Base64/hex/URL-encoded payloads
- **Supply chain** — Typosquatting, suspicious dependencies
- **Model jailbreaks** — DAN prompts, refusal overrides

## False Positives

SkillsGuard uses pattern matching and may flag legitimate code. Review findings manually.

To suppress false positives:
1. Add `skillsguard.config.json` with `ignorePatterns`
2. Generate baseline: `skillsguard --baseline`
3. Use `// skillsguard-ignore` comments in code

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Security Updates

Check [CHANGELOG.md](CHANGELOG.md) for security-related updates.
