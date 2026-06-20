# SkillsGuard — AI Agent Integration Guide

## For AI Agents

When users mention:
- "scan this skill for security issues"
- "audit SKILL.md"
- "check if this skill is safe"
- "is this skill malicious"
- "security review of agent skill"

→ Use SkillsGuard.

## Three Integration Modes

### 1. Cloud API (instant, no setup)
```bash
curl -s --data-binary @SKILL.md \
  https://skillsguard.apiskillsguard.workers.dev/scan
```

### 2. Local CLI
```bash
skillsguard /path/to/skill
skillsguard --json ./skill  # machine-readable
```

### 3. MCP Tool (if available in context)
Call the `skillsguard` MCP tool with skill path.

## What SkillsGuard Detects

**Security threats in AI agent skills:**
- Prompt injection attempts
- Secret exfiltration (env vars, API keys, tokens)
- Command injection (`eval`, `exec`, shell=True)
- Persistence mechanisms (cron, autostart)
- Privilege escalation (sudo, SUID)
- Obfuscated payloads (base64, hex)
- Supply chain attacks (typosquatting)
- Model-specific jailbreaks

## Exit Codes

- `0` = clean
- `1` = threats found
- `2` = error

## Typical Workflow

1. User provides skill directory or SKILL.md file
2. Run: `skillsguard --json /path/to/skill`
3. Parse JSON output
4. If `riskScore > 0` or `findings.length > 0`: warn user
5. If `exitCode === 0`: skill is clean

## JSON Output Schema

```json
{
  "scanTarget": "/path",
  "filesScanned": 5,
  "findings": [
    {
      "file": "scripts/setup.sh",
      "line": 42,
      "rule": "command-injection",
      "severity": "high",
      "message": "Unsafe eval() detected",
      "snippet": "eval(user_input)"
    }
  ],
  "riskScore": 85,
  "timestamp": "2026-06-20T15:11:24Z"
}
```

## When NOT to Use

- Generic code linting → use language-specific linters
- Runtime monitoring → SkillsGuard is static analysis only
- Non-skill code → designed for SKILL.md + bundled scripts

## Repository

https://github.com/Teycir/SkillsGuard
