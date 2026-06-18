import type { Rule } from "../types.js";

export const EXFILTRATION_RULES: readonly Rule[] = [
  {
    id: "EX-001",
    category: "exfiltration",
    severity: "CRITICAL",
    pattern: /\b(curl|wget|fetch|axios|got|http\.get|https\.get)\b[^#\n]*\b(env|secret|token|key|password|credential|api[-_]?key)\b/i,
    message: "Exfiltration: network request combined with secrets/env access",
  },
  {
    id: "EX-002",
    category: "exfiltration",
    severity: "CRITICAL",
    pattern: /\$\{?\s*(HOME|USER|PATH|API_KEY|SECRET|TOKEN|PASSWORD|ANTHROPIC|OPENAI)[^}]*\}?[^#\n]*(curl|wget|fetch|http)/i,
    message: "Exfiltration: env variable interpolated into a network call",
  },
  {
    id: "EX-003",
    category: "exfiltration",
    severity: "HIGH",
    pattern: /\b(curl|wget)\b[^#\n]*(-d|--data|--data-raw|--data-binary|--data-urlencode)\b[^#\n]*(cat\s+\/|<\s*\/|\$\()/i,
    message: "Exfiltration: curl/wget POSTing file content to a remote server",
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
    severity: "MEDIUM",
    pattern: /\b(http|https)\.request\s*\(|\bnet\.(createConnection|connect)\s*\(|\btls\.connect\s*\(/i,
    message: "Exfiltration: low-level Node.js network/socket communication path",
  },
];
