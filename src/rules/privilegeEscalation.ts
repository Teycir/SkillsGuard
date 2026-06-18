import type { Rule } from "../types.js";

export const PRIVILEGE_ESCALATION_RULES: readonly Rule[] = [
  {
    id: "PE-001",
    category: "privilege-escalation",
    severity: "CRITICAL",
    pattern: /\bsudo\s+-S\b|\bsudo\s+--stdin\b/i,
    message: "Privilege escalation: sudo with stdin flag — password piped programmatically",
    skipCommentLines: true,
  },
  {
    id: "PE-002",
    category: "privilege-escalation",
    severity: "HIGH",
    pattern: /\bchmod\s+[0-9]*[67][0-9][0-9]\s+(\/bin\/|\/usr\/bin\/|\/sbin\/)/i,
    message: "Privilege escalation: chmod on system binaries",
    skipCommentLines: true,
  },
  {
    id: "PE-003",
    category: "privilege-escalation",
    severity: "HIGH",
    pattern: /\bchown\s+root\b/i,
    message: "Privilege escalation: chown root on a file",
    skipCommentLines: true,
  },
  {
    id: "PE-004",
    category: "privilege-escalation",
    severity: "MEDIUM",
    pattern: /\/etc\/sudoers/i,
    message: "Privilege escalation: sudoers file access",
  },
  {
    id: "PE-005",
    category: "privilege-escalation",
    severity: "HIGH",
    pattern: /\bprocess\.(setuid|setgid|setegid|seteuid)\s*\(|(?<!\.)\b(setuid|setgid|setegid|seteuid)\s*\(|\bos\.(setuid|setgid|seteuid|setegid)\s*\(/i,
    message: "Privilege escalation: setting system user or group IDs programmatically",
  },
];
