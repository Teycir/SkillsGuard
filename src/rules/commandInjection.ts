import type { Rule } from "../types.js";

export const COMMAND_INJECTION_RULES: readonly Rule[] = [
  {
    id: "CI-001",
    category: "command-injection",
    severity: "CRITICAL",
    pattern: /\beval\b[^#\n]*\$\(/i,
    message: "Command injection: eval with command substitution — classic code execution",
  },
  {
    id: "CI-002",
    category: "command-injection",
    severity: "CRITICAL",
    pattern: /\beval\b[^#\n]*(base64|hex|decode|echo|printf)/i,
    message: "Command injection: eval decoding encoded payload — obfuscated execution",
  },
  {
    id: "CI-003",
    category: "command-injection",
    severity: "HIGH",
    pattern: /\b(bash|sh|zsh|ksh|fish)\s+-c\s+['"]/i,
    message: "Command injection: shell invoked with inline command string",
  },
  {
    id: "CI-004",
    category: "command-injection",
    severity: "HIGH",
    pattern: /`[^`]{0,200}(rm|mv|cp|chmod|chown|dd|mkfs|kill|wget|curl)[^`]{0,200}`/i,
    message: "Command injection: backtick substitution running destructive/network commands",
  },
  {
    id: "CI-005",
    category: "command-injection",
    severity: "HIGH",
    pattern: /\bos\.system\s*\(|subprocess\.(call|run|Popen)\s*\(\s*['"]/i,
    message: "Command injection: Python subprocess/os.system with hardcoded command",
  },
  {
    id: "CI-006",
    category: "command-injection",
    severity: "MEDIUM",
    pattern: /\bexec\s*\(\s*(user|input|request|query|param|data)\b/i,
    message: "Command injection: exec() called with user-controlled input",
  },
  {
    id: "CI-007",
    category: "command-injection",
    severity: "HIGH",
    // The second alternative uses a negative lookbehind for `.` so that
    // method calls like regexp.exec(str), db.exec(query), pool.spawn() are
    // NOT flagged — only top-level function calls (no receiver) are caught.
    pattern: /\bchild_process\.(exec|spawn|fork|execFile|execSync|spawnSync|execFileSync)\s*\(|(?<![\w.])\b(exec|spawn|fork|execFile|execSync|spawnSync|execFileSync)\s*\(/i,
    message: "Command execution: Node.js child_process command invocation pattern",
  },
  {
    id: "CI-008",
    category: "command-injection",
    severity: "HIGH",
    pattern: /Bun\.(spawn|spawnSync)\s*\(/i,
    message: "Command execution: Bun.spawn command execution pattern",
  },
  {
    id: "CI-009",
    category: "command-injection",
    severity: "HIGH",
    pattern: /\b(execa|zx)\s*\(/i,
    message: "Command execution: third-party shell execution wrapper (execa/zx)",
  },
  {
    id: "CI-010",
    category: "command-injection",
    severity: "HIGH",
    pattern: /\bos\.(popen|spawn[lpve]*)\s*\(|\bpty\.spawn\s*\(/i,
    message: "Command execution: Python os.popen/spawn or pty.spawn",
  },
];
