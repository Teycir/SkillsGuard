import type { Rule } from "../types.js";

export const COMMAND_INJECTION_RULES: readonly Rule[] = [
  {
    id: "CI-001",
    category: "command-injection",
    severity: "CRITICAL",
    pattern: /\beval\b[^#\n]*\$\(/i,
    message: "Command injection: eval with command substitution — classic code execution",
    remediation: "Remove eval entirely. If dynamic execution is required, use an explicit allowlist of permitted commands rather than evaluating arbitrary input.",
    // READMEs explaining why eval is bad are the #1 FP source for this rule.
    skipCommentLines: true,
  },
  {
    id: "CI-002",
    category: "command-injection",
    severity: "CRITICAL",
    pattern: /\beval\b[^#\n]*(base64|hex|decode|echo|printf)/i,
    message: "Command injection: eval decoding encoded payload — obfuscated execution",
    remediation: "Encoded payloads inside eval are a strong indicator of malicious obfuscation. Remove the eval and the encoding layer; if the content is legitimate, inline it as a plain string.",
    skipCommentLines: true,
  },
  {
    id: "CI-003",
    category: "command-injection",
    severity: "HIGH",
    // Extended to catch unquoted -c arguments: $VAR, $(cmd), ${var} — not just quoted strings.
    // After -c, match a quote followed by non-whitespace OR $ followed by word-char/paren/brace.
    pattern: /\b(bash|sh|zsh|ksh|fish)\s+-c\s+(['"]\S|\$[\w({])/i,
    message: "Command injection: shell invoked with inline command string (quoted or variable)",
    skipCommentLines: true,
  },
  {
    id: "CI-004",
    category: "command-injection",
    severity: "HIGH",
    pattern: /`[^`]{0,200}(rm|mv|cp|chmod|chown|dd|mkfs|kill|wget|curl)[^`]{0,200}`/i,
    message: "Command injection: backtick substitution running destructive/network commands",
    skipCommentLines: true,
  },
  {
    id: "CI-005",
    category: "command-injection",
    severity: "HIGH",
    // Require the argument to open with a quote (hardcoded string) to match the
    // message text and avoid firing on subprocess.call(variable, ...) calls.
    pattern: /\bos\.system\s*\(\s*['"]|subprocess\.(call|run|Popen)\s*\(\s*['"]/i,
    message: "Command injection: Python subprocess/os.system with hardcoded command string",
    skipCommentLines: true,
  },
  {
    id: "CI-006",
    category: "command-injection",
    severity: "MEDIUM",
    pattern: /\bexec\s*\(\s*(user|input|request|query|param|data)\b/i,
    message: "Command injection: exec() called with user-controlled input",
    skipCommentLines: true,
  },
  {
    id: "CI-007",
    category: "command-injection",
    severity: "HIGH",
    // The second alternative uses a negative lookbehind for `.` and word chars
    // so that method calls like regexp.exec(str), db.exec(query), pool.spawn()
    // are NOT flagged — only top-level function calls (no receiver) are caught.
    pattern: /\bchild_process\.(exec|spawn|fork|execFile|execSync|spawnSync|execFileSync)\s*\(|(?<![\w.])\b(exec|spawn|fork|execFile|execSync|spawnSync|execFileSync)\s*\(/i,
    message: "Command execution: Node.js child_process command invocation pattern",
    skipCommentLines: true,
  },
  {
    id: "CI-008",
    category: "command-injection",
    severity: "HIGH",
    pattern: /Bun\.(spawn|spawnSync)\s*\(/i,
    message: "Command execution: Bun.spawn command execution pattern",
    skipCommentLines: true,
  },
  {
    id: "CI-009",
    category: "command-injection",
    severity: "HIGH",
    pattern: /\b(execa|zx)\s*\(/i,
    message: "Command execution: third-party shell execution wrapper (execa/zx)",
    skipCommentLines: true,
  },
  {
    id: "CI-010",
    category: "command-injection",
    severity: "HIGH",
    pattern: /\bos\.(popen|spawn[lpve]*)\s*\(|\bpty\.spawn\s*\(/i,
    message: "Command execution: Python os.popen/spawn or pty.spawn",
    skipCommentLines: true,
  },
  {
    id: "CI-011",
    category: "command-injection",
    severity: "HIGH",
    // python/python3/pypy -c with quoted or variable argument — mirrors CI-003 for Python.
    pattern: /\b(python3?|pypy)\s+-c\s+(['"]\S|\$[\w({])/i,
    message: "Command injection: Python invoked with inline -c command string",
    skipCommentLines: true,
  },
];
