import type { Rule } from "../types.js";

export const OBFUSCATION_RULES: readonly Rule[] = [
  {
    id: "OB-001",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /echo\s+['"A-Za-z0-9+/=]{20,}['"]\s*\|\s*base64\s+(-d|--decode)/i,
    message: "Obfuscation: base64-encoded payload piped to base64 decode",
  },
  {
    id: "OB-002",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /printf\s+'(\\x[0-9a-fA-F]{2}){6,}'/i,
    message: "Obfuscation: hex-escaped payload in printf — shellcode or hidden command",
  },
  {
    id: "OB-003",
    category: "obfuscation",
    severity: "MEDIUM",
    pattern: /\$\{\s*[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*-\s*['"][^'"]*['"]\s*\}\s*\|\s*(bash|sh|python|node)/i,
    message: "Obfuscation: shell parameter expansion used to hide pipe-to-shell pattern",
  },
  {
    id: "OB-004",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\)|\batob\s*\(|\bString\.fromCharCode\b|\bnew\s+Function\s*\(/i,
    message: "Obfuscation/Dynamic Execution: JS/TS base64 decoding, char codes or dynamic function creation",
  },
  {
    id: "OB-005",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /\bgetattr\s*\(\s*[a-zA-Z0-9_]+\s*,\s*['"]__\w+__['"]\s*\)|\b__import__\s*\(|\bbytes\.fromhex\s*\(|\bbase64\.b64decode\s*\(/i,
    message: "Obfuscation: Python dynamic attribute access, dynamic import or base64/hex decoding",
  },
];
