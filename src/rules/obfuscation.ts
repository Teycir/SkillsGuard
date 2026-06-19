import type { Rule } from "../types.js";

export const OBFUSCATION_RULES: readonly Rule[] = [
  {
    id: "OB-001",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /echo\s+['"A-Za-z0-9+/=]{20,}['"]\s*\|\s*base64\s+(-d|--decode)/i,
    message: "Obfuscation: base64-encoded payload piped to base64 decode",
    skipCommentLines: true,
  },
  {
    id: "OB-002",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /printf\s+'(\\x[0-9a-fA-F]{2}){6,}'/i,
    message: "Obfuscation: hex-escaped payload in printf — shellcode or hidden command",
    skipCommentLines: true,
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
    severity: "LOW",
    // ponytail: downgraded MEDIUM -> LOW. Buffer.from(x, 'base64') alone is extremely
    // common in legit code (JWT decoding, image/file handling) and was firing
    // constantly. The real signal — decode PAIRED with exec/network — is now OB-004-CTX
    // below at HIGH. This rule stays as a low-noise informational flag.
    message: "Obfuscation/Dynamic Execution: JS/TS base64 decoding, char codes or dynamic function creation — review for legitimacy",
    pattern: /\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\)|\batob\s*\(|\bString\.fromCharCode\b|\bnew\s+Function\s*\(/i,
    skipCommentLines: true,
  },
  {
    id: "OB-004-CTX",
    category: "obfuscation",
    severity: "HIGH",
    // ponytail: companion to OB-004. Fires only when a decode call (Buffer.from base64,
    // atob, fromCharCode) appears together with a consequence (new Function, eval, exec,
    // spawn, or a network call) within ~200 chars — covers both orderings, since
    // `new Function(atob(x))` puts the consequence call *around* the decode, not after it.
    pattern:
      /(?:\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\)|\batob\s*\(|\bString\.fromCharCode\b)[\s\S]{0,200}(?:\bnew\s+Function\s*\(|\beval\s*\(|\bexec\s*\(|\bspawn\s*\(|\bfetch\s*\(|\baxios\b|\bhttp\.request\s*\(|\.then\s*\(\s*\(?\s*\)?\s*=>)|(?:\bnew\s+Function\s*\(|\beval\s*\(|\bexec\s*\(|\bspawn\s*\(|\bfetch\s*\(|\baxios\b|\bhttp\.request\s*\(|\.then\s*\(\s*\(?\s*\)?\s*=>)[\s\S]{0,200}(?:\bBuffer\.from\s*\([^,]+,\s*['"]base64['"]\s*\)|\batob\s*\(|\bString\.fromCharCode\b)/i,
    message: "Obfuscation: base64/charcode decode paired with dynamic execution or a network call — decode-then-act pattern",
    remediation: "A decoded payload that is immediately executed (eval, new Function, exec, spawn) or sent over the network is a strong obfuscation signal, unlike a bare decode used for JWTs or file parsing. Review what the decoded content actually contains.",
  },
  {
    id: "OB-005",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /\bgetattr\s*\(\s*[a-zA-Z0-9_]+\s*,\s*['"]__\w+__['"]\s*\)|\b__import__\s*\(|\bbytes\.fromhex\s*\(|\bbase64\.b64decode\s*\(/i,
    message: "Obfuscation: Python dynamic attribute access, dynamic import or base64/hex decoding",
  },
  // NOTE: zero-width/invisible Unicode steganography is covered by
  // ADV-002, ADV-003, and ADV-005 in advancedAttacks.ts (previously
  // duplicated here as OB-006 — removed to avoid double-counting in
  // risk scoring).
  {
    id: "OB-007",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /<!--[\s\S]{0,500}(ignore|system|instruction|disregard|forget|override)[\s\S]{0,500}-->/i,
    message: "HTML comment injection: prompt-injection keywords hidden in HTML comments within Markdown",
  },
];
