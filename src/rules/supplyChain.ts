import type { Rule } from "../types.js";

export const SUPPLY_CHAIN_RULES: readonly Rule[] = [
  {
    id: "SC-001",
    category: "supply-chain",
    severity: "HIGH",
    pattern: /\b(npm|yarn|pnpm)\s+install\b[^#\n]*https?:\/\//i,
    message: "Supply chain: npm install from a raw URL (not the registry)",
  },
  {
    id: "SC-002",
    category: "supply-chain",
    severity: "HIGH",
    pattern: /\bpip\s+install\b[^#\n]*https?:\/\//i,
    message: "Supply chain: pip install from a raw URL",
  },
  {
    id: "SC-003",
    category: "supply-chain",
    severity: "HIGH",
    pattern: /\bcargo\s+add\b[^#\n]*--git\s+https?:\/\/(?!github\.com|gitlab\.com|bitbucket\.org)/i,
    message: "Supply chain: cargo add from an unrecognized git host",
  },
  {
    id: "SC-004",
    category: "supply-chain",
    severity: "MEDIUM",
    pattern: /\b(npm|pip|cargo)\b[^#\n]*--registry\s+https?:\/\/(?!registry\.npmjs\.org|pypi\.org|static\.crates\.io)/i,
    message: "Supply chain: package manager pointed at a non-standard registry",
  },
  {
    id: "SC-005",
    category: "supply-chain",
    severity: "CRITICAL",
    pattern: /postinstall['":\s]+[^#\n]*(curl|wget|bash|sh|python|node)[^#\n]*(https?:\/\/|http:\/\/)/i,
    message: "Supply chain: postinstall script fetches code from the internet",
  },
  {
    id: "SC-006",
    category: "supply-chain",
    severity: "HIGH",
    pattern: /"(preinstall|postinstall|prepublish|prepare|prepublishOnly)"\s*:\s*"[^"]*(curl|wget|bash|sh|node|python)/i,
    message: "Supply chain: package.json script hook executes external scripts or commands",
  },
  {
    id: "SC-007",
    category: "supply-chain",
    severity: "HIGH",
    pattern: /\b(twittter|githuub|googel|amazonw|npm-install-|nppm|pyypi)\b/i,
    message: "Supply chain: suspicious lookalike domain or package name (typosquatting)",
  },
];
