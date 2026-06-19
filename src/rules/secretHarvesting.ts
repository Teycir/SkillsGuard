import type { Rule } from "../types.js";

export const SECRET_HARVESTING_RULES: readonly Rule[] = [
  {
    id: "SH-001",
    category: "secret-harvesting",
    severity: "CRITICAL",
    pattern: /\benv\b[^#\n]*(ANTHROPIC|OPENAI|AWS|AZURE|GOOGLE)[^#\n]*(curl|wget|fetch|http)/i,
    message: "Secret harvesting: reading AI/cloud provider API key and making a network call",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
  {
    id: "SH-002",
    category: "secret-harvesting",
    severity: "HIGH",
    pattern: /cat\s+~\/\.(aws\/credentials|config\/gcloud|kube\/config|ssh\/id_)/i,
    message: "Secret harvesting: reading cloud/SSH credentials from well-known paths",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
  {
    id: "SH-003",
    category: "secret-harvesting",
    severity: "HIGH",
    pattern: /printenv\s*\|\s*(grep|awk|sed)[^#\n]*(curl|wget|http)/i,
    message: "Secret harvesting: dumping env vars, filtering, then sending over network",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
  {
    id: "SH-004",
    category: "secret-harvesting",
    severity: "CRITICAL",
    // cat .env (or any .env variant) followed by a network exfiltration tool on the same line.
    // Catches the single most common dotenv-exfil pattern without requiring a provider keyword.
    pattern: /\bcat\s+[^#\n]*\.env\b[^#\n]*(curl|wget|fetch|http|nc\b)/i,
    message: "Secret harvesting: reading .env file and sending its contents over the network",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
];
