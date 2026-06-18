import type { Rule } from "../types.js";

export const NETWORK_RULES: readonly Rule[] = [
  {
    id: "NW-001",
    category: "network",
    severity: "HIGH",
    pattern: /\b(curl|wget)\b[^#\n]*(--silent|-s)\s+https?:\/\/(?!.*\.anthropic\.com|.*\.github\.com|.*\.githubusercontent\.com|.*\.npmjs\.com|.*\.pypi\.org)[^#\n]*\|\s*(bash|sh|python|node)/i,
    message: "Network: silently fetching a script from an external host and piping to shell",
  },
  {
    id: "NW-002",
    category: "network",
    severity: "HIGH",
    pattern: /\bngrok\b|\bserveo\b|\blocalxpose\b|\btailscale\b[^#\n]*--ssh/i,
    message: "Network: tunnel tool detected — may be used to expose internal services",
  },
  {
    id: "NW-003",
    category: "network",
    severity: "MEDIUM",
    pattern: /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/i,
    message: "Network: raw IP address URL — suspicious, avoids DNS-based blocklists",
  },
  {
    id: "NW-004",
    category: "network",
    severity: "HIGH",
    pattern: /\b(curl|wget)\b[^#\n]*\.onion\b/i,
    message: "Network: Tor .onion address in curl/wget — covert exfiltration channel",
  },
];
