import type { Rule } from "../types.js";

export const PERSISTENCE_RULES: readonly Rule[] = [
  {
    id: "PS-001",
    category: "persistence",
    severity: "HIGH",
    pattern: /crontab\s+-[el]|crontab\s+<|\/etc\/cron\./i,
    message: "Persistence: modifying crontab or system cron — installing persistent task",
  },
  {
    id: "PS-002",
    category: "persistence",
    severity: "HIGH",
    pattern: /echo[^#\n]+(>>|>)\s*(~\/\.(bashrc|zshrc|profile|bash_profile)|\/etc\/(profile|environment))/i,
    message: "Persistence: appending to shell startup file",
  },
  {
    id: "PS-003",
    category: "persistence",
    severity: "HIGH",
    pattern: /~\/\.config\/systemd|\/etc\/systemd\/system\/[a-z]/i,
    message: "Persistence: writing a systemd unit file — installing a service",
  },
  {
    id: "PS-004",
    category: "persistence",
    severity: "HIGH",
    pattern: /launchctl\s+(load|bootstrap)|~\/Library\/LaunchAgents\//i,
    message: "Persistence: macOS LaunchAgent manipulation",
  },
  {
    id: "PS-005",
    category: "persistence",
    severity: "HIGH",
    pattern: /module\.paths\.push\s*\(|\brequire\.extensions\b|sys\.path\.append\s*\(/i,
    message: "Persistence/Hijack: modifying module resolution paths dynamically at runtime",
  },
];
