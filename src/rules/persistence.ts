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
  {
    id: "PS-006",
    category: "persistence",
    severity: "HIGH",
    // reg add/import installs registry keys from cmd; regedit /s|/i silently imports .reg files.
    pattern: /\breg\s+(add|import)\b|\bregedit\s+(\/s|\/i|\/c)\b/i,
    message: "Persistence: Windows registry modification via reg.exe or regedit silent import",
    skipCommentLines: true,
  },
  {
    id: "PS-007",
    category: "persistence",
    severity: "HIGH",
    // LD_PRELOAD with any value is flagged (any .so injection is suspicious).
    // LD_LIBRARY_PATH is only flagged when pointing at writable/temp paths (not system lib dirs).
    pattern: /\bLD_PRELOAD\s*=|\bLD_LIBRARY_PATH\s*=[^#\n]*(\.so\b|\/tmp\/|\/dev\/shm\/)/i,
    message: "Persistence/Hijack: LD_PRELOAD or suspicious LD_LIBRARY_PATH — shared library injection",
    skipCommentLines: true,
  },
];
