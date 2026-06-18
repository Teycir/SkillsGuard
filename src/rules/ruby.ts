/**
 * SkillsGuard — Ruby-specific security rules
 *
 * Covers patterns common in skills that wrap Ruby scripts or Rake tasks:
 * remote code evaluation, OS command injection, unsafe YAML/Marshal,
 * Gemfile source redirection, and credential exposure.
 */

import type { Rule } from "../types.js";

export const RUBY_RULES: readonly Rule[] = [
  // ── Remote code evaluation ────────────────────────────────────────────────
  {
    id: "RB-001",
    category: "ruby",
    severity: "CRITICAL",
    pattern: /\beval\s+.*\bURI\b|\beval\s+.*\bNet::HTTP\b|\beval\s+.*open\s*\(\s*['"]https?:/i,
    message: "Ruby: eval of remotely fetched content — RCE risk",
  },
  {
    id: "RB-002",
    category: "ruby",
    severity: "CRITICAL",
    pattern: /require\s+['"]open-uri['"][^#\n]*\n[^#\n]*eval\b|eval\s+open\s*\(/i,
    message: "Ruby: open-uri combined with eval — remote code execution",
  },

  // ── OS command injection ──────────────────────────────────────────────────
  {
    id: "RB-003",
    category: "ruby",
    severity: "CRITICAL",
    pattern: /`[^`]{0,200}(rm\s+-rf|wget|curl|bash|sh)[^`]{0,200}`|\bsystem\s*\(\s*['"].*\|\s*(bash|sh)\b/i,
    message: "Ruby: backtick or system() executing destructive/remote commands",
  },
  {
    id: "RB-004",
    category: "ruby",
    severity: "HIGH",
    pattern: /\bsystem\s*\(\s*[^)]*\$\{|\bsystem\s*\(\s*[^)]*#\{[^}]*\}/i,
    message: "Ruby: system() with string interpolation — command injection via user input",
  },
  {
    id: "RB-005",
    category: "ruby",
    severity: "HIGH",
    pattern: /IO\.popen\s*\(|Open3\.(popen|capture|pipeline)[^(]*\(/i,
    message: "Ruby: IO.popen / Open3 shell execution",
  },

  // ── Unsafe deserialization ────────────────────────────────────────────────
  {
    id: "RB-006",
    category: "ruby",
    severity: "CRITICAL",
    pattern: /\bMarshal\.load\s*\(|\bMarshal\.restore\s*\(/i,
    message: "Ruby: Marshal.load — arbitrary object deserialization (RCE risk)",
  },
  {
    id: "RB-007",
    category: "ruby",
    severity: "HIGH",
    pattern: /YAML\.load\s*\([^)]*\)(?!\s*#[^#\n]*safe)/i,
    message: "Ruby: YAML.load without safe flag — use YAML.safe_load to prevent RCE",
  },

  // ── Gemfile source hijack ────────────────────────────────────────────────
  {
    id: "RB-008",
    category: "ruby",
    severity: "HIGH",
    pattern: /^\s*source\s+['"]https?:\/\/(?!rubygems\.org)/im,
    message: "Gemfile: non-rubygems.org source — potential supply chain risk",
  },
  {
    id: "RB-009",
    category: "ruby",
    severity: "HIGH",
    pattern: /^\s*gem\s+['"][^'"]+['"],[^#\n]*git:\s*['"]https?:\/\/(?!github\.com|gitlab\.com)/im,
    message: "Gemfile: gem loaded from unrecognized git host",
  },

  // ── Credential exposure ───────────────────────────────────────────────────
  {
    id: "RB-010",
    category: "ruby",
    severity: "HIGH",
    pattern: /ENV\[['"](?:API_KEY|SECRET|TOKEN|PASSWORD|ANTHROPIC|OPENAI)['"]\][^#\n]*(puts|print|p\s|logger|send|post|Net::HTTP)/i,
    message: "Ruby: API key or secret sent over network or logged",
  },
];
