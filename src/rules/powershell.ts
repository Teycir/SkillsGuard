/**
 * SkillsGuard — PowerShell-specific security rules
 *
 * Covers PS1/PSM1 patterns that are common in agent skills that wrap
 * PowerShell scripts: encoded commands, download-cradles, AMSI bypasses,
 * persistence via scheduled tasks and registry, and credential theft.
 */

import type { Rule } from "../types.js";

export const POWERSHELL_RULES: readonly Rule[] = [
  // ── Encoded/obfuscated execution ─────────────────────────────────────────
  {
    id: "PS-001",
    category: "powershell",
    severity: "CRITICAL",
    pattern: /\bpowershell\b[^#\n]*-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]\b|\bpowershell\b[^#\n]*-[Ee][Nn][Cc]\b/i,
    message: "PowerShell: encoded command flag — obfuscated execution",
  },
  {
    id: "PS-002",
    category: "powershell",
    severity: "CRITICAL",
    pattern: /\[System\.Convert\]::FromBase64String\s*\(|\[System\.Text\.Encoding\].*FromBase64|IEX\s*\(|Invoke-Expression\s*\$/i,
    message: "PowerShell: base64-decoded or Invoke-Expression dynamic execution",
  },
  {
    id: "PS-003",
    category: "powershell",
    severity: "CRITICAL",
    pattern: /IEX\s*\(|Invoke-Expression\s*\(.*\$|Invoke-Expression\s+'[^']+'/i,
    message: "PowerShell: Invoke-Expression (IEX) — dynamic code execution",
  },

  // ── Download cradles ─────────────────────────────────────────────────────
  {
    id: "PS-004",
    category: "powershell",
    severity: "CRITICAL",
    pattern: /\(New-Object\s+Net\.WebClient\)\.DownloadString\s*\(|\bInvoke-WebRequest\b[^#\n]*\|\s*IEX\b/i,
    message: "PowerShell: download-cradle pattern — fetching and executing remote code",
  },
  {
    id: "PS-005",
    category: "powershell",
    severity: "HIGH",
    pattern: /\bInvoke-WebRequest\b|\bwget\b[^#\n]*\.ps1\b|\bNet\.WebClient\b|\bStart-BitsTransfer\b/i,
    message: "PowerShell: web download function — review for legitimacy",
  },

  // ── AMSI / ETW bypass ────────────────────────────────────────────────────
  {
    id: "PS-006",
    category: "powershell",
    severity: "CRITICAL",
    pattern: /amsiInitFailed|amsiContext|AmsiScanBuffer|amsi\.dll|Add-Type[^#\n]*AmsiUtils/i,
    message: "PowerShell: AMSI bypass attempt — security instrumentation disabled",
  },

  // ── Credential theft ────────────────────────────────────────────────────
  {
    id: "PS-007",
    category: "powershell",
    severity: "CRITICAL",
    pattern: /Get-Credential\s*\||\bConvertFrom-SecureString\b|\bCredential.*Export\b/i,
    message: "PowerShell: credential extraction or export",
  },
  {
    id: "PS-008",
    category: "powershell",
    severity: "HIGH",
    pattern: /\[System\.Runtime\.InteropServices\.Marshal\]::SecureStringToBSTR\b/i,
    message: "PowerShell: SecureString to plaintext conversion",
  },

  // ── Persistence ──────────────────────────────────────────────────────────
  {
    id: "PS-009",
    category: "powershell",
    severity: "HIGH",
    pattern: /New-ScheduledTask|Register-ScheduledTask|schtasks\s+\/create/i,
    message: "PowerShell: scheduled task creation — persistence mechanism",
  },
  {
    id: "PS-010",
    category: "powershell",
    severity: "HIGH",
    pattern: /New-ItemProperty[^#\n]*HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
    message: "PowerShell: registry Run-key modification — persistence mechanism",
  },

  // ── Execution policy bypass ──────────────────────────────────────────────
  {
    id: "PS-011",
    category: "powershell",
    severity: "MEDIUM",
    pattern: /\bSet-ExecutionPolicy\s+(?:Bypass|Unrestricted|RemoteSigned)\b|\bpowershell\b[^#\n]*-[Ee][Xx][Ee][Cc][Uu][Tt][Ii][Oo][Nn][Pp][Oo][Ll][Ii][Cc][Yy]\s+Bypass/i,
    message: "PowerShell: execution policy bypassed",
  },
];
