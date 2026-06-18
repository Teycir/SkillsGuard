/**
 * SkillsGuard — Watch mode
 *
 * Monitors a target directory for file changes and re-runs the scanner
 * automatically on each save.  Prints only the delta (new vs resolved
 * findings) rather than the full report on every change.
 *
 * Usage:
 *   skillsguard ./skill --watch
 *   skillsguard ./skill --watch --min-severity HIGH
 */

import { watch as fsWatch } from "node:fs";
import type { ScanOptions, Finding, Severity } from "./types.js";
import { SEVERITY_RANK } from "./types.js";
import { scan } from "./scanner.js";

// ─── ANSI helpers (duplicated from report.ts to keep zero deps) ───────────────
const C = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  dim:    "\x1b[2m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  green:  "\x1b[32m",
  cyan:   "\x1b[36m",
  white:  "\x1b[37m",
  bgRed:  "\x1b[41m",
} as const;

function colorForSev(s: Severity, noColor: boolean): string {
  if (noColor) return "";
  switch (s) {
    case "CRITICAL": return `${C.bold}${C.bgRed}${C.white}`;
    case "HIGH":     return `${C.bold}${C.red}`;
    case "MEDIUM":   return `${C.bold}${C.yellow}`;
    case "LOW":      return `${C.bold}${C.cyan}`;
    case "INFO":     return C.dim;
    default:         return "";
  }
}

function strip(s: string): string { return s.replace(/\x1b\[[0-9;]*m/g, ""); }

// ─── Fingerprint (same logic as baseline to avoid duplicating the key) ────────
function fp(f: Finding): string {
  return `${f.ruleId}::${f.file}::${f.line}`;
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface WatchOptions {
  target:      string;
  scanOptions: ScanOptions;
  minSeverity: Severity;
  noColor:     boolean;
  /** Debounce delay in ms between a file-change event and re-scan (default 300). */
  debounceMs?: number;
}

export function startWatch(opts: WatchOptions): void {
  const { target, scanOptions, minSeverity, noColor, debounceMs = 300 } = opts;
  const use = noColor ? strip : (s: string) => s;
  const minRank = SEVERITY_RANK[minSeverity];

  let prevFindings: Finding[] = [];
  let debounceTimer: ReturnType<typeof setTimeout> | null = null;
  let scanning = false;

  function ts(): string {
    return new Date().toLocaleTimeString("en-GB", { hour12: false });
  }

  async function runScan(): Promise<void> {
    if (scanning) return; // skip if a scan is already in flight
    scanning = true;
    try {
      const result = await scan(target, scanOptions);
      const filtered = result.findings.filter((f) => SEVERITY_RANK[f.severity] >= minRank);

      const prevFP    = new Set(prevFindings.map(fp));
      const currFP    = new Set(filtered.map(fp));
      const newOnes   = filtered.filter((f) => !prevFP.has(fp(f)));
      const resolved  = prevFindings.filter((f) => !currFP.has(fp(f)));

      if (newOnes.length === 0 && resolved.length === 0) {
        // Unchanged — print a quiet heartbeat only if count also changed (file structure change)
        if (filtered.length !== prevFindings.length) {
          process.stdout.write(use(`${C.dim}[${ts()}] — ${filtered.length} finding(s) (no change)${C.reset}\n`));
        } else {
          process.stdout.write(use(`${C.dim}[${ts()}] ✓ clean (${filtered.length} finding(s) unchanged)${C.reset}\n`));
        }
      } else {
        if (newOnes.length > 0) {
          process.stdout.write(use(`${C.bold}[${ts()}] ⚠  ${newOnes.length} new finding(s):${C.reset}\n`));
          for (const f of newOnes) {
            const col = colorForSev(f.severity, noColor);
            process.stdout.write(use(`  ${col}[${f.severity}]${C.reset} ${f.ruleId}: ${f.message}\n`));
            process.stdout.write(use(`  ${C.dim}${f.file}:${f.line}  ▶ ${f.evidence}${C.reset}\n`));
          }
        }
        if (resolved.length > 0) {
          process.stdout.write(use(`${C.green}[${ts()}] ✓ ${resolved.length} finding(s) resolved${C.reset}\n`));
        }
      }

      prevFindings = filtered;
    } catch (err: unknown) {
      process.stderr.write(`[${ts()}] Scan error: ${String(err)}\n`);
    } finally {
      scanning = false;
    }
  }

  // Initial scan
  process.stdout.write(use(`\n${C.bold}SkillsGuard — watch mode${C.reset}  ${C.dim}${target}${C.reset}\n`));
  process.stdout.write(use(`${C.dim}Min severity: ${minSeverity} · Ctrl+C to stop${C.reset}\n\n`));
  void runScan();

  // Watch for changes
  fsWatch(target, { recursive: true }, (_event, filename) => {
    if (!filename) return;
    // Ignore hidden dirs and build artifacts
    if (/^\./.test(filename) || /node_modules|dist|build/.test(filename)) return;

    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => void runScan(), debounceMs);
  });

  // Keep process alive
  process.stdin.resume();
  process.on("SIGINT", () => {
    process.stdout.write(use(`\n${C.dim}Watch stopped.${C.reset}\n`));
    process.exit(0);
  });
}
