export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

export interface Rule {
  id: string;
  category: string;
  severity: Severity;
  pattern: RegExp;
  message: string;
}

export interface Finding {
  ruleId: string;
  category: string;
  severity: Severity;
  message: string;
  file: string;
  line: number;
  evidence: string;
  decodedFrom?: string;
}

export interface ScanResult {
  target: string;
  filesScanned: number;
  findings: Finding[];
  durationMs: number;
}

/**
 * A partially-specified rule supplied by the caller (e.g. via CLI --rule flag
 * or programmatically). Missing fields are filled in with safe defaults.
 */
export interface CustomRule {
  /** Raw regex source string, e.g. "evil\s+pattern" */
  pattern: string;
  /** Regex flags, e.g. "i". Defaults to "gi". */
  flags?: string;
  /** Rule ID. Auto-generated as "CUSTOM-NNN" if omitted. */
  id?: string;
  /** Severity. Defaults to HIGH. */
  severity?: Severity;
  /** Category label. Defaults to "custom". */
  category?: string;
  /** Human-readable message. Defaults to the pattern source. */
  message?: string;
}

/**
 * Options forwarded to scan() / scanText() to extend or override built-in rules.
 */
export interface ScanOptions {
  /**
   * Extra rules to merge on top of (or instead of) the built-in rule set.
   * Appended after the built-in rules so they show up in findings as-is.
   */
  extraRules?: CustomRule[];
  /**
   * When true, run ONLY the extraRules — skip the built-in rule set entirely.
   * Useful for testing a custom ruleset in isolation.
   */
  rulesOnly?: boolean;
}
