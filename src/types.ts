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

/**
 * Risk score: a single number in [0, 100] summarising how dangerous the scan
 * result is, suitable for a CI gate threshold (e.g. fail if score > 40).
 *
 * Scoring:
 *   CRITICAL → 25 pts each (capped at 4)
 *   HIGH     → 10 pts each (capped at 4)
 *   MEDIUM   →  3 pts each (capped at 4)
 *   LOW      →  1 pt  each (capped at 4)
 *   INFO     →  0 pts
 *
 * Final score = min(100, sum of all contributions).
 */
export interface RiskScore {
  score: number;     // [0, 100]
  label: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface ScanResult {
  target: string;
  filesScanned: number;
  findings: Finding[];
  durationMs: number;
  riskScore: RiskScore;
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
  extraRules?: CustomRule[];
  rulesOnly?: boolean;
  /**
   * Rule IDs to suppress entirely during this scan (in addition to inline
   * `skillsguard-ignore` comments). Typically populated from config file.
   */
  ignoreRules?: string[];
}
