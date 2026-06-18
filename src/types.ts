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
  /**
   * When true, lines that are pure comments (leading #, //, /*, <!--, >)
   * are skipped before pattern-matching.  Eliminates the overwhelming
   * majority of FPs where rules fire on README examples or commented-out code.
   *
   * Do NOT set this for rules that specifically look for malicious content
   * INSIDE comments (e.g. MS-023 RAG poisoning via HTML comments).
   */
  skipCommentLines?: boolean;
  /**
   * When true, lines containing well-known placeholder/stopword patterns
   * (example, dummy, fake, your-token-here, xxxx, changeme, …) are skipped.
   * Appropriate for secret-harvesting, supply-chain, and network rules that
   * fire heavily on documentation examples.
   */
  skipPlaceholderLines?: boolean;
  /**
   * Optional human-readable remediation guidance surfaced by `skillsguard rules`
   * and `--suggest-fix`. Populated for CRITICAL and HIGH rules.
   */
  remediation?: string;
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
  /**
   * Per-rule severity overrides. Key is rule ID, value is the desired severity.
   * Lets teams tune severity to their own risk model without forking rules.
   * e.g. { "EX-008": "CRITICAL", "OB-001": "MEDIUM" }
   */
  severityOverrides?: Partial<Record<string, Severity>>;
  /**
   * Glob-style path segments to exclude from scanning.
   * A file is excluded if any segment matches a component of its path.
   * e.g. ["vendor", "third_party", "generated"]
   */
  excludePatterns?: string[];
  /**
   * Stop scanning after this many findings (fast-fail for CI pipelines).
   * Undefined or 0 means no limit.
   */
  maxFindings?: number;
}
