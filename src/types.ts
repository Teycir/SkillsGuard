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
