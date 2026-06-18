/**
 * Worker-safe scanner module.
 * Re-exports only the pure (no-fs) functions from the main scanner.
 * The Worker entry point imports from here — not from the Node scanner.
 *
 * We inline the logic rather than re-exporting from "../../src/scanner.ts"
 * because the main scanner imports node:fs which is unavailable in Workers
 * even when nodejs_compat is enabled (fs requires the local filesystem).
 */

import type { Finding, ScanOptions, Rule, CustomRule, RiskScore } from "./types.js";
import { RULES } from "./rules.js";
import { shouldIgnoreLine, isCommentLine, isPlaceholderLine, isTestFilePath } from "./ignore.js";

// ─── Custom rule resolution ──────────────────────────────────────────────────

let _customCounter = 0;

export function resolveCustomRule(raw: CustomRule, index?: number): Rule {
  const counter = index ?? ++_customCounter;
  const id = raw.id ?? `CUSTOM-${String(counter).padStart(3, "0")}`;
  const flags = raw.flags ?? "gi";
  let compiledPattern: RegExp;
  try {
    compiledPattern = new RegExp(raw.pattern, flags);
  } catch (err) {
    throw new Error(`Invalid regex for rule "${id}": ${raw.pattern} — ${String(err)}`);
  }
  return {
    id,
    category: raw.category ?? "custom",
    severity: raw.severity ?? "HIGH",
    pattern: compiledPattern,
    message: raw.message ?? `Custom rule matched: ${raw.pattern}`,
  };
}

function resolveRules(options?: ScanOptions): readonly Rule[] {
  const extras = (options?.extraRules ?? []).map((r, i) => resolveCustomRule(r, i + 1));
  const base = options?.rulesOnly ? extras : [...RULES, ...extras];

  const afterIgnore = options?.ignoreRules?.length
    ? base.filter((r) => !new Set(options.ignoreRules).has(r.id))
    : base;

  const overrides = options?.severityOverrides;
  if (!overrides || Object.keys(overrides).length === 0) return afterIgnore;
  return afterIgnore.map((r) =>
    overrides[r.id] ? { ...r, severity: overrides[r.id]! } : r,
  );
}

// ─── scanText ────────────────────────────────────────────────────────────────

export function scanText(
  text: string,
  filePath: string,
  decodedFrom?: string,
  options?: ScanOptions,
): readonly Finding[] {
  const findings: Finding[] = [];
  const lines = text.split("\n");
  const rules = resolveRules(options);
  const inTestFile = isTestFilePath(filePath);

  for (const rule of rules) {
    const regex = rule.pattern.flags.includes("g")
      ? new RegExp(rule.pattern.source, rule.pattern.flags)
      : rule.pattern;

    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (line === undefined) continue;
      if (shouldIgnoreLine(line, rule.id)) continue;
      if (rule.skipCommentLines    && !decodedFrom && isCommentLine(line))    continue;
      if (rule.skipPlaceholderLines && !decodedFrom && isPlaceholderLine(line)) continue;

      if (regex.test(line)) {
        const severity =
          inTestFile && rule.severity !== "CRITICAL" ? "INFO" : rule.severity;

        findings.push({
          ruleId:   rule.id,
          category: rule.category,
          severity,
          message:  rule.message,
          file:     filePath,
          line:     lineIdx + 1,
          evidence: line.trim().slice(0, 200),
          decodedFrom,
        });
        if (regex.flags.includes("g")) regex.lastIndex = 0;
      }
    }
  }

  return findings;
}

// ─── computeRiskScore ────────────────────────────────────────────────────────

const RISK_WEIGHTS: Record<string, number> = {
  CRITICAL: 25, HIGH: 10, MEDIUM: 3, LOW: 1, INFO: 0,
};

export function computeRiskScore(findings: readonly Finding[]): RiskScore {
  const buckets: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) buckets[f.severity] = (buckets[f.severity] ?? 0) + 1;

  let raw = 0;
  for (const [sev, count] of Object.entries(buckets)) {
    raw += Math.min(count, 4) * (RISK_WEIGHTS[sev] ?? 0);
  }
  const score = Math.min(100, raw);

  let label: RiskScore["label"];
  if (score === 0)      label = "NONE";
  else if (score <= 10) label = "LOW";
  else if (score <= 30) label = "MEDIUM";
  else if (score <= 60) label = "HIGH";
  else                  label = "CRITICAL";

  return { score, label };
}
