/**
 * SkillsGuard — SARIF 2.1.0 emitter
 *
 * Produces a GitHub Code Scanning-compatible SARIF document from a ScanResult.
 * Zero dependencies — all types inlined below.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { ScanResult, Finding, Severity } from "./types.js";
import { createRequire } from "node:module";

const _require = createRequire(import.meta.url);
const pkg = _require("../package.json") as { version?: string };
const TOOL_VERSION: string = typeof pkg.version === "string" ? pkg.version : "0.0.0";

// ─── SARIF severity mapping ───────────────────────────────────────────────────

function sarifLevel(sev: Severity): "error" | "warning" | "note" | "none" {
  switch (sev) {
    case "CRITICAL":
    case "HIGH":     return "error";
    case "MEDIUM":   return "warning";
    case "LOW":      return "note";
    case "INFO":     return "none";
  }
}

// ─── Rule index ───────────────────────────────────────────────────────────────

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  defaultConfiguration: { level: "error" | "warning" | "note" | "none" };
  properties: { tags: string[]; "security-severity": string };
}

const SECURITY_SEVERITY: Record<Severity, string> = {
  CRITICAL: "9.5",
  HIGH:     "7.5",
  MEDIUM:   "5.0",
  LOW:      "3.0",
  INFO:     "0.0",
};

function buildRules(findings: readonly Finding[]): SarifRule[] {
  const seen = new Map<string, SarifRule>();
  for (const f of findings) {
    if (seen.has(f.ruleId)) continue;
    seen.set(f.ruleId, {
      id: f.ruleId,
      name: f.ruleId.replace(/[^A-Za-z0-9]/g, ""),
      shortDescription: { text: f.message },
      defaultConfiguration: { level: sarifLevel(f.severity) },
      properties: {
        tags: ["security", f.category],
        "security-severity": SECURITY_SEVERITY[f.severity],
      },
    });
  }
  return [...seen.values()];
}

// ─── Result builder ───────────────────────────────────────────────────────────

function buildResults(findings: readonly Finding[], rules: SarifRule[]): unknown[] {
  const ruleIndex = new Map(rules.map((r, i) => [r.id, i]));
  return findings.map((f) => ({
    ruleId: f.ruleId,
    ruleIndex: ruleIndex.get(f.ruleId) ?? 0,
    level: sarifLevel(f.severity),
    message: {
      text: f.decodedFrom
        ? `${f.message} [decoded from ${f.decodedFrom}]`
        : f.message,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: f.file.replace(/\\/g, "/"),
            uriBaseId: "%SRCROOT%",
          },
          region: {
            startLine: f.line,
            snippet: f.evidence ? { text: f.evidence } : undefined,
          },
        },
      },
    ],
    properties: {
      severity: f.severity,
      category: f.category,
    },
  }));
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Convert a {@link ScanResult} into a SARIF 2.1.0 document string.
 * Pass the result directly to stdout or write to a `.sarif` file.
 */
export function toSarif(result: ScanResult): string {
  const rules = buildRules(result.findings);
  const sarifDoc = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SkillsGuard",
            version: TOOL_VERSION,
            informationUri: "https://github.com/teycir/SkillsGuard",
            rules,
          },
        },
        results: buildResults(result.findings, rules),
        properties: {
          target: result.target,
          filesScanned: result.filesScanned,
          durationMs: result.durationMs,
          riskScore: result.riskScore,
        },
      },
    ],
  };
  return JSON.stringify(sarifDoc, null, 2);
}

export function reportSarif(result: ScanResult): void {
  process.stdout.write(toSarif(result) + "\n");
}
