import test from "node:test";
import assert from "node:assert";
import { computeRiskScore } from "../src/scanner.js";
import type { Finding, Severity } from "../src/types.js";

function finding(severity: Severity, unanalyzed = false): Finding {
  return {
    ruleId: unanalyzed ? "SG-SKIP-001" : "X-001",
    category: "test",
    severity,
    message: "m",
    file: "f",
    line: 1,
    evidence: "",
    pattern: "",
    ...(unanalyzed ? { unanalyzed: true } : {}),
  };
}

test("scores without unanalyzed findings are unchanged", () => {
  assert.deepStrictEqual(computeRiskScore([]), { score: 0, label: "NONE" });
  assert.deepStrictEqual(computeRiskScore([finding("HIGH")]), { score: 10, label: "LOW" });
  assert.deepStrictEqual(computeRiskScore([finding("CRITICAL")]), { score: 25, label: "MEDIUM" });
  assert.deepStrictEqual(computeRiskScore([finding("CRITICAL"), finding("HIGH")]), { score: 35, label: "HIGH" });
});

test("an unanalyzed finding alone scores at the middle of its severity band", () => {
  const cases: ReadonlyArray<[Severity, number, string]> = [
    ["CRITICAL", 80, "CRITICAL"],
    ["HIGH", 45, "HIGH"],
    ["MEDIUM", 20, "MEDIUM"],
    ["LOW", 5, "LOW"],
    ["INFO", 0, "NONE"], // explicitly downgraded to INFO: no floor
  ];
  for (const [severity, score, label] of cases) {
    assert.deepStrictEqual(computeRiskScore([finding(severity, true)]), { score, label }, severity);
  }
});

test("an unreviewed HIGH clears the documented --max-risk 40 gate", () => {
  assert.ok(computeRiskScore([finding("HIGH", true)]).score > 40);
});

test("the floor only lifts the score; it never adds to real detections", () => {
  const detections = [finding("CRITICAL"), finding("CRITICAL"), finding("CRITICAL"), finding("CRITICAL"), finding("CRITICAL")];
  const withGap = computeRiskScore([...detections, finding("HIGH", true)]);
  const withoutFlag = computeRiskScore([...detections, finding("HIGH")]);
  assert.strictEqual(withGap.score, withoutFlag.score);
  assert.ok(withGap.score > 45);
});

test("the highest floor wins when several files were not analyzed", () => {
  const result = computeRiskScore([finding("MEDIUM", true), finding("HIGH", true)]);
  assert.deepStrictEqual(result, { score: 45, label: "HIGH" });
});

test("a score is never above 100", () => {
  const many = Array.from({ length: 500 }, () => finding("CRITICAL", true));
  assert.strictEqual(computeRiskScore(many).score, 100);
});
