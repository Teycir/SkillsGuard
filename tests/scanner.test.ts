import test from "node:test";
import assert from "node:assert";
import { scan } from "../src/scanner.js";
import { writeFileSync, mkdirSync, chmodSync, rmSync } from "node:fs";
import { join } from "node:path";

test("Suppression comments skip rule matches", async () => {
  const result = await scan("testskills/safe-skill");
  assert.strictEqual(result.findings.length, 0);
});

test("scan throws on non-existent target path", async () => {
  await assert.rejects(
    () => scan("nonexistent-directory-xyz"),
    /Cannot access target 'nonexistent-directory-xyz'/
  );
});

test("scan reports read errors for unreadable files", async () => {
  const tmpDir = join(process.cwd(), "temp-unreadable-test");
  try {
    mkdirSync(tmpDir, { recursive: true });
    const filePath = join(tmpDir, "unreadable.sh");
    writeFileSync(filePath, "eval 'unreadable'", "utf-8");
    // Make file completely unreadable (000 permissions)
    chmodSync(filePath, 0o000);

    const result = await scan(tmpDir);
    const readErr = result.findings.find(f => f.ruleId === "SG-READ-ERR");
    assert.ok(readErr);
    assert.strictEqual(readErr.severity, "HIGH");
    assert.match(readErr.message, /Failed to read file/);
  } finally {
    try {
      chmodSync(join(tmpDir, "unreadable.sh"), 0o644);
    } catch {}
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }
});

