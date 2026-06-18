import test from "node:test";
import assert from "node:assert";
import { scan } from "../src/scanner.js";

test("Suppression comments skip rule matches", async () => {
  const result = await scan("testskills/safe-skill");
  assert.strictEqual(result.findings.length, 0);
});
