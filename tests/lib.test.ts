import test from "node:test";
import assert from "node:assert";
import { runConcurrent } from "../src/lib/concurrency.js";
import { isSafePath } from "../src/lib/path.js";
import { shouldIgnoreLine } from "../src/lib/ignore.js";
import { resolve } from "node:path";
import { homedir } from "node:os";

test("runConcurrent maps items in the exact input order", async () => {
  const items = [1, 2, 3, 4, 5];
  const fn = async (x: number) => {
    // Artificial non-uniform delay to test concurrent race handling
    await new Promise((resolve) => setTimeout(resolve, (5 - x) * 2));
    return x * 10;
  };
  const results = await runConcurrent(items, 3, fn);
  assert.deepStrictEqual(results, [10, 20, 30, 40, 50]);
});

test("isSafePath permits authorized and rejects dangerous paths", () => {
  const home = resolve(homedir());
  
  // Safe cases
  assert.strictEqual(isSafePath(home), true);
  assert.strictEqual(isSafePath(resolve(home, "projects")), true);
  
  // Traversal and outside target scope
  assert.strictEqual(isSafePath("/etc/passwd"), false);
  assert.strictEqual(isSafePath(resolve(home, "../../etc/passwd")), false);
  
  // Original sensitive locations
  assert.strictEqual(isSafePath(resolve(home, ".ssh")), false);
  assert.strictEqual(isSafePath(resolve(home, ".ssh/id_rsa")), false);
  assert.strictEqual(isSafePath(resolve(home, ".ssh\\id_rsa")), false);
  assert.strictEqual(isSafePath(resolve(home, "some_dir\\.ssh\\id_rsa")), false);
  assert.strictEqual(isSafePath(resolve(home, ".bashrc")), false);
  assert.strictEqual(isSafePath(resolve(home, "some_dir\\.bash_history")), false);
  assert.strictEqual(isSafePath(resolve(home, "some_dir/passwd")), false);
  assert.strictEqual(isSafePath(resolve(home, "some_dir\\passwd")), false);

  // Newly added sensitive locations (cloud CLIs, container tooling)
  assert.strictEqual(isSafePath(resolve(home, ".kube")), false);
  assert.strictEqual(isSafePath(resolve(home, ".kube/config")), false);
  assert.strictEqual(isSafePath(resolve(home, ".docker")), false);
  assert.strictEqual(isSafePath(resolve(home, ".docker/config.json")), false);
  assert.strictEqual(isSafePath(resolve(home, ".azure")), false);
  assert.strictEqual(isSafePath(resolve(home, ".terraform.d")), false);
  assert.strictEqual(isSafePath(resolve(home, "some_dir/vault-token")), false);
  assert.strictEqual(isSafePath(resolve(home, "some_dir/pgpass")), false);
});

test("shouldIgnoreLine behaves correctly for inline comments", () => {
  // Global ignore
  assert.strictEqual(shouldIgnoreLine("const x = 1; // skillsguard-ignore", "PI-001"), true);
  
  // Specific rule ignore
  assert.strictEqual(shouldIgnoreLine("const x = 1; // skillsguard-ignore PI-001", "PI-001"), true);
  assert.strictEqual(shouldIgnoreLine("const x = 1; // skillsguard-ignore: PI-001", "PI-001"), true);
  
  // Mismatch specific ignore
  assert.strictEqual(shouldIgnoreLine("const x = 1; // skillsguard-ignore PI-002", "PI-001"), false);
  
  // No ignore comment
  assert.strictEqual(shouldIgnoreLine("const x = 1;", "PI-001"), false);
});
