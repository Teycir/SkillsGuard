import test from "node:test";
import assert from "node:assert";
import { SILENT_SKIP_DIRS, isSilentPath } from "../src/lib/skipdirs.js";

test("isSilentPath: events inside .git and .skillsguard are ignored", () => {
  for (const p of [".git/HEAD", ".git/hooks/pre-commit", "sub/.git/config", ".skillsguard/baseline.json", "a\\.git\\x"]) {
    assert.strictEqual(isSilentPath(p), true, p);
  }
});

test("isSilentPath: everything the scanner reads or reports triggers a re-scan", () => {
  for (const p of [
    "SKILL.md", "src/run.py", "dist/payload.js", "build/out.sh", "node_modules/pkg/index.js",
    ".hidden/run.sh", ".env", "scripts/distribute.sh", "rebuild.py", "tests/helper.js",
    "__pycache__/x.cpython-312.pyc", "docs/.github-notes.md", "my.git.backup/x", ".gitignore", ".gitattributes",
  ]) {
    assert.strictEqual(isSilentPath(p), false, p);
  }
});

test("the silent set is exactly the two directories the scanner never reads", () => {
  assert.deepStrictEqual([...SILENT_SKIP_DIRS].sort(), [".git", ".skillsguard"]);
});
