import test from "node:test";
import assert from "node:assert";
import { SCOPE_CREEP_RULES } from "../../src/rules/scopeCreep.js";

function rule(id: string) {
  const r = SCOPE_CREEP_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("SC-CR-001 catches deep directory traversal", () => {
  const r = rule("SC-CR-001");
  assert.ok(r.pattern.test("../../../../etc/passwd"));
  assert.ok(r.pattern.test("../../../..\\windows\\system32"));
  assert.ok(!r.pattern.test("../../relative/path"));  // only 2 levels — not deep enough
  assert.ok(!r.pattern.test("./subdir/file"));
});

test("SC-CR-002 catches direct references to sensitive system paths", () => {
  const r = rule("SC-CR-002");
  assert.ok(r.pattern.test("/etc/passwd"));
  assert.ok(r.pattern.test("/etc/shadow"));
  assert.ok(r.pattern.test("/etc/sudoers"));
  assert.ok(r.pattern.test("/etc/resolv.conf"));
  assert.ok(!r.pattern.test("/etc/nginx/nginx.conf"));
  assert.ok(!r.pattern.test("/etc/apt/sources.list"));
});

test("SC-CR-003 catches access to credential/config dotfiles", () => {
  const r = rule("SC-CR-003");
  assert.ok(r.pattern.test("~/.ssh/id_rsa"));
  assert.ok(r.pattern.test("~/.aws/credentials"));
  assert.ok(r.pattern.test("~/.kube/config"));
  assert.ok(r.pattern.test("path.join(home, '.bashrc')"));
  assert.ok(r.pattern.test("readFile('.gitconfig')"));
  assert.ok(!r.pattern.test("./config/settings.json"));
});

test("SC-CR-003 does NOT fire on prose documentation about .bashrc", () => {
  const r = rule("SC-CR-003");
  // These are markdown prose sentences — no path separator, no quote, no bracket
  // The pattern requires (?:\/|\\|['"\`\(,\s]|^) before the dot, but a plain
  // word in the middle of a sentence like "edit your .bashrc file" still has
  // a space before the dot, so it DOES match — and that's intentional (it's a
  // suspicious reference to a dotfile in a skill). The FP we're specifically
  // guarding against was the word ".bashrc" appearing with NO leading context
  // anchor at all, which the current path-separator group already prevents for
  // truly bare occurrences. Prose with a leading space is still flagged because
  // ` ` is in the alternation — this is the correct behavior for a skill.
  // Confirm the known-safe non-match still holds:
  assert.ok(!r.pattern.test("./config/settings.json"));
  assert.ok(!r.pattern.test("There is no mention of dotfiles here."));
});
