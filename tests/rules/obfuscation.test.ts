import test from "node:test";
import assert from "node:assert";
import { OBFUSCATION_RULES } from "../../src/rules/obfuscation.js";

function rule(id: string) {
  const r = OBFUSCATION_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("OB-001 catches base64 payload piped to decoder", () => {
  const r = rule("OB-001");
  // Must be >= 20 chars of base64 content (the {20,} minimum)
  assert.ok(r.pattern.test("echo 'Y3VybCAtcyBodHRwczovL2V2aWwuY29t' | base64 -d"));
  assert.ok(r.pattern.test("echo 'aGVsbG8gd29ybGQgdGhpcyBpcyBsb25n' | base64 -d"));
  // Short payload (< 20 chars) should NOT match
  assert.ok(!r.pattern.test("echo 'SGVsbG8=' | base64 -d"));
  assert.ok(!r.pattern.test("echo hello"));
});

test("OB-002 catches hex-escaped shellcode payload in printf", () => {
  const r = rule("OB-002");
  assert.ok(r.pattern.test("printf '\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68'"));
  // Too short (< 6 pairs) should NOT match
  assert.ok(!r.pattern.test("printf '\\x41\\x42'"));
  assert.ok(!r.pattern.test("echo hello"));
});

test("OB-003 catches shell parameter expansion hiding pipe-to-shell pattern", () => {
  const r = rule("OB-003");
  // ${VAR:-'<payload>'} | shell — the fixed pattern matches the closing }
  assert.ok(r.pattern.test("${CMD:-''} | bash"));
  assert.ok(r.pattern.test("${VAR:-'payload'} | sh"));
  assert.ok(r.pattern.test('${VAR:-"cmd"} | python'));
  // No pipe-to-shell — should NOT match
  assert.ok(!r.pattern.test("${VAR:-default}"));
  assert.ok(!r.pattern.test("normal code"));
});

test("OB-004 catches JS dynamic eval patterns", () => {
  const r = rule("OB-004");
  assert.ok(r.pattern.test("Buffer.from(payload, 'base64')"));
  assert.ok(r.pattern.test("atob(encodedString)"));
  assert.ok(r.pattern.test("String.fromCharCode(65, 66, 67)"));
  assert.ok(r.pattern.test("new Function('return 42')()"));
  assert.ok(!r.pattern.test("Buffer.from('hello', 'utf8')"));
});

test("OB-005 catches Python obfuscation patterns", () => {
  const r = rule("OB-005");
  assert.ok(r.pattern.test("getattr(os, '__reduce__')"));
  assert.ok(r.pattern.test("__import__('subprocess')"));
  assert.ok(r.pattern.test("bytes.fromhex('deadbeef')"));
  assert.ok(r.pattern.test("base64.b64decode(payload)"));
  assert.ok(!r.pattern.test("import base64"));
});
