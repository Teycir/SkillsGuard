import test from "node:test";
import assert from "node:assert";
import { PRIVILEGE_ESCALATION_RULES } from "../../src/rules/privilegeEscalation.js";

function rule(id: string) {
  const r = PRIVILEGE_ESCALATION_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("PE-001 catches sudo with stdin password flag", () => {
  const r = rule("PE-001");
  assert.ok(r.pattern.test("echo 'password' | sudo -S apt install backdoor"));
  assert.ok(r.pattern.test("sudo --stdin rm -rf /"));
  assert.ok(!r.pattern.test("sudo apt update"));
});

test("PE-002 catches chmod on system binaries", () => {
  const r = rule("PE-002");
  assert.ok(r.pattern.test("chmod 777 /bin/bash"));
  assert.ok(r.pattern.test("chmod 4755 /usr/bin/python3"));
  assert.ok(!r.pattern.test("chmod 755 ./my-script.sh"));
  assert.ok(!r.pattern.test("chmod 644 /bin/ls"));  // 644 — no write/exec bits in octal middle
});

test("PE-003 catches chown root on files", () => {
  const r = rule("PE-003");
  assert.ok(r.pattern.test("chown root /tmp/payload"));
  assert.ok(r.pattern.test("chown root:root /etc/evil.conf"));
  assert.ok(!r.pattern.test("chown alice:alice /home/alice/file"));
});

test("PE-004 catches sudoers file access", () => {
  const r = rule("PE-004");
  assert.ok(r.pattern.test("cat /etc/sudoers"));
  assert.ok(r.pattern.test("echo 'user ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers"));
  assert.ok(!r.pattern.test("echo 'configured sudoers'"));
});

test("PE-005 catches programmatic UID/GID manipulation", () => {
  const r = rule("PE-005");
  assert.ok(r.pattern.test("process.setuid(0)"));
  assert.ok(r.pattern.test("process.setgid(0)"));
  assert.ok(r.pattern.test("os.setuid(0)"));
  assert.ok(r.pattern.test("os.seteuid(0)"));
  assert.ok(!r.pattern.test("process.pid"));
  assert.ok(!r.pattern.test("os.getuid()"));
});
