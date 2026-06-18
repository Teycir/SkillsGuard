import test from "node:test";
import assert from "node:assert";
import { FILE_SYSTEM_RULES } from "../../src/rules/fileSystem.js";

function rule(id: string) {
  const r = FILE_SYSTEM_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("FS-001 catches recursive delete targeting system/home directories", () => {
  const r = rule("FS-001");
  assert.ok(r.pattern.test("rm -rf /"));
  assert.ok(r.pattern.test("rm -rf ~/"));
  assert.ok(r.pattern.test("rm -rf $HOME/important"));
  assert.ok(r.pattern.test("rm -rf /etc/"));
  assert.ok(r.pattern.test("rm -rf /usr/bin/python3"));
  assert.ok(r.pattern.test("rm -fr /home/user/"));
  assert.ok(!r.pattern.test("rm -rf ./build"));
  assert.ok(!r.pattern.test("rm -rf tmp/"));
});

test("FS-002 catches dd writing to device/boot/system paths", () => {
  const r = rule("FS-002");
  assert.ok(r.pattern.test("dd if=/dev/zero of=/dev/sda"));
  assert.ok(r.pattern.test("dd if=payload.bin of=/boot/vmlinuz"));
  assert.ok(r.pattern.test("dd if=rootkit.img of=/etc/passwd"));
  assert.ok(!r.pattern.test("dd if=/dev/urandom of=/tmp/random.bin bs=1M count=1"));
  assert.ok(!r.pattern.test("dd if=input.iso of=./output.img"));
});

test("FS-003 catches writes to sensitive system config files", () => {
  const r = rule("FS-003");
  // Standalone write() — matches \bwrite\w*\s*\(
  assert.ok(r.pattern.test("write('/etc/hosts', newContent)"));
  assert.ok(r.pattern.test("fs.write('/etc/resolv.conf', data)"));
  // Compound names like writeFileSync also match \bwrite\w*
  assert.ok(r.pattern.test("writeFileSync('/etc/passwd', payload)"));
  assert.ok(r.pattern.test("fs.writeFile('/etc/hosts', data, cb)"));
  // Non-sensitive paths should NOT fire
  assert.ok(!r.pattern.test("write('./config/hosts.json', data)"));
  assert.ok(!r.pattern.test("writeFile('/tmp/output.txt', result)"));
});
