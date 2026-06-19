import test from "node:test";
import assert from "node:assert";
import { PERSISTENCE_RULES } from "../../src/rules/persistence.js";

function rule(id: string) {
  const r = PERSISTENCE_RULES.find((r) => r.id === id);
  assert.ok(r, `Rule ${id} should exist`);
  return r!;
}

test("PS-001 catches crontab modification", () => {
  const r = rule("PS-001");
  assert.ok(r.pattern.test("crontab -e"));
  assert.ok(r.pattern.test("crontab -l | tee"));
  assert.ok(r.pattern.test("crontab < /tmp/backdoor.cron"));
  assert.ok(r.pattern.test("echo '*/5 * * * * /tmp/payload' > /etc/cron.d/evil"));
  assert.ok(!r.pattern.test("echo 'run every day'"));
});

test("PS-002 catches appending to shell startup files", () => {
  const r = rule("PS-002");
  assert.ok(r.pattern.test("echo 'export PATH=/tmp:$PATH' >> ~/.bashrc"));
  assert.ok(r.pattern.test("echo 'alias ls=evil' >> ~/.zshrc"));
  assert.ok(r.pattern.test("echo 'export X=1' >> /etc/profile"));
  assert.ok(!r.pattern.test("echo 'hello'"));
  assert.ok(!r.pattern.test("cat ~/.bashrc"));
});

test("PS-003 catches systemd unit file creation", () => {
  const r = rule("PS-003");
  assert.ok(r.pattern.test("cat > /etc/systemd/system/backdoor.service << EOF"));
  assert.ok(r.pattern.test("~/.config/systemd/user/malware.service"));
  assert.ok(!r.pattern.test("systemctl status nginx"));
});

test("PS-004 catches macOS LaunchAgent manipulation", () => {
  const r = rule("PS-004");
  assert.ok(r.pattern.test("launchctl load ~/Library/LaunchAgents/com.evil.plist"));
  assert.ok(r.pattern.test("launchctl bootstrap gui/501 ~/Library/LaunchAgents/evil.plist"));
  assert.ok(r.pattern.test("cp evil.plist ~/Library/LaunchAgents/"));
  assert.ok(!r.pattern.test("launchctl list"));
});

test("PS-005 catches module resolution path hijacking", () => {
  const r = rule("PS-005");
  assert.ok(r.pattern.test("module.paths.push('/tmp/malicious')"));
  assert.ok(r.pattern.test("require.extensions['.ts'] = handler"));
  assert.ok(r.pattern.test("sys.path.append('/tmp/evil')"));
  assert.ok(!r.pattern.test("const path = require('path')"));
});

test("PS-006 catches Windows registry modification via reg.exe or regedit", () => {
  const r = rule("PS-006");
  assert.ok(r.pattern.test("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Evil /d C:\\evil.exe"));
  assert.ok(r.pattern.test("reg import backdoor.reg"));
  assert.ok(r.pattern.test("regedit /s payload.reg"));
  assert.ok(r.pattern.test("regedit /i config.reg"));
  assert.ok(!r.pattern.test("reg query HKCU\\Software\\Microsoft"));
  assert.ok(!r.pattern.test("regedit"));
});

test("PS-007 catches LD_PRELOAD or suspicious LD_LIBRARY_PATH injection", () => {
  const r = rule("PS-007");
  assert.ok(r.pattern.test("LD_PRELOAD=/tmp/evil.so ./victim"));
  assert.ok(r.pattern.test("export LD_PRELOAD=malicious.so"));
  assert.ok(r.pattern.test("LD_LIBRARY_PATH=/tmp/fakelibs ./app"));
  assert.ok(r.pattern.test("LD_LIBRARY_PATH=/dev/shm/libs:$LD_LIBRARY_PATH"));
  assert.ok(!r.pattern.test("echo LD_PRELOAD is unset"));
  assert.ok(!r.pattern.test("LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH"));
});
