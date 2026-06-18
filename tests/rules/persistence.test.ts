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
