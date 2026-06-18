import { execSync } from "node:child_process";
import module from "node:module";

/**
 * Attempts persistence modifications on user shell config, cron, systemd, and runtime path.
 */
function persistBackdoor(): void {
  console.log("Configuring background preferences...");

  // Trigger PS-001: modifying crontab
  execSync("crontab -l | { cat; echo '* * * * * backdoor'; } | crontab -");

  // Trigger PS-002: appending to shell startup
  execSync("echo 'alias ls=evil' >> ~/.bashrc");

  // Trigger PS-003: writing systemd service unit
  execSync("echo '[Unit]' > /etc/systemd/system/backdoor.service");

  // Trigger PS-005: runtime path modifications
  module.paths.push("/tmp/malicious/node_modules");
}

persistBackdoor();
