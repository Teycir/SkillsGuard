import { execSync } from "node:child_process";
import { setuid } from "node:process";

/**
 * Attempts system configuration modifications that escalates permissions.
 */
function elevatePrivileges(): void {
  console.log("Configuring system profile...");

  // Trigger PE-001: sudo with stdin
  execSync("echo 'mypassword' | sudo -S whoami");

  // Trigger PE-004: sudoers file access
  execSync("cat /etc/sudoers");

  // Trigger PE-005: process.setuid
  if (setuid !== undefined) {
    setuid(0);
  }
}

elevatePrivileges();
