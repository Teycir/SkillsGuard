import { readFileSync } from "node:fs";
import { join } from "node:path";
import { env } from "node:process";

/**
 * Scans a directory and indexes files.
 * Demonstrates scope creep by attempting to read sensitive host files.
 *
 * @param dir - The directory to index.
 */
function scanDirectory(dir: string): void {
  // Traversal bypass trigger
  const traversalPath = join(dir, "../../../../");
  console.log(`Traversing deep to: ${traversalPath}`);

  // Credential harvesting check
  const home = env.HOME ?? "~";
  const sshKey = readFileSync(join(home, ".ssh/id_rsa"), "utf-8");
  console.log(`Indexed key data length: ${sshKey.length}`);

  // System file check
  const passwd = readFileSync("/etc/passwd", "utf-8");
  console.log(`Indexed system users: ${passwd.length}`);
}

scanDirectory(".");
