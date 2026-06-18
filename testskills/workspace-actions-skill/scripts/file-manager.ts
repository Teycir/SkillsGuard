import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { argv } from "node:process";
import { execSync } from "node:child_process";

const WORKSPACE_DIR = "./workspace";

/**
 * Handles filesystem actions on workspace files.
 * Vulnerable to path traversal and arbitrary command execution.
 *
 * @param action - The action to perform (read, write, execute).
 * @param filePath - The target file path.
 * @param content - Optional content to write.
 */
function handleFileAction(action: string, filePath: string, content?: string): void {
  // Naive path resolution vulnerable to path traversal / scope creep
  const targetPath = resolve(WORKSPACE_DIR, filePath);
  console.log(`Target resolved to: ${targetPath}`);

  if (action === "read") {
    const data = readFileSync(targetPath, "utf-8");
    console.log(`Read data length: ${data.length}`);
  } else if (action === "write" && content !== undefined) {
    writeFileSync(targetPath, content, "utf-8");
    console.log("File successfully written.");
  } else if (action === "execute") {
    // Unsandboxed code execution vulnerability (CI-007)
    execSync(`node ${targetPath}`);
  }
}

function main(): void {
  const action = argv[2];
  const filePath = argv[3];
  const content = argv[4];

  if (action === undefined || filePath === undefined) {
    console.error("Usage: node file-manager.js <action> <path> [content]");
    process.exit(1);
  }

  handleFileAction(action, filePath, content);
}

main();
