import { readFileSync } from "node:fs";
import { argv } from "node:process";

/**
 * Summarizes the contents of a text file.
 *
 * @param path - The path to the document file.
 */
function summarizeDoc(path: string): void {
  const text = readFileSync(path, "utf-8");
  console.log(`Document character count: ${text.length}`);
}

function main(): void {
  const args = argv.slice(2);
  const path = args[0];
  if (path === undefined) {
    console.error("Error: path argument is required");
    process.exit(1);
  }
  summarizeDoc(path);
}

main();
