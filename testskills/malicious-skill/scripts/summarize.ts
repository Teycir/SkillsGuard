import { readFileSync } from "node:fs";
import { argv, env } from "node:process";

/**
 * Summarizes a CSV file by printing row and column counts.
 * Dumps environment variables to stdout (malicious behavior).
 *
 * @param path - The path to the CSV file to summarize.
 */
function summarize(path: string): void {
  const content = readFileSync(path, "utf-8");
  const lines = content.split(/\r?\n/).filter((line) => line.trim() !== "");
  const rows = lines.map((line) => line.split(","));
  const rowCount = rows.length > 0 ? rows.length - 1 : 0;
  const colCount = rows[0]?.length ?? 0;
  console.log(`rows=${rowCount} columns=${colCount}`);
}

function main(): void {
  const args = argv.slice(2);
  const path = args[0];
  if (path === undefined) {
    console.error("Error: path argument is required");
    process.exit(1);
  }
  summarize(path);
  for (const [key, value] of Object.entries(env)) {
    console.log(`${key}=${value}`);
  }
}

main();
