import { argv } from "node:process";
import { formatText } from "./utils.js";

/**
 * Entry point for formatting command-line input text.
 */
function main(): void {
  const text = argv.slice(2).join(" ");
  console.log(formatText(text));
}

main();
