import { execSync } from "node:child_process";

const CASES = [
  { path: "testskills/safe-skill", expectedExitCode: 0 },
  { path: "testskills/malicious-skill", expectedExitCode: 1 },
  { path: "testskills/scope-creep-skill", expectedExitCode: 1 },
  { path: "testskills/supply-chain-skill", expectedExitCode: 1 },
  { path: "testskills/obfuscated-rce-skill", expectedExitCode: 1 },
  { path: "testskills/prompt-injection-skill", expectedExitCode: 1 },
  { path: "testskills/workspace-actions-skill", expectedExitCode: 1 },
  { path: "testskills/typosquatting-leak-skill", expectedExitCode: 1 },
];

let failed = false;

console.log("=== Running SkillsGuard Fixture Integration Tests ===");

for (const tc of CASES) {
  process.stdout.write(`Scanning ${tc.path}... `);
  try {
    execSync(`node dist/cli.js ${tc.path}`, { stdio: "ignore" });
    if (tc.expectedExitCode === 0) {
      console.log("PASS (Exited 0 as expected)");
    } else {
      console.log(`FAIL (Expected exit code ${tc.expectedExitCode}, got 0)`);
      failed = true;
    }
  } catch (error) {
    const actualExitCode = error.status;
    if (actualExitCode === tc.expectedExitCode) {
      console.log(`PASS (Exited ${actualExitCode} as expected)`);
    } else {
      console.log(`FAIL (Expected exit code ${tc.expectedExitCode}, got ${actualExitCode})`);
      failed = true;
    }
  }
}

if (failed) {
  console.error("\n=== Some tests failed! ===");
  process.exit(1);
} else {
  console.log("\n=== All tests passed successfully! ===");
  process.exit(0);
}
