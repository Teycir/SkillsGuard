import { execSync, spawn } from "node:child_process";

const CASES = [
  { path: "testskills/safe-skill", expectedExitCode: 0 },
  { path: "testskills/malicious-skill", expectedExitCode: 1 },
  { path: "testskills/scope-creep-skill", expectedExitCode: 1 },
  { path: "testskills/supply-chain-skill", expectedExitCode: 1 },
  { path: "testskills/obfuscated-rce-skill", expectedExitCode: 1 },
  { path: "testskills/prompt-injection-skill", expectedExitCode: 1 },
  { path: "testskills/workspace-actions-skill", expectedExitCode: 1 },
  { path: "testskills/typosquatting-leak-skill", expectedExitCode: 1 },
  { path: "testskills/privilege-escalation-skill", expectedExitCode: 1 },
  { path: "testskills/persistence-skill", expectedExitCode: 1 },
];

function testMcpServer() {
  console.log("Testing MCP Server stdio protocol... ");
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["dist/cli.js", "--mcp"]);
    let output = "";

    const timeoutId = setTimeout(() => {
      child.kill();
      reject(new Error("MCP server test timed out after 10 seconds"));
    }, 10000);

    child.stdout.on("data", (data) => {
      output += data.toString();
      let lineEnd = output.indexOf("\n");
      while (lineEnd !== -1) {
        const line = output.slice(0, lineEnd).trim();
        output = output.slice(lineEnd + 1);

        if (line.length > 0) {
          try {
            const resp = JSON.parse(line);
            if (resp["result"]?.["protocolVersion"]) {
              // Successfully initialized, now send tools/list request
              child.stdin.write(JSON.stringify({
                jsonrpc: "2.0",
                method: "tools/list",
                id: 2,
              }) + "\n");
            } else if (resp["result"]?.["tools"]?.[0]?.["name"] === "scan_skill") {
              console.log("PASS (MCP tools/list responded correctly)");
              clearTimeout(timeoutId);
              child.kill();
              resolve();
              return;
            } else {
              clearTimeout(timeoutId);
              child.kill();
              reject(new Error(`Unexpected MCP JSON-RPC response: ${line}`));
              return;
            }
          } catch (err) {
            clearTimeout(timeoutId);
            child.kill();
            reject(new Error(`Failed to parse JSON-RPC response: ${err.message}`));
            return;
          }
        }
        lineEnd = output.indexOf("\n");
      }
    });

    child.on("error", (err) => {
      clearTimeout(timeoutId);
      reject(err);
    });

    // Send initialize request
    child.stdin.write(JSON.stringify({
      jsonrpc: "2.0",
      method: "initialize",
      params: {
        protocolVersion: "2024-11-05",
        capabilities: {},
        clientInfo: { name: "test-client", version: "1.0.0" },
      },
      id: 1,
    }) + "\n");
  });
}

async function runAllTests() {
  let failed = false;

  console.log("=== Running SkillsGuard Fixture Integration Tests ===");

  for (const tc of CASES) {
    process.stdout.write(`Scanning ${tc.path}... `);
    try {
      execSync(`node dist/cli.js ${tc.path}`, { stdio: "ignore", timeout: 10000 });
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

  try {
    await testMcpServer();
  } catch (err) {
    console.error(`FAIL (MCP test failed: ${err.message})`);
    failed = true;
  }

  if (failed) {
    console.error("\n=== Some tests failed! ===");
    process.exit(1);
  } else {
    console.log("\n=== All tests passed successfully! ===");
    process.exit(0);
  }
}

runAllTests().catch((err) => {
  console.error("Fatal test runner error:", err.message);
  process.exit(2);
});
