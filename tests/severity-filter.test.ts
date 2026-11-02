import test from "node:test";
import assert from "node:assert";
import { spawn, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { applyMinSeverity } from "../src/lib/severity-filter.js";
import type { Finding, Severity } from "../src/types.js";

// The production build, as users run it (`npm test` builds it first). The compiled
// copy under dist-test/src cannot start: it resolves ../package.json from dist-test/.
const CLI = fileURLToPath(new URL("../../dist/cli.js", import.meta.url));

// ~9.3 MB of harmless comment lines: over the 8 MB limit, so it is never read.
const OVERSIZE = ("# " + "abcdefghij".repeat(7) + "abcdefgh\n").repeat(115_000);

// Timestamp-mode .pyc: header only. Raises exactly one ordinary HIGH, SG-BYTECODE-001.
const PLAIN_PYC = (() => {
  const header = Buffer.alloc(16);
  header.writeUInt16LE(3531, 0);
  header.writeUInt8(0x0d, 2);
  header.writeUInt8(0x0a, 3);
  return header;
})();

function finding(severity: Severity, unanalyzed = false): Finding {
  return {
    ruleId: unanalyzed ? "SG-SKIP-001" : "X-001",
    category: "test",
    severity,
    message: "m",
    file: "f",
    line: 1,
    evidence: "",
    pattern: "",
    ...(unanalyzed ? { unanalyzed: true } : {}),
  };
}

async function withTree<T>(
  files: Record<string, string | Buffer>,
  run: (dir: string) => Promise<T> | T,
  root = tmpdir(),
): Promise<T> {
  const dir = mkdtempSync(join(root, "sg-minsev-"));
  try {
    for (const [name, content] of Object.entries(files)) {
      const full = join(dir, name);
      mkdirSync(dirname(full), { recursive: true });
      writeFileSync(full, content);
    }
    return await run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function runCli(dir: string, ...args: string[]) {
  const r = spawnSync(process.execPath, [CLI, dir, "--json", "--no-color", ...args], {
    encoding: "utf-8",
    maxBuffer: 32 * 1024 * 1024,
  });
  assert.ok(r.stdout, `no JSON on stdout (exit ${r.status}): ${r.stderr}`);
  return { status: r.status, result: JSON.parse(r.stdout) as { findings: Finding[]; riskScore: { score: number; label: string } } };
}

// ─── applyMinSeverity ────────────────────────────────────────────────────────

test("applyMinSeverity keeps findings at or above the threshold", () => {
  const all = (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const).map((s) => finding(s));
  assert.deepStrictEqual(applyMinSeverity(all, "HIGH").map((f) => f.severity), ["CRITICAL", "HIGH"]);
  assert.deepStrictEqual(applyMinSeverity(all, "CRITICAL").map((f) => f.severity), ["CRITICAL"]);
  assert.strictEqual(applyMinSeverity(all, "INFO").length, 5);
});

test("applyMinSeverity never drops unanalyzed findings, whatever their severity", () => {
  const kept = applyMinSeverity([finding("HIGH", true), finding("LOW", true), finding("HIGH")], "CRITICAL");
  assert.deepStrictEqual(kept.map((f) => f.severity), ["HIGH", "LOW"]);
  assert.ok(kept.every((f) => f.unanalyzed));
});

test("applyMinSeverity with an unrecognised level keeps everything", () => {
  assert.strictEqual(applyMinSeverity([finding("INFO"), finding("HIGH")], "bogus").length, 2);
});

// ─── CLI ─────────────────────────────────────────────────────────────────────

test("CLI: --min-severity CRITICAL does not hide an unreviewed file", async () => {
  await withTree({ "SKILL.md": "# Helper\n", "helper.py": OVERSIZE }, (dir) => {
    const { status, result } = runCli(dir, "--min-severity", "CRITICAL");
    assert.deepStrictEqual(result.findings.map((f) => f.ruleId), ["SG-SKIP-001"]);
    assert.strictEqual(result.riskScore.label, "HIGH");
    assert.strictEqual(status, 1);
  });
});

test("CLI: --min-severity still filters ordinary findings", async () => {
  await withTree({ "SKILL.md": "# Helper\n", "__pycache__/x.cpython-312.pyc": PLAIN_PYC }, (dir) => {
    const shown = runCli(dir, "--min-severity", "HIGH");
    assert.deepStrictEqual(shown.result.findings.map((f) => f.ruleId), ["SG-BYTECODE-001"]);

    const hidden = runCli(dir, "--min-severity", "CRITICAL");
    assert.deepStrictEqual(hidden.result.findings, []);
    assert.strictEqual(hidden.result.riskScore.label, "NONE");
    assert.strictEqual(hidden.status, 0);
  });
});

// ─── MCP scan_skills_dir ─────────────────────────────────────────────────────

/** Send initialize + one tools/call to a real `--mcp` server and return the parsed tool payload. */
function mcpScanSkillsDir(path: string, minSeverity: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, "--mcp"]);
    const timer = setTimeout(() => { child.kill(); reject(new Error("MCP call timed out")); }, 20_000);
    let buf = "";
    child.stdout.on("data", (chunk: Buffer) => {
      buf += chunk.toString();
      for (let nl = buf.indexOf("\n"); nl !== -1; nl = buf.indexOf("\n")) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        const msg = JSON.parse(line);
        if (msg.id === 1) {
          child.stdin.write(JSON.stringify({
            jsonrpc: "2.0", id: 2, method: "tools/call",
            params: { name: "scan_skills_dir", arguments: { path, min_severity: minSeverity } },
          }) + "\n");
        } else if (msg.id === 2) {
          clearTimeout(timer);
          child.kill();
          if (msg.error || msg.result?.isError) reject(new Error(line));
          else resolve(JSON.parse(msg.result.content[0].text));
        }
      }
    });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) + "\n");
  });
}

test("MCP scan_skills_dir: min_severity CRITICAL does not mark an unreviewed skill safe", async () => {
  // isSafePath only allows the working directory or home, so build the tree under cwd.
  await withTree({ "bigskill/SKILL.md": "# Helper\n", "bigskill/helper.py": OVERSIZE }, async (dir) => {
    const summary = await mcpScanSkillsDir(dir, "CRITICAL");
    assert.strictEqual(summary.flagged, 1);
    assert.strictEqual(summary.clean, 0);
    const skill = summary.results[0];
    assert.strictEqual(skill.safe, false);
    assert.deepStrictEqual(skill.findings.map((f: Finding) => f.ruleId), ["SG-SKIP-001"]);
    assert.strictEqual(skill.riskScore.label, "HIGH");
  }, process.cwd());
});

test("MCP scan_skills_dir: min_severity still hides ordinary findings", async () => {
  await withTree({ "pycskill/SKILL.md": "# Helper\n", "pycskill/__pycache__/x.cpython-312.pyc": PLAIN_PYC }, async (dir) => {
    const summary = await mcpScanSkillsDir(dir, "CRITICAL");
    assert.strictEqual(summary.clean, 1);
    assert.strictEqual(summary.flagged, 0);
  }, process.cwd());
});
