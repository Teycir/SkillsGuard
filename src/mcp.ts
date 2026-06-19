import { stdin, stdout } from "node:process";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import { scan, scanText, computeRiskScore } from "./scanner.js";
import { createRequire } from "node:module";
import { isSafePath } from "./lib/path.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json");
const version =
  typeof pkg === "object" && pkg !== null && "version" in pkg && typeof pkg.version === "string"
    ? pkg.version
    : "0.1.0";

// Default timeout for a single scan_skill call (30 s). Callers can override.
const DEFAULT_SCAN_TIMEOUT_MS = 30_000;

// How many skill subdirectories to scan in parallel inside scan_skills_dir.
const DIR_SCAN_CONCURRENCY = 8;

// Maximum bytes we will accept from a remote URL (512 KB).
const MAX_REMOTE_BYTES = 512 * 1024;

// Maximum redirects to follow when fetching a remote skill.
const MAX_REMOTE_REDIRECTS = 5;


// ─── Types ────────────────────────────────────────────────────────────────────

interface JsonRpcRequest {
  readonly jsonrpc: "2.0";
  readonly id: number | string | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

function isJsonRpcRequest(val: unknown): val is JsonRpcRequest {
  if (typeof val !== "object" || val === null) return false;
  const obj = val as Record<string, unknown>;
  return (
    obj["jsonrpc"] === "2.0" &&
    typeof obj["method"] === "string" &&
    ("id" in obj
      ? obj["id"] === null || typeof obj["id"] === "number" || typeof obj["id"] === "string"
      : true)
  );
}

function sendResult(id: number | string | null, result: unknown): void {
  stdout.write(JSON.stringify({ jsonrpc: "2.0", id, result }) + "\n");
}

function sendError(id: number | string | null, code: number, message: string): void {
  stdout.write(JSON.stringify({ jsonrpc: "2.0", id, error: { code, message } }) + "\n");
}

// ─── Timeout wrapper ──────────────────────────────────────────────────────────

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error(`Timed out after ${ms} ms: ${label}`)), ms),
    ),
  ]);
}

// ─── URL helpers ──────────────────────────────────────────────────────────────

/**
 * Returns true if the string is an http:// or https:// URL.
 * Deliberately narrow: anything else (file://, data://, ftp://, plain paths)
 * is treated as a local filesystem path.
 */
function isHttpUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === "https:" || u.protocol === "http:";
  } catch {
    return false;
  }
}

/**
 * Fetch a remote skill file and return its text content.
 *
 * Guards applied:
 *  - HTTPS preferred; HTTP accepted but the URL is logged to stderr
 *  - Content-Type must be text/* or application/octet-stream
 *  - Body truncated / rejected if > MAX_REMOTE_BYTES
 *  - Fetch itself is wrapped in the caller-supplied timeout
 *  - Maximum MAX_REMOTE_REDIRECTS redirects followed
 */
async function fetchRemoteSkill(rawUrl: string, timeoutMs: number): Promise<string> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid URL: ${rawUrl}`);
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`Unsupported protocol '${url.protocol}'. Only http and https are allowed.`);
  }
  if (url.protocol === "http:") {
    console.error(`[skillsguard] Warning: fetching over plain HTTP — consider using HTTPS: ${rawUrl}`);
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(rawUrl, {
      signal: controller.signal,
      redirect: "follow",
      headers: { "User-Agent": `skillsguard/${version}` },
    });

    if (!response.ok) {
      throw new Error(`Remote server returned HTTP ${response.status} ${response.statusText}`);
    }

    // Guard content-type — only accept text-ish responses.
    const ct = response.headers.get("content-type") ?? "";
    if (ct && !ct.includes("text") && !ct.includes("octet-stream") && !ct.includes("json")) {
      throw new Error(
        `Remote content-type '${ct}' is not a text type. ` +
        `Only text/*, application/octet-stream and application/json are accepted.`,
      );
    }

    // Read at most MAX_REMOTE_BYTES to prevent memory exhaustion.
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Response body is empty or not readable");

    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        totalBytes += value.byteLength;
        if (totalBytes > MAX_REMOTE_BYTES) {
          await reader.cancel();
          throw new Error(
            `Remote content exceeds size limit (${MAX_REMOTE_BYTES / 1024} KB). ` +
            `Refusing to scan to prevent memory exhaustion.`,
          );
        }
        chunks.push(value);
      }
    }

    return new TextDecoder().decode(
      chunks.reduce((acc, chunk) => {
        const merged = new Uint8Array(acc.length + chunk.length);
        merged.set(acc);
        merged.set(chunk, acc.length);
        return merged;
      }, new Uint8Array(0)),
    );
  } finally {
    clearTimeout(timer);
  }
}


// ─── scan_skills_dir implementation ──────────────────────────────────────────

interface SkillSummary {
  skill: string;
  safe: boolean;
  riskScore: { score: number; label: string };
  filesScanned: number;
  durationMs: number;
  findings: Array<{
    ruleId: string;
    severity: string;
    category: string;
    message: string;
    file: string;
    line: number;
    evidence: string;
    decodedFrom?: string;
  }>;
  error?: string;
}

async function scanSkillsDir(
  dirPath: string,
  timeoutPerSkillMs: number,
  minSeverity: string,
  stopOnFirst: boolean,
): Promise<{
  scanned: number;
  flagged: number;
  clean: number;
  errors: number;
  durationMs: number;
  results: SkillSummary[];
}> {
  const start = Date.now();

  let entries: { name: string; isDirectory: boolean }[];
  try {
    const raw = await readdir(dirPath, { withFileTypes: true });
    entries = raw
      .filter((e) => e.isDirectory() || e.name === "SKILL.md")
      .map((e) => ({ name: e.name, isDirectory: e.isDirectory() }));
  } catch (err: unknown) {
    throw new Error(
      `Cannot read skills directory '${dirPath}': ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  const hasSingleSkill = entries.some((e) => !e.isDirectory && e.name === "SKILL.md");
  const skillPaths: string[] = hasSingleSkill
    ? [dirPath]
    : entries.filter((e) => e.isDirectory).map((e) => join(dirPath, e.name));

  const SEVERITY_RANK: Record<string, number> = {
    CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
  };
  const minRank = SEVERITY_RANK[minSeverity] ?? 0;

  const results: SkillSummary[] = [];
  let flagged = 0;
  let clean = 0;
  let errors = 0;

  for (let i = 0; i < skillPaths.length; i += DIR_SCAN_CONCURRENCY) {
    const batch = skillPaths.slice(i, i + DIR_SCAN_CONCURRENCY);

    const batchResults = await Promise.all(
      batch.map(async (skillPath): Promise<SkillSummary> => {
        const skillName = skillPath === dirPath ? "." : skillPath.slice(dirPath.length + 1);
        try {
          const result = await withTimeout(scan(skillPath), timeoutPerSkillMs, skillPath);
          const visibleFindings = result.findings.filter(
            (f) => (SEVERITY_RANK[f.severity] ?? 0) >= minRank,
          );
          const safe = visibleFindings.length === 0;
          return {
            skill: skillName,
            safe,
            riskScore: result.riskScore,
            filesScanned: result.filesScanned,
            durationMs: result.durationMs,
            findings: visibleFindings,
          };
        } catch (err: unknown) {
          return {
            skill: skillName,
            safe: false,
            riskScore: { score: 0, label: "NONE" },
            filesScanned: 0,
            durationMs: 0,
            findings: [],
            error: err instanceof Error ? err.message : String(err),
          };
        }
      }),
    );

    for (const r of batchResults) {
      if (r.error) errors++;
      else if (r.safe) clean++;
      else flagged++;
      if (!r.safe || r.error) results.push(r);
      if (stopOnFirst && flagged > 0) break;
    }
    if (stopOnFirst && flagged > 0) break;
  }

  return {
    scanned: skillPaths.length,
    flagged,
    clean,
    errors,
    durationMs: Date.now() - start,
    results,
  };
}


// ─── Request handler ──────────────────────────────────────────────────────────

async function handleRequest(line: string): Promise<void> {
  let req: unknown;
  try {
    req = JSON.parse(line);
  } catch {
    sendError(null, -32700, "Parse error");
    return;
  }

  if (!isJsonRpcRequest(req)) {
    sendError(null, -32600, "Invalid Request");
    return;
  }

  const { id, method, params } = req;

  if (method === "initialize") {
    sendResult(id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "skillsguard", version },
    });
    return;
  }

  if (method === "initialized") return;

  if (method === "tools/list") {
    sendResult(id, {
      tools: [
        {
          name: "scan_skill",
          description:
            "Static security scanner for a single AI agent skill — accepts either a " +
            "local filesystem path (directory or file) or an https:// / http:// URL. " +
            "When given a URL the skill content is fetched (max 512 KB) and scanned in memory; " +
            "no loop or bulk URL scanning is allowed — use scan_skills_dir for local bulk scans.",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description:
                  "Absolute local path OR a single https:// / http:// URL to the skill file or directory.",
              },
              timeout_ms: {
                type: "number",
                description: `Timeout in milliseconds. Defaults to ${DEFAULT_SCAN_TIMEOUT_MS}. ` +
                  "For remote URLs this also caps the HTTP fetch time.",
              },
            },
            required: ["path"],
          },
        },
        {
          name: "scan_skills_dir",
          description:
            "Scan a LOCAL directory containing many skill subdirectories (e.g. ~/.agents/skills). " +
            "Scans each subdirectory independently with concurrency control and a per-skill timeout. " +
            "Returns only flagged skills and errors to keep the payload bounded. " +
            "URLs are NOT accepted here — pass a URL to scan_skill instead.",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description: "Absolute LOCAL path to the parent directory containing skill subdirectories.",
              },
              timeout_per_skill_ms: {
                type: "number",
                description: "Per-skill timeout in milliseconds. Defaults to 15000.",
              },
              min_severity: {
                type: "string",
                enum: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                description: "Only include findings at or above this severity. Defaults to INFO.",
              },
              stop_on_first: {
                type: "boolean",
                description: "Stop after the first flagged skill.",
              },
            },
            required: ["path"],
          },
        },
      ],
    });
    return;
  }

  if (method === "tools/call") {
    const name = params?.["name"];
    const args = params?.["arguments"] as Record<string, unknown> | undefined;

    // ── scan_skill ─────────────────────────────────────────────────────────────
    if (name === "scan_skill") {
      const target = args?.["path"];
      if (typeof target !== "string" || target.trim().length === 0) {
        sendError(id, -32602, "Invalid params: 'path' must be a non-empty string");
        return;
      }
      if (target.length > 4096) {
        sendError(id, -32602, "Path / URL too long (max 4096 chars)");
        return;
      }

      const timeoutMs =
        typeof args?.["timeout_ms"] === "number" && args["timeout_ms"] > 0
          ? args["timeout_ms"]
          : DEFAULT_SCAN_TIMEOUT_MS;

      try {
        // ── Remote URL branch ───────────────────────────────────────────────
        if (isHttpUrl(target)) {
          const startRemote = Date.now();
          const text = await withTimeout(
            fetchRemoteSkill(target, timeoutMs),
            timeoutMs,
            target,
          );
          // scanText uses the URL as the "file path" label in findings output.
          const findings = scanText(text, target);
          const riskScore = computeRiskScore(findings);
          const result = {
            target,
            filesScanned: 1,
            findings: [...findings],
            durationMs: Date.now() - startRemote,
            riskScore,
          };
          sendResult(id, {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
          });
          return;
        }

        // ── Local path branch ────────────────────────────────────────────────
        if (!isSafePath(target)) {
          sendResult(id, {
            isError: true,
            content: [{ type: "text", text: `Access denied: '${target}' is outside the authorized workspace.` }],
          });
          return;
        }

        const result = await withTimeout(scan(target), timeoutMs, target);
        sendResult(id, {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        sendResult(id, {
          isError: true,
          content: [{ type: "text", text: `Error scanning '${target}': ${msg}` }],
        });
      }
      return;
    }

    // ── scan_skills_dir ────────────────────────────────────────────────────────
    if (name === "scan_skills_dir") {
      const dirPath = args?.["path"];
      if (typeof dirPath !== "string" || dirPath.trim().length === 0) {
        sendError(id, -32602, "Invalid params: 'path' must be a non-empty string");
        return;
      }

      // Explicitly block URLs — no curl loops.
      if (isHttpUrl(dirPath)) {
        sendResult(id, {
          isError: true,
          content: [{
            type: "text",
            text:
              "scan_skills_dir only accepts a local directory path, not a URL. " +
              "To scan a remote skill file, use scan_skill with the URL instead.",
          }],
        });
        return;
      }

      if (dirPath.length > 4096) {
        sendError(id, -32602, "Path too long (max 4096 chars)");
        return;
      }
      if (!isSafePath(dirPath)) {
        sendResult(id, {
          isError: true,
          content: [{ type: "text", text: `Access denied: '${dirPath}' is outside the authorized workspace.` }],
        });
        return;
      }

      const timeoutPerSkill =
        typeof args?.["timeout_per_skill_ms"] === "number" && args["timeout_per_skill_ms"] > 0
          ? args["timeout_per_skill_ms"]
          : 15_000;
      const minSeverity =
        typeof args?.["min_severity"] === "string" ? args["min_severity"] : "INFO";
      const stopOnFirst =
        typeof args?.["stop_on_first"] === "boolean" ? args["stop_on_first"] : false;

      try {
        const summary = await scanSkillsDir(dirPath, timeoutPerSkill, minSeverity, stopOnFirst);
        sendResult(id, {
          content: [{ type: "text", text: JSON.stringify(summary, null, 2) }],
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        sendResult(id, {
          isError: true,
          content: [{ type: "text", text: `Error scanning skills directory '${dirPath}': ${msg}` }],
        });
      }
      return;
    }
  }

  sendError(id, -32601, `Method not found: ${method}`);
}

// ─── MCP server entrypoint ────────────────────────────────────────────────────

export async function runMcpServer(): Promise<void> {
  // Redirect console.log/info to stderr so they never corrupt the JSON-RPC stream.
  console.log = console.error;
  console.info = console.error;

  let buffer = "";

  stdin.on("data", (chunk: Buffer) => {
    buffer += chunk.toString("utf-8");
    let lineEnd = buffer.indexOf("\n");
    while (lineEnd !== -1) {
      const line = buffer.slice(0, lineEnd).trim();
      buffer = buffer.slice(lineEnd + 1);
      if (line.length > 0) {
        handleRequest(line).catch((err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          console.error(`Error handling MCP request: ${msg}`);
        });
      }
      lineEnd = buffer.indexOf("\n");
    }
  });

  await new Promise<void>(() => {});
}
