import { stdin, stdout } from "node:process";
import { scan } from "./scanner.js";
import { createRequire } from "node:module";
import { isSafePath } from "./lib/path.js";

const require = createRequire(import.meta.url);
const pkg = require("../package.json");
const version = typeof pkg === "object" && pkg !== null && "version" in pkg && typeof pkg.version === "string" ? pkg.version : "0.1.0";

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
    ("id" in obj ? obj["id"] === null || typeof obj["id"] === "number" || typeof obj["id"] === "string" : true)
  );
}

function sendResult(id: number | string | null, result: unknown): void {
  const resp = {
    jsonrpc: "2.0",
    id,
    result,
  };
  stdout.write(JSON.stringify(resp) + "\n");
}

function sendError(id: number | string | null, code: number, message: string): void {
  const resp = {
    jsonrpc: "2.0",
    id,
    error: {
      code,
      message,
    },
  };
  stdout.write(JSON.stringify(resp) + "\n");
}

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
      capabilities: {
        tools: {},
      },
      serverInfo: {
        name: "skillsguard",
        version,
      },
    });
    return;
  }

  if (method === "initialized") {
    return;
  }

  if (method === "tools/list") {
    sendResult(id, {
      tools: [
        {
          name: "scan_skill",
          description: "Static security scanner for AI agent skills, tools, scripts, and directories. Run this tool to audit a target path before inspecting, installing, or executing it.",
          inputSchema: {
            type: "object",
            properties: {
              path: {
                type: "string",
                description: "The absolute path to the directory or file containing the skill/script to scan.",
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

    if (name === "scan_skill") {
      const targetPath = args?.["path"];
      if (typeof targetPath !== "string") {
        sendError(id, -32602, "Invalid params: 'path' must be a string");
        return;
      }

      if (targetPath.length > 4096) {
        sendError(id, -32602, "Path too long");
        return;
      }

      if (!isSafePath(targetPath)) {
        sendResult(id, {
          isError: true,
          content: [
            {
              type: "text",
              text: `Access denied: Target path '${targetPath}' is outside the authorized workspace or contains sensitive files.`,
            },
          ],
        });
        return;
      }

      try {
        const result = await scan(targetPath);
        sendResult(id, {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        });
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        sendResult(id, {
          isError: true,
          content: [
            {
              type: "text",
              text: `Error scanning target: ${msg}`,
            },
          ],
        });
      }
      return;
    }
  }

  sendError(id, -32601, `Method not found: ${method}`);
}

/**
 * Runs the zero-dependency JSON-RPC stdio MCP server.
 */
export async function runMcpServer(): Promise<void> {
  // Redirect stdout console logs to stderr to avoid corrupting MCP JSON-RPC protocol messages
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

  // Keep process alive
  await new Promise<void>(() => {});
}
