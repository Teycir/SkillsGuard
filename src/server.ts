import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { parse as parseUrl } from "node:url";
import { scanText } from "./scanner.js";

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let body = "";
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString("utf8");
      if (body.length > 2 * 1024 * 1024) { // 2MB limit
        reject(new Error("Payload too large"));
      }
    });
    req.on("end", () => resolve(body));
    req.on("error", (err) => reject(err));
  });
}

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const parsed = parseUrl(req.url ?? "", true);
  const path = parsed.pathname ?? "/";

  if (req.method === "GET" && (path === "/" || path === "/health")) {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "healthy", service: "skillsguard" }));
    return;
  }

  if (req.method === "POST" && path === "/scan") {
    let body: string;
    try {
      body = await readBody(req);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      res.writeHead(413, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: msg }));
      return;
    }

    let content = "";
    let filename = "SKILL.md";

    const contentType = req.headers["content-type"] ?? "";
    if (contentType.includes("application/json")) {
      try {
        const parsedJson = JSON.parse(body) as unknown;
        if (typeof parsedJson === "object" && parsedJson !== null) {
          const obj = parsedJson as Record<string, unknown>;
          content = typeof obj["content"] === "string" ? obj["content"] : "";
          filename = typeof obj["filename"] === "string" ? obj["filename"] : "SKILL.md";
        }
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Invalid JSON body" }));
        return;
      }
    } else {
      content = body;
      const queryFilename = parsed.query["filename"];
      if (typeof queryFilename === "string") {
        filename = queryFilename;
      }
    }

    const findings = scanText(content, filename);
    const result = {
      filename,
      findings,
      safe: findings.length === 0,
    };

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result, null, 2));
    return;
  }

  res.writeHead(404, { "Content-Type": "application/json" });
  res.end(JSON.stringify({ error: "Not found" }));
}

import type { Server } from "node:http";

/**
 * Starts the HTTP server on the specified port and returns the Server instance.
 */
export function startServer(port: number): Server {
  const server = createServer((req, res) => {
    handleRequest(req, res).catch((err: unknown) => {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`HTTP Server error: ${msg}`);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal Server Error" }));
      }
    });
  });

  server.listen(port, () => {
    console.error(`SkillsGuard HTTP server running at http://localhost:${port}/`);
    console.error(`To scan a skill:`);
    console.error(`  curl --data-binary @SKILL.md http://localhost:${port}/scan`);
  });

  return server;
}
