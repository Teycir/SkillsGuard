import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { env, argv } from "node:process";

interface McpServerConfig {
  readonly command: string;
  readonly args: readonly string[];
  readonly disabled?: boolean;
  readonly autoApprove?: readonly string[];
}

interface McpConfig {
  mcpServers?: Record<string, McpServerConfig>;
}

/**
 * Automatically registers SkillsGuard as an MCP server in the user's Claude configurations.
 */
export function setupMcp(): void {
  const home = env.HOME ?? env.USERPROFILE ?? "";
  if (!home) {
    console.error("Error: Could not locate home directory.");
    process.exit(1);
  }

  // Determine the absolute path to the cli runner script
  const scriptPath = resolve(argv[1] ?? join(process.cwd(), "dist", "cli.js"));

  const configPaths = [
    // Claude CLI/Code config
    join(home, ".config", "claude", "mcp_config.json"),
    // Claude Desktop config (macOS)
    join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
    // Claude Desktop config (Windows)
    join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json"),
  ];

  let configuredCount = 0;

  for (const configPath of configPaths) {
    const isClaudeCliPath = configPath.includes(".config/claude");
    // Only configure if the config exists, or if it is the CLI path (we create it)
    if (existsSync(configPath) || isClaudeCliPath) {
      try {
        const parentDir = join(configPath, "..");
        if (!existsSync(parentDir)) {
          mkdirSync(parentDir, { recursive: true });
        }

        let configData: McpConfig = {};
        if (existsSync(configPath)) {
          const raw = readFileSync(configPath, "utf-8");
          try {
            configData = JSON.parse(raw) as McpConfig;
          } catch {
            configData = {};
          }
        }

        if (!configData.mcpServers) {
          configData.mcpServers = {};
        }

        configData.mcpServers["skillsguard"] = {
          command: "node",
          args: [scriptPath, "--mcp"],
          disabled: false,
          autoApprove: [],
        };

        writeFileSync(configPath, JSON.stringify(configData, null, 2), "utf-8");
        console.log(`Registered MCP server configuration at: ${configPath}`);
        configuredCount++;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`Error configuring MCP path ${configPath}: ${msg}`);
      }
    }
  }

  if (configuredCount > 0) {
    console.log(`\nSuccessfully registered SkillsGuard in ${configuredCount} configuration(s).`);
    console.log("AI agents will now automatically call 'scan_skill' tool when encountering skill files.");
  } else {
    console.warn("\nWarning: Could not configure MCP. No config directories detected.");
  }
}
