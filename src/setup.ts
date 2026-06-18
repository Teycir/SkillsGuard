import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync } from "node:fs";
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
 * 
 * @param dryRun - If true, displays changes without writing them.
 */
export function setupMcp(dryRun = false): void {
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
        if (!dryRun && !existsSync(parentDir)) {
          mkdirSync(parentDir, { recursive: true, mode: 0o700 });
        }

        let configData: McpConfig = {};
        if (existsSync(configPath)) {
          const raw = readFileSync(configPath, "utf-8");
          try {
            configData = JSON.parse(raw) as McpConfig;
          } catch (err: unknown) {
            console.error(`Warning: Config file ${configPath} contains invalid JSON. Resetting to empty schema. Error: ${String(err)}`);
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

        const jsonOutput = JSON.stringify(configData, null, 2);

        if (dryRun) {
          console.log(`[Dry Run] Would write to: ${configPath}`);
          console.log(`[Dry Run] Content payload:\n${jsonOutput}\n`);
        } else {
          // Backup existing config if it exists
          if (existsSync(configPath)) {
            const backupPath = `${configPath}.bak`;
            copyFileSync(configPath, backupPath);
            console.log(`Created configuration backup at: ${backupPath}`);
          }
          writeFileSync(configPath, jsonOutput, { encoding: "utf-8", mode: 0o600 });
          console.log(`Registered MCP server configuration at: ${configPath}`);
        }
        configuredCount++;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        console.error(`Error configuring MCP path ${configPath}: ${msg}`);
      }
    }
  }

  if (configuredCount > 0) {
    if (dryRun) {
      console.log(`\n[Dry Run] Simulated registering SkillsGuard in ${configuredCount} configuration(s).`);
    } else {
      console.log(`\nSuccessfully registered SkillsGuard in ${configuredCount} configuration(s).`);
      console.log("AI agents will now automatically call 'scan_skill' tool when encountering skill files.");
    }
  } else {
    console.warn("\nWarning: Could not configure MCP. No config directories detected.");
  }
}
