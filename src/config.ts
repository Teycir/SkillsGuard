/**
 * SkillsGuard — Config file loader
 *
 * Looks for `skillsguard.config.json` walking up from cwd, then from the
 * scan target's directory, stopping at a filesystem root or a `.git` boundary.
 *
 * Schema example:
 * {
 *   "minSeverity": "HIGH",
 *   "exitZero": false,
 *   "sarif": false,
 *   "noColor": false,
 *   "ignoreRules": ["EX-008"],
 *   "extraRules": [
 *     { "pattern": "my_secret_token", "severity": "CRITICAL", "message": "Leaked token" }
 *   ],
 *   "rulesOnly": false,
 *   "maxRiskScore": null
 * }
 *
 * CLI flags always override config file values.
 */

import { readFile, stat } from "node:fs/promises";
import { join, dirname, parse as parsePath } from "node:path";
import type { Severity, CustomRule } from "./types.js";

const CONFIG_FILENAME = "skillsguard.config.json";
const VALID_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

export interface SkillsGuardConfig {
  minSeverity?: Severity;
  exitZero?: boolean;
  sarif?: boolean;
  noColor?: boolean;
  ignoreRules?: string[];
  extraRules?: CustomRule[];
  rulesOnly?: boolean;
  /** Fail (exit 1) when the computed risk score exceeds this threshold [0-100]. */
  maxRiskScore?: number | null;
}

async function fileExists(p: string): Promise<boolean> {
  try { await stat(p); return true; } catch { return false; }
}

/**
 * Walk up the directory tree from `startDir`, looking for
 * `skillsguard.config.json`. Stops at a `.git` directory or filesystem root.
 */
async function findConfigFile(startDir: string): Promise<string | null> {
  let dir = startDir;
  while (true) {
    const candidate = join(dir, CONFIG_FILENAME);
    if (await fileExists(candidate)) return candidate;
    // Stop at git root
    if (await fileExists(join(dir, ".git"))) return null;
    const parent = dirname(dir);
    if (parent === dir) return null; // filesystem root
    dir = parent;
  }
}

function parseConfigRaw(raw: unknown, filePath: string): SkillsGuardConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${filePath}: config must be a JSON object`);
  }
  const obj = raw as Record<string, unknown>;
  const cfg: SkillsGuardConfig = {};

  if ("minSeverity" in obj) {
    const v = String(obj["minSeverity"]).toUpperCase();
    if (!VALID_SEVERITIES.has(v)) throw new Error(`${filePath}: invalid minSeverity "${obj["minSeverity"]}"`);
    cfg.minSeverity = v as Severity;
  }
  if ("exitZero"     in obj) cfg.exitZero     = Boolean(obj["exitZero"]);
  if ("sarif"        in obj) cfg.sarif        = Boolean(obj["sarif"]);
  if ("noColor"      in obj) cfg.noColor      = Boolean(obj["noColor"]);
  if ("rulesOnly"    in obj) cfg.rulesOnly    = Boolean(obj["rulesOnly"]);
  if ("maxRiskScore" in obj) {
    const v = obj["maxRiskScore"];
    cfg.maxRiskScore = v === null ? null : Number(v);
  }
  if ("ignoreRules" in obj) {
    if (!Array.isArray(obj["ignoreRules"])) throw new Error(`${filePath}: ignoreRules must be an array`);
    cfg.ignoreRules = (obj["ignoreRules"] as unknown[]).map(String);
  }
  if ("extraRules" in obj) {
    if (!Array.isArray(obj["extraRules"])) throw new Error(`${filePath}: extraRules must be an array`);
    cfg.extraRules = obj["extraRules"] as CustomRule[];
  }
  return cfg;
}

/**
 * Load and parse the nearest `skillsguard.config.json` for a given scan target.
 * Returns `null` if no config file is found, throws on parse errors.
 */
export async function loadConfig(targetPath: string): Promise<SkillsGuardConfig | null> {
  // Search from the target directory first, then from cwd
  let configPath: string | null = null;
  try {
    const s = await stat(targetPath);
    const searchDir = s.isDirectory() ? targetPath : dirname(targetPath);
    configPath = await findConfigFile(searchDir);
  } catch {
    // fall through to cwd search
  }
  if (!configPath) {
    configPath = await findConfigFile(process.cwd());
  }
  if (!configPath) return null;

  let text: string;
  try {
    text = await readFile(configPath, "utf-8");
  } catch (err) {
    throw new Error(`Cannot read ${configPath}: ${String(err)}`);
  }

  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new Error(`${configPath}: invalid JSON — ${String(err)}`);
  }

  return parseConfigRaw(raw, configPath);
}
