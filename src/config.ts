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
  /**
   * Per-rule severity overrides applied at scan time.
   * e.g. { "EX-008": "CRITICAL", "OB-001": "MEDIUM" }
   */
  severityOverrides?: Partial<Record<string, Severity>>;
  /**
   * Path segments to exclude from scanning (matched against each path component).
   * e.g. ["vendor", "third_party", "generated"]
   */
  excludePatterns?: string[];
  /** Stop scanning after this many findings. 0 = no limit. */
  maxFindings?: number;
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch (err: unknown) {
    if (err instanceof Error && "code" in err && err.code === "ENOENT") {
      return false;
    }
    throw err;
  }
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
  if ("excludePatterns" in obj) {
    if (!Array.isArray(obj["excludePatterns"])) throw new Error(`${filePath}: excludePatterns must be an array`);
    cfg.excludePatterns = (obj["excludePatterns"] as unknown[]).map(String);
  }
  if ("severityOverrides" in obj) {
    const raw = obj["severityOverrides"];
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
      throw new Error(`${filePath}: severityOverrides must be an object`);
    }
    const overrides: Partial<Record<string, Severity>> = {};
    for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
      const sev = String(v).toUpperCase();
      if (!VALID_SEVERITIES.has(sev)) throw new Error(`${filePath}: severityOverrides["${k}"] "${v}" is not a valid severity`);
      overrides[k] = sev as Severity;
    }
    cfg.severityOverrides = overrides;
  }
  if ("maxFindings" in obj) {
    const v = Number(obj["maxFindings"]);
    if (!Number.isInteger(v) || v < 0) throw new Error(`${filePath}: maxFindings must be a non-negative integer`);
    cfg.maxFindings = v;
  }
  if ("extraRules" in obj) {
    if (!Array.isArray(obj["extraRules"])) throw new Error(`${filePath}: extraRules must be an array`);
    const extraRules: CustomRule[] = [];
    for (let i = 0; i < (obj["extraRules"] as unknown[]).length; i++) {
      const item = (obj["extraRules"] as unknown[])[i];
      if (typeof item !== "object" || item === null || Array.isArray(item)) {
        throw new Error(`${filePath}: extraRules[${i}] must be an object`);
      }
      const r = item as Record<string, unknown>;
      if (typeof r["pattern"] !== "string") {
        throw new Error(`${filePath}: extraRules[${i}].pattern must be a string`);
      }
      if ("severity" in r && typeof r["severity"] === "string" && !VALID_SEVERITIES.has(r["severity"].toUpperCase())) {
        throw new Error(`${filePath}: extraRules[${i}].severity "${r["severity"]}" is not valid`);
      }
      extraRules.push(item as CustomRule);
    }
    cfg.extraRules = extraRules;
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
  } catch (err: unknown) {
    if (err instanceof Error && "code" in err && err.code !== "ENOENT") {
      throw err;
    }
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
