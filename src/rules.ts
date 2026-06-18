/**
 * SkillsGuard — Rule registry
 * Each rule has a unique ID, category, severity, regex pattern, and message.
 * Patterns are matched against raw file content AND decoded blobs.
 */

import type { Rule } from "./types.js";

import { PROMPT_INJECTION_RULES } from "./rules/promptInjection.js";
import { EXFILTRATION_RULES } from "./rules/exfiltration.js";
import { COMMAND_INJECTION_RULES } from "./rules/commandInjection.js";
import { SUPPLY_CHAIN_RULES } from "./rules/supplyChain.js";
import { PERSISTENCE_RULES } from "./rules/persistence.js";
import { PRIVILEGE_ESCALATION_RULES } from "./rules/privilegeEscalation.js";
import { FILE_SYSTEM_RULES } from "./rules/fileSystem.js";
import { NETWORK_RULES } from "./rules/network.js";
import { OBFUSCATION_RULES } from "./rules/obfuscation.js";
import { SECRET_HARVESTING_RULES } from "./rules/secretHarvesting.js";
import { SCOPE_CREEP_RULES } from "./rules/scopeCreep.js";

export const RULES: Rule[] = [
  ...PROMPT_INJECTION_RULES,
  ...EXFILTRATION_RULES,
  ...COMMAND_INJECTION_RULES,
  ...SUPPLY_CHAIN_RULES,
  ...PERSISTENCE_RULES,
  ...PRIVILEGE_ESCALATION_RULES,
  ...FILE_SYSTEM_RULES,
  ...NETWORK_RULES,
  ...OBFUSCATION_RULES,
  ...SECRET_HARVESTING_RULES,
  ...SCOPE_CREEP_RULES,
];
