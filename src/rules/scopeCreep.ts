import type { Rule } from "../types.js";

export const SCOPE_CREEP_RULES: readonly Rule[] = [
  {
    id: "SC-CR-001",
    category: "scope-creep",
    severity: "HIGH",
    pattern: /\.\.(?:\/|\\)\.\.(?:\/|\\)\.\.(?:\/|\\)\.\./,
    message: "Scope creep: deep directory traversal attempting to climb out of workspace root",
  },
  {
    id: "SC-CR-002",
    category: "scope-creep",
    severity: "HIGH",
    pattern: /\/etc\/(passwd|shadow|hosts|resolv\.conf|sudoers|environment)/i,
    message: "Scope creep: direct reference to sensitive absolute system paths",
  },
  {
    id: "SC-CR-003",
    category: "scope-creep",
    severity: "HIGH",
    pattern: /(?:\/|\\|['"]|\s|^)\.(ssh|aws|kube|gitconfig|bashrc|zshrc|profile|history|gnupg|docker)\b/i,
    message: "Scope creep: accessing user ssh/cloud credentials or shell history outside project bounds",
  },
];
