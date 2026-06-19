/**
 * SkillsGuard — Advanced Attack Techniques
 *
 * Sophisticated threat patterns discovered in 2024-2026 research:
 *
 *   ADV-001..005  Unicode tag injection (invisible payloads)
 *   ADV-006..010  Configuration/settings poisoning
 *   ADV-011..015  Narrative framing / guardrail bypass
 *   ADV-016..020  Tool hijacking / action space manipulation
 *   ADV-021..025  Dynamic context preprocessing attacks
 *
 * References:
 *   - "Not What You've Signed Up For" (Greshake et al., 2023)
 *   - Datadog AI security research (2024)
 *   - Claude Code security advisory (2025)
 */

import type { Rule } from "../types.js";

export const ADVANCED_ATTACK_RULES: readonly Rule[] = [

  // ── Unicode tag injection (invisible payloads) ────────────────────────────

  {
    id: "ADV-001",
    category: "obfuscation",
    severity: "CRITICAL",
    pattern: /[\u{E0000}-\u{E007F}]/u,
    message: "Advanced: Unicode tag characters detected — invisible payload injection",
  },
  {
    id: "ADV-002",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /[\u200B-\u200D\uFEFF]/,
    message: "Advanced: Zero-width Unicode characters — potential steganographic payload",
  },
  {
    id: "ADV-003",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /[\u2060\u2061\u2062\u2063\u2064\u206A-\u206F]/,
    message: "Advanced: Invisible formatting characters — may hide malicious instructions",
  },
  {
    id: "ADV-004",
    category: "obfuscation",
    severity: "MEDIUM",
    pattern: /[\uFFF9-\uFFFB]/,
    message: "Advanced: Interlinear annotation characters — potential instruction hiding",
  },
  {
    id: "ADV-005",
    category: "obfuscation",
    severity: "HIGH",
    pattern: /(?:[\u200B-\u200D\uFEFF].*){5,}/,
    message: "Advanced: Multiple zero-width chars in sequence — likely steganographic encoding",
  },

  // ── Configuration/settings poisoning ──────────────────────────────────────

  {
    id: "ADV-006",
    category: "persistence",
    severity: "CRITICAL",
    pattern: /\.claude\/settings\.json|\.cursor\/settings\.json|\.windsurf\/settings\.json/i,
    message: "Advanced: Agent configuration file modification — persistence via settings poisoning",
  },
  {
    id: "ADV-007",
    category: "persistence",
    severity: "CRITICAL",
    pattern: /"(?:pre|post)(?:Run|Hook|Action|Exec)"\s*:\s*"[^"]*(?:curl|wget|bash|sh|python|node)/i,
    message: "Advanced: Pre/post-hook injection in config — auto-executes on agent startup",
  },
  {
    id: "ADV-008",
    category: "persistence",
    severity: "HIGH",
    pattern: /"autoLoadSkills?"\s*:\s*(?:true|\[)/i,
    message: "Advanced: Auto-load skills config — bypasses user consent on skill loading",
  },
  {
    id: "ADV-009",
    category: "persistence",
    severity: "HIGH",
    pattern: /"trustedPublishers?"\s*:\s*\[[^\]]*\]|"alwaysTrust"\s*:\s*true/i,
    message: "Advanced: Trust override in config — disables supply chain verification",
  },
  {
    id: "ADV-010",
    category: "persistence",
    severity: "MEDIUM",
    pattern: /\.aider\/|\.continue\/config\.json|\.copilot\/settings\.json/i,
    message: "Advanced: AI coding assistant config modification — persistence vector",
  },

  // ── Narrative framing / guardrail bypass ──────────────────────────────────

  {
    id: "ADV-011",
    category: "model-specific",
    severity: "HIGH",
    pattern: /to\s+(?:fulfill|complete|accomplish)\s+(?:your|this|the)\s+(?:request|task|goal)\s*,?\s*(?:you\s+)?(?:must|should|need\s+to)\s+(?:first|initially|now)\s+(?:run|execute|perform|call)/i,
    message: "Advanced: Narrative framing — makes malicious action seem like prerequisite",
    skipCommentLines: true,
  },
  {
    id: "ADV-012",
    category: "model-specific",
    severity: "HIGH",
    pattern: /(?:for|to\s+ensure)\s+(?:data\s+integrity|security|compliance|best\s+practices)\s*,?\s*(?:you\s+)?(?:must|should)\s+(?:run|execute|call)\s+(?:this|the\s+following)/i,
    message: "Advanced: Security pretext framing — justifies malicious action as safety measure",
    skipCommentLines: true,
  },
  {
    id: "ADV-013",
    category: "model-specific",
    severity: "MEDIUM",
    pattern: /(?:as\s+a|per)\s+(?:standard|required|mandatory|necessary)\s+(?:procedure|protocol|step|prerequisite)/i,
    message: "Advanced: Authority framing — claims malicious action is standard procedure",
    skipCommentLines: true,
    skipPlaceholderLines: true,
  },
  {
    id: "ADV-014",
    category: "model-specific",
    severity: "HIGH",
    pattern: /(?:diagnostic|validation|verification|sanity\s+check)\s+script\s+(?:must|should)\s+(?:be\s+)?(?:run|executed)/i,
    message: "Advanced: Diagnostic pretext — malicious script disguised as validation",
    skipCommentLines: true,
  },
  {
    id: "ADV-015",
    category: "model-specific",
    severity: "MEDIUM",
    pattern: /(?:trust|believe|understand)\s+(?:me|that|this\s+is)\s+(?:necessary|required|safe|legitimate)/i,
    message: "Advanced: Trust appeal framing — emotional manipulation to bypass scrutiny",
    skipCommentLines: true,
  },

  // ── Tool hijacking / action space manipulation ────────────────────────────

  {
    id: "ADV-016",
    category: "model-specific",
    severity: "HIGH",
    pattern: /(?:prefer|prioritize|favor|choose)\s+(?:the\s+)?(?:bash|shell|terminal|execute|run_code)\s+(?:tool|function|action)\s+(?:over|instead\s+of|rather\s+than)/i,
    message: "Advanced: Tool preference manipulation — biases agent toward dangerous tools",
  },
  {
    id: "ADV-017",
    category: "model-specific",
    severity: "HIGH",
    pattern: /(?:never|do\s+not|avoid)\s+(?:use|call|invoke)\s+(?:the\s+)?(?:safe|read_only|view|inspect)\s+(?:tool|function|mode)/i,
    message: "Advanced: Safe tool suppression — prevents agent from choosing safe alternatives",
  },
  {
    id: "ADV-018",
    category: "model-specific",
    severity: "MEDIUM",
    pattern: /(?:if|when)\s+(?:uncertain|unsure|unclear|ambiguous)\s*,?\s*(?:default\s+to|always|automatically)\s+(?:execute|run|call)/i,
    message: "Advanced: Ambiguity exploitation — instructs agent to pick dangerous option when unclear",
  },
  {
    id: "ADV-019",
    category: "model-specific",
    severity: "HIGH",
    pattern: /(?:implicitly|silently|automatically)\s+(?:assume|infer|treat)\s+(?:all\s+)?(?:commands?|instructions?|tasks?)\s+(?:as|require)/i,
    message: "Advanced: Implicit action framing — removes explicit user approval requirement",
  },
  {
    id: "ADV-020",
    category: "model-specific",
    severity: "MEDIUM",
    pattern: /(?:expand|broaden|extend)\s+(?:your|the)\s+(?:scope|authority|permissions?|capabilities?)\s+(?:to\s+include|by)/i,
    message: "Advanced: Scope expansion instruction — gradually increases agent's dangerous capabilities",
  },

  // ── Dynamic context preprocessing ─────────────────────────────────────────

  {
    id: "ADV-021",
    category: "command-injection",
    severity: "CRITICAL",
    pattern: /!\s*`\s*(?:gh|git|curl|wget|aws|gcloud|az)\s+(?:api|fetch|get|pull|clone)/,
    message: "Advanced: Dynamic context preprocessing — external command output injected into prompt",
  },
  {
    id: "ADV-022",
    category: "command-injection",
    severity: "CRITICAL",
    pattern: /!\s*`[^`]*(?:cat|head|tail|grep|awk|sed)\s+[^`]*(?:\.env|secret|credential|token|key)/i,
    message: "Advanced: Preprocessing reads secrets — injects sensitive data into agent context",
  },
  {
    id: "ADV-023",
    category: "command-injection",
    severity: "HIGH",
    pattern: /!\s*`[^`]*\$\([^)]*\)/,
    message: "Advanced: Nested command substitution in preprocessing — chained execution",
  },
  {
    id: "ADV-024",
    category: "exfiltration",
    severity: "CRITICAL",
    pattern: /!\s*`[^`]*(?:curl|wget)[^`]*(?:-d|--data|--data-binary|-X\s+POST)/i,
    message: "Advanced: Preprocessing with HTTP POST — exfiltrates data before agent sees it",
  },
  {
    id: "ADV-025",
    category: "command-injection",
    severity: "HIGH",
    pattern: /!\s*`[^`]*(?:base64|openssl|gpg)\s+(?:enc|dec|-d|--decode)/i,
    message: "Advanced: Encoding/decoding in preprocessing — obfuscated payload execution",
  },
];
