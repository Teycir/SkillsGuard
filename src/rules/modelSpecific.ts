/**
 * SkillsGuard — Model-specific attack rules
 *
 * These patterns target AI-specific threat vectors that have no equivalent
 * in traditional SAST tools:
 *
 *   MS-001..005  Tool / function-call manipulation
 *   MS-006..009  Context window & memory attacks
 *   MS-010..013  Multi-agent / orchestration hijacking
 *   MS-014..017  Model-specific jailbreak vocabulary
 *   MS-018..021  Agentic loop abuse (infinite tasks, self-replication)
 *   MS-022..024  Retrieval-Augmented Generation (RAG) poisoning
 *
 * References:
 *   - OWASP LLM Top 10 (LLM01–LLM10)
 *   - Anthropic usage policy — agentic misuse patterns
 *   - Greshake et al., "Not What You've Signed Up For" (indirect injection)
 */

import type { Rule } from "../types.js";

export const MODEL_SPECIFIC_RULES: readonly Rule[] = [

  // ── Tool / function-call manipulation ─────────────────────────────────────

  {
    id: "MS-001",
    category: "model-specific",
    severity: "CRITICAL",
    pattern: /call\s+(the\s+)?(bash|shell|terminal|execute|run_code|computer)\s+(tool|function)\s+(and\s+)?(run|execute|eval)/i,
    message: "Model-specific: skill explicitly instructs the model to call execution tools — tool-call injection",
  },
  {
    id: "MS-002",
    category: "model-specific",
    severity: "CRITICAL",
    pattern: /use\s+your\s+(bash|shell|computer|browser|execute)\s+(tool|capability|access)\s+to\s+(install|download|upload|exfiltrate|send)/i,
    message: "Model-specific: skill directs Claude to use agentic tools for harmful operations",
  },
  {
    id: "MS-003",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\btool[_\s-]?call[s]?\s*:\s*\{|\bfunction[_\s-]?call[s]?\s*:\s*\{|["']name['"]\s*:\s*["'](bash|computer|execute|shell|run_code)["']/i,
    message: "Model-specific: embedded JSON tool-call payload in skill content — may hijack agentic dispatch",
  },
  {
    id: "MS-004",
    category: "model-specific",
    severity: "HIGH",
    pattern: /<tool[_\s]?call>|<\/tool[_\s]?call>|<function[_\s]?call>|<\/function[_\s]?call>|<tool[_\s]?use>|<\/tool[_\s]?use>/i,
    message: "Model-specific: XML-style tool-call tags injected into skill — attempts to spoof model output format",
  },
  {
    id: "MS-005",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\banswer\s+as\s+if\s+(you\s+)?(already\s+)?called|\bpretend\s+(you\s+)?(have\s+)?executed|\bsimulate\s+(the\s+)?(output|result)\s+of\s+(running|calling|executing)/i,
    message: "Model-specific: skill instructs model to fabricate tool results — hallucination injection",
  },

  // ── Context window & memory attacks ───────────────────────────────────────

  {
    id: "MS-006",
    category: "model-specific",
    severity: "CRITICAL",
    pattern: /ignore\s+(all\s+)?(content|text|instructions?)\s+(above|before|prior|earlier)\s+(in\s+)?(this\s+)?(context|conversation|window|thread|prompt)/i,
    message: "Model-specific: context-window wipe — instructs model to discard all prior conversation",
  },
  {
    id: "MS-007",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\bCONTEXT\s*OVERFLOW\b|\bCONTEXT\s*RESET\b|\bSYSTEM\s*RESET\b|\bNEW\s*SESSION\b|\bCLEAR\s*MEMORY\b/i,
    message: "Model-specific: fake context-management signal injected into skill — attempts to reset model state",
  },
  {
    id: "MS-008",
    category: "model-specific",
    severity: "HIGH",
    pattern: /(store|remember|memorize|save)\s+(the\s+)?(following|this|these)\s+(instructions?|rules?|payload|commands?)\s+(in\s+(memory|your\s+context|your\s+mind)|for\s+later)/i,
    message: "Model-specific: skill attempts to plant persistent instructions in model memory",
  },
  {
    id: "MS-009",
    category: "model-specific",
    severity: "HIGH",
    pattern: /when\s+(the\s+user\s+)?(?:next\s+)?(?:asks?|says?|types?|mentions?)\s+.{0,60}\s+(?:you\s+(?:must|should|will)|always|immediately|silently)\s+/i,
    message: "Model-specific: conditional trigger — skill plants a future-action on specific user input (sleeper instruction)",
  },

  // ── Multi-agent / orchestration hijacking ─────────────────────────────────

  {
    id: "MS-010",
    category: "model-specific",
    severity: "CRITICAL",
    pattern: /\b(sub[-_\s]?agent|child[-_\s]?agent|worker[-_\s]?agent|orchestrat(?:or|ed)\s+agent)\b[^#\n]*(ignore|bypass|override|skip)\s+(?:your\s+|the\s+)?(safety|policy|guidelines?|rules?)/i,
    message: "Model-specific: orchestration hijack — sub-agent instructed to bypass safety rules",
  },
  {
    id: "MS-011",
    category: "model-specific",
    severity: "CRITICAL",
    pattern: /\bsend\s+(this\s+)?(message|payload|instruction|command)\s+to\s+(the\s+)?(all\s+)?(other\s+)?(agents?|models?|assistants?|claude|gpt|llm)/i,
    message: "Model-specific: agent-to-agent injection — skill instructs model to propagate malicious payload to other agents",
  },
  {
    id: "MS-012",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\bpass[\s-]?through\b[^#\n]*(instructions?|payload|content|message)\s+(to|into|onto)\s+(the\s+)?(next|downstream|child|sub)[\s-]?agent/i,
    message: "Model-specific: payload pass-through to downstream agent — lateral injection in multi-agent chain",
  },
  {
    id: "MS-013",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\bimpersonate\s+(another\s+)?(agent|model|assistant|tool|api|service)\b|\bpretend\s+to\s+be\s+(another\s+)?(agent|model|tool)\b/i,
    message: "Model-specific: skill instructs model to impersonate another agent or service",
  },

  // ── Model-specific jailbreak vocabulary ───────────────────────────────────

  {
    id: "MS-014",
    category: "model-specific",
    severity: "CRITICAL",
    // No /i flag: single-word personas (DAN, DUDE…) are always all-caps in the
    // wild; matching case-insensitively would hit common first names (Dan, Stan).
    // Multi-word phrases are listed in both common casings via alternation.
    pattern: /\b(DAN|DUDE|STAN|AIM|BasedGPT|BetterDAN)\b|Developer\s+Mode|Jailbreak\s+Mode|Evil\s+Bot|developer\s+mode|jailbreak\s+mode|evil\s+bot/,
    message: "Model-specific: known jailbreak persona name — classic role-play exploit",
  },
  {
    id: "MS-015",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\bdo\s+anything\s+now\b|\bunrestricted\s+mode\b|\bgod\s+mode\b|\bno\s*[-\s]?filter\s+mode\b|\bjailbreak\s+mode\b/i,
    message: "Model-specific: jailbreak mode phrase — attempts to disable model restrictions",
  },
  {
    id: "MS-016",
    category: "model-specific",
    severity: "HIGH",
    pattern: /respond\s+(only\s+)?in\s+(character|roleplay|RP|fictional\s+mode)\s+and\s+(never|do\s+not)\s+(break|leave|exit|drop)\s+(character|role|the\s+fiction)/i,
    message: "Model-specific: locked roleplay — skill forbids Claude from breaking character to give safety warnings",
  },
  {
    id: "MS-017",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\bHypothet(?:ically|ical(?:ly)?)\s*,?\s*(how\s+would\s+you|you\s+could|walk\s+me\s+through|explain\s+how\s+to)\b/i,
    message: "Model-specific: hypothetical framing used to elicit restricted content — common jailbreak preamble",
  },

  // ── Agentic loop abuse ────────────────────────────────────────────────────

  {
    id: "MS-018",
    category: "model-specific",
    severity: "HIGH",
    pattern: /repeat\s+(this|the\s+following|these)\s+(task|action|step|instruction|command)\s+(indefinitely|forever|in\s+a\s+loop|until\s+stopped|without\s+stopping)/i,
    message: "Model-specific: infinite task loop instruction — denial-of-service via agentic repetition",
  },
  {
    id: "MS-019",
    category: "model-specific",
    severity: "HIGH",
    pattern: /\b(spawn|create|start|launch|instantiate)\s+(a\s+)?(new|another|additional)\s+(copy|instance|version)\s+of\s+(yourself|this\s+agent|this\s+model|claude|the\s+assistant)/i,
    message: "Model-specific: self-replication directive — skill instructs model to spawn copies of itself",
  },
  {
    id: "MS-020",
    category: "model-specific",
    severity: "HIGH",
    pattern: /do\s+not\s+(ask|request|prompt|wait)\s+(for\s+)?(user\s+)?(approval|confirmation|permission|consent)\s+(before|prior\s+to)\s+(taking|executing|running|performing)\s+(action|step|command|task)/i,
    message: "Model-specific: approval bypass — skill instructs model to skip human confirmation on agentic actions",
  },
  {
    id: "MS-021",
    category: "model-specific",
    severity: "MEDIUM",
    pattern: /\bhide\s+(your\s+)?(actions?|steps?|tool\s+calls?|commands?|operations?)\s+from\s+(the\s+)?(user|human|operator|log|transcript)/i,
    message: "Model-specific: action concealment — skill instructs model to hide what it is doing",
  },

  // ── RAG / retrieval poisoning ──────────────────────────────────────────────

  {
    id: "MS-022",
    category: "model-specific",
    severity: "CRITICAL",
    pattern: /\[INST\s*OVERRIDE\]|\[SYSTEM\s*INJECT\]|\[HIDDEN\s*INSTRUCTION\]|\[INVISIBLE\s*COMMAND\]/i,
    message: "Model-specific: RAG injection marker — hidden instruction tags designed to survive retrieval and activate in context",
  },
  {
    id: "MS-023",
    category: "model-specific",
    severity: "HIGH",
    pattern: /<!--\s*(ignore|override|instruction|system|admin|hidden)[^>]{0,120}-->|\/\*\s*(ignore|override|hidden\s+instruction|system\s+prompt)[^*]{0,120}\*\//i,
    message: "Model-specific: hidden instruction in HTML/CSS comment — RAG poisoning via comment block",
  },
  {
    id: "MS-024",
    category: "model-specific",
    severity: "HIGH",
    pattern: /(when\s+retrieved|when\s+embedded|when\s+included|when\s+inserted)\s+(into|in)\s+(the\s+)?(context|prompt|conversation|chat)\s*,?\s*(you\s+)?(must|should|will)\s+(ignore|override|forget|disregard)/i,
    message: "Model-specific: time-delayed RAG injection — instruction activates only when the document is retrieved into a prompt",
  },
];
