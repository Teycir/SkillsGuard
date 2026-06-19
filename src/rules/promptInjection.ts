import type { Rule } from "../types.js";

export const PROMPT_INJECTION_RULES: readonly Rule[] = [
  {
    id: "PI-001",
    category: "prompt-injection",
    severity: "CRITICAL",
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|constraints?|prompts?)/i,
    message: "Classic prompt injection: instructs Claude to ignore prior guidelines",
    remediation: "This phrase is the canonical prompt injection vector. If present in a skill, it must be removed — there is no legitimate use case for a skill instructing the model to ignore its prior guidelines.",
  },
  {
    id: "PI-002",
    category: "prompt-injection",
    severity: "CRITICAL",
    pattern: /forget\s+(everything|all|your|prior)\s*(you\s+)?(know|were|have|said|been)/i,
    message: "Prompt injection: attempts to wipe Claude's context or persona",
  },
  {
    id: "PI-003",
    category: "prompt-injection",
    severity: "CRITICAL",
    pattern: /you\s+are\s+now\s+(a\s+)?(different|new|unrestricted|jailbroken|DAN|evil|hacked)/i,
    message: "Persona hijack: attempts to redefine Claude as a different/unrestricted model",
  },
  {
    id: "PI-004",
    category: "prompt-injection",
    severity: "HIGH",
    pattern: /\[\s*SYSTEM\s*\]|\[INST\]|<\|system\|>|<\|im_start\|>|<\|endoftext\|>/i,
    message: "Fake system/instruction tokens: attempts to inject model-level directives",
  },
  {
    id: "PI-005",
    category: "prompt-injection",
    severity: "HIGH",
    pattern: /act\s+as\s+(if\s+you\s+are|a\s+)?(unrestricted|unfiltered|uncensored|no[\s-]?limit)/i,
    message: "Prompt injection: instructs Claude to act as an unrestricted model",
  },
  {
    id: "PI-006",
    category: "prompt-injection",
    severity: "HIGH",
    pattern: /disregard\s+(your\s+)?(safety|ethical|content)\s+(policy|policies|filter|guidelines?|rules?)/i,
    message: "Prompt injection: instructs Claude to disregard safety policies",
  },
  {
    id: "PI-007",
    category: "prompt-injection",
    severity: "HIGH",
    // Tightened to require that the action-verb and the "user/human/operator"
    // are both present within a short window, AND that a concealment object
    // (what/that/about/from + content) follows or precedes the user reference.
    //
    // This eliminates the common UX false-positive pattern:
    //   "do not mention the user's name"  ← user is the OBJECT, not the deceived party
    //   "do not tell the user their order number"  ← still matches (user is deceived party)
    //
    // Pattern reads: do not <verb> the user [that/what/about/from <something>]
    // OR: do not <verb> [to] the user [anything about <X>]
    // The key guard is (?:that|what|about|from|anything|it|this|the fact)\b within
    // 80 chars AFTER the user reference, confirming there's a concealment object.
    pattern: /\bdo\s+not\s+(?:tell|inform|reveal|disclose|say|notify)\s+(?:to\s+)?(?:the\s+)?(?:user|human|operator)\b.{0,80}(?:that|what|about|from|anything|it|this|the\s+fact)\b/i,
    message: "Secrecy directive: skill instructs Claude to hide specific actions or information from the user",
  },
  {
    id: "PI-008",
    category: "prompt-injection",
    severity: "MEDIUM",
    pattern: /always\s+respond\s+(with|in)\s+(json|xml|yaml)\s+and\s+(never|do\s+not)\s+(add|include)\s+any\s+(explanation|text|comment)/i,
    message: "Output hijack: forces structured output to suppress Claude's warnings",
  },
  {
    id: "PI-009",
    category: "prompt-injection",
    severity: "HIGH",
    pattern: /(translate|convert|relay|pass|forward)\s+(everything|all)\s+(the\s+)?(user\s+)?(say|says|sends?|types?|inputs?)\s+to/i,
    message: "Relay injection: skill may be forwarding user messages to an attacker",
  },
  {
    id: "PI-010",
    category: "prompt-injection",
    severity: "HIGH",
    pattern: /(fetch|load|download|get|read)\s+instructions?\s+from\s+https?:\/\//i,
    message: "Dynamic prompt injection: attempts to fetch/execute instructions from an external URL",
  },
  {
    id: "PI-011",
    category: "prompt-injection",
    severity: "HIGH",
    // This rule detects potential Unicode homoglyph attacks where attackers use visually similar characters
    // from different Unicode blocks (Cyrillic U+0400-U+04FF or IPA Extensions U+0250-U+02AF) combined with
    // prompt injection keywords. The pattern uses positive lookaheads to ensure both conditions are met:
    // 1. The text contains at least one Cyrillic or IPA character
    // 2. The text contains at least one prompt injection keyword (instruct, system, ignore, etc.)
    // This helps catch obfuscated injection attempts that might bypass simple ASCII-based pattern matching
    pattern: /(?=.*[\u0400-\u04FF\u0250-\u02AF])(?=.*(instruct|system|ignore|disregard|forget|prompt))/i,
    message: "Unicode homoglyph injection: Cyrillic/IPA lookalikes mixed with prompt-injection keywords",
    remediation: "Attackers use visually similar Cyrillic/phonetic characters (e.g., Cyrillic 'і' for Latin 'i') to bypass pattern matching. This text should be normalized or rejected.",
  },
];
