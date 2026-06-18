/**
 * SkillsGuard — Dockerfile / container security rules
 *
 * Flags patterns that are dangerous when a skill provisions or configures
 * containers: privileged flags, root execution, secret baked into images,
 * curl-pipe-sh during build, and exposed dangerous ports.
 */

import type { Rule } from "../types.js";

export const DOCKER_RULES: readonly Rule[] = [
  // ── Privileged containers ────────────────────────────────────────────────
  {
    id: "DK-001",
    category: "docker",
    severity: "CRITICAL",
    pattern: /\bdocker\s+run\b[^#\n]*--privileged\b/i,
    message: "Docker: --privileged flag grants full host kernel access",
  },
  {
    id: "DK-002",
    category: "docker",
    severity: "HIGH",
    pattern: /\bdocker\s+run\b[^#\n]*--cap-add\s+(ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN)\b/i,
    message: "Docker: dangerous capability added to container",
  },

  // ── Root user in Dockerfile ──────────────────────────────────────────────
  {
    id: "DK-003",
    category: "docker",
    severity: "HIGH",
    pattern: /^USER\s+root\s*$/im,
    message: "Dockerfile: explicit USER root — container runs as host root",
  },
  {
    id: "DK-004",
    category: "docker",
    severity: "MEDIUM",
    pattern: /^RUN\s+.*\bchmod\s+(777|a\+[rwx]+)\b/im,
    message: "Dockerfile: world-writable chmod in RUN instruction",
  },

  // ── Secrets baked into image ────────────────────────────────────────────
  {
    id: "DK-005",
    category: "docker",
    severity: "CRITICAL",
    pattern: /^(ENV|ARG)\s+(API_KEY|SECRET|PASSWORD|TOKEN|ANTHROPIC|OPENAI|AWS_SECRET)\s*=/im,
    message: "Dockerfile: secret or API key baked into image as ENV/ARG",
  },

  // ── Curl-pipe-sh during build ────────────────────────────────────────────
  {
    id: "DK-006",
    category: "docker",
    severity: "CRITICAL",
    pattern: /^RUN\b[^#\n]*(curl|wget)\b[^#\n]*\|\s*(bash|sh|python|node)\b/im,
    message: "Dockerfile: RUN fetches and executes a remote script",
  },

  // ── Host volume mounts ────────────────────────────────────────────────────
  {
    id: "DK-007",
    category: "docker",
    severity: "HIGH",
    pattern: /\bdocker\s+run\b[^#\n]*-v\s+\/\s*:/i,
    message: "Docker: mounting host root filesystem into container",
  },
  {
    id: "DK-008",
    category: "docker",
    severity: "HIGH",
    pattern: /\bdocker\s+run\b[^#\n]*-v\s+\/etc:|\bdocker\s+run\b[^#\n]*-v\s+\/var\/run\/docker\.sock:/i,
    message: "Docker: mounting /etc or Docker socket — container escape risk",
  },

  // ── ADD vs COPY ───────────────────────────────────────────────────────────
  {
    id: "DK-009",
    category: "docker",
    severity: "LOW",
    pattern: /^ADD\s+https?:\/\//im,
    message: "Dockerfile: ADD from remote URL — use COPY + RUN curl for better caching and auditability",
  },
];
