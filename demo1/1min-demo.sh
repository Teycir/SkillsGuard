#!/bin/bash
# SkillsGuard 1-minute demo — visual impact optimized

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  SkillsGuard: Security Scanner for AI Agents${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Part 1: Clean skill - compact JSON (0-15s)
echo -e "${GREEN}[1/3]${NC} Scanning SAFE skill from Anthropic..."
curl -sL https://raw.githubusercontent.com/anthropics/skills/main/skills/algorithmic-art/SKILL.md | \
  curl -s --data-binary @- https://skillsguard.apiskillsguard.workers.dev/scan | \
  jq -r '"\(.safe | if . then "✅ SAFE" else "❌ UNSAFE" end) | Risk: \(.riskScore.label) (\(.riskScore.score)) | Findings: \(.findings | length)"'
echo ""

# Part 2: Malicious skill - FULL COLORED CLI OUTPUT (15-45s)
echo -e "${RED}[2/3]${NC} Scanning MALICIOUS test skill..."
skillsguard ~/Repos/SkillsGuard/testskills/malicious-skill --min-severity CRITICAL
echo ""

# Part 3: Local audit - visual loop (45-60s)
echo -e "${YELLOW}[3/3]${NC} Auditing ALL skills on this machine..."
for dir in ~/.kiro/skills ~/.agents/skills ~/.config/opencode/skill; do
  if [ -d "$dir" ]; then
    echo -n "  $(basename $dir): "
    if skillsguard "$dir" --json --min-severity HIGH --quiet 2>/dev/null; then
      echo -e "${GREEN}✅ SAFE${NC}"
    else
      echo -e "${RED}⚠️  FINDINGS${NC}"
    fi
  fi
done
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}Install: npm install -g skillsguard${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
