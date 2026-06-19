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

# Part 1: Cloud API - scan via curl (0-20s)
echo -e "${GREEN}[1/2]${NC} Cloud API: Scanning SAFE skill from Anthropic..."
echo -e "${BLUE}$ curl --data-binary @SKILL.md https://skillsguard.apiskillsguard.workers.dev/scan${NC}"
curl -sL https://raw.githubusercontent.com/anthropics/skills/main/skills/algorithmic-art/SKILL.md | \
  curl -s --data-binary @- https://skillsguard.apiskillsguard.workers.dev/scan | \
  jq '.'
sleep 2
echo ""

# Part 2: Local CLI - malicious + obfuscated (20-50s)
echo -e "${RED}[2/2]${NC} Local CLI: Detecting threats..."
skillsguard ~/Repos/SkillsGuard/testskills/malicious-skill --min-severity CRITICAL
echo ""
echo -e "  ${YELLOW}Obfuscated base64 payload...${NC}"
skillsguard ~/Repos/SkillsGuard/testskills/obfuscated-rce-skill --min-severity HIGH
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Demo Complete${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BLUE}Cloud API:${NC}  curl --data-binary @SKILL.md"
echo -e "             https://skillsguard.apiskillsguard.workers.dev/scan"
echo ""
echo -e "  ${BLUE}CLI:${NC}        npm install -g skillsguard"
echo -e "             skillsguard /path/to/skill"
echo ""
echo -e "  ${BLUE}MCP Server:${NC} skillsguard setup"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}github.com/Teycir/SkillsGuard${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
