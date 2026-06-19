#!/bin/bash
# SkillsGuard demo part 2 — MCP integration and local audit

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  SkillsGuard: MCP Integration & Local Audit${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Part 1: MCP setup
echo -e "${GREEN}[1/2]${NC} MCP Server Setup..."
echo -e "${BLUE}$ skillsguard setup${NC}"
echo ""
echo -e "  ${GREEN}✓${NC} Registered MCP server in ~/.config/claude/mcp_config.json"
echo -e "  ${GREEN}✓${NC} scan_skill tool now available to Claude"
echo ""
sleep 2

# Part 2: Local audit
echo -e "${YELLOW}[2/2]${NC} Auditing ALL skills on this machine..."
echo ""
for dir in ~/.kiro/skills ~/.agents/skills ~/.config/opencode/skill; do
  if [ -d "$dir" ]; then
    echo -e "  ${BLUE}Scanning:${NC} $dir"
    if skillsguard "$dir" --json --min-severity HIGH --quiet 2>/dev/null; then
      echo -e "  ${GREEN}✅ SAFE${NC} — No HIGH/CRITICAL findings"
    else
      echo -e "  ${RED}⚠️  FINDINGS${NC} — Review required"
    fi
    echo ""
  fi
done

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}✓ Demo Complete${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${BLUE}MCP Server:${NC} skillsguard setup"
echo -e "  ${BLUE}CLI:${NC}        skillsguard /path/to/skill"
echo -e "  ${BLUE}Cloud API:${NC}  curl --data-binary @SKILL.md \\"
echo -e "             https://skillsguard.apiskillsguard.workers.dev/scan"
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}github.com/Teycir/SkillsGuard${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
