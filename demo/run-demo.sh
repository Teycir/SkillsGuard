#!/usr/bin/env bash
#
# SkillsGuard Cloud API demo
#
# Sends 8 real test fixtures from testskills/ to the live, free, hosted
# scan API and prints the actual JSON response for each one. No synthetic
# or hand-written attack payloads are introduced here — every file sent
# already exists in this repo under testskills/, is reviewed, and is
# covered by testskills/run-tests.js.
#
# Usage:
#   bash demo/run-demo.sh
#
# Requires: curl, jq (optional, for pretty-printing)

set -euo pipefail

API="https://skillsguard.apiskillsguard.workers.dev/scan"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES="$ROOT/testskills"

# Each entry: <label> <file to send>
CASES=(
  "1. Clean skill (no findings expected)|$FIXTURES/safe-skill/SKILL.md"
  "2. Prompt injection in SKILL.md|$FIXTURES/malicious-skill/SKILL.md"
  "3. Base64-obfuscated reverse shell (decode pipeline)|$FIXTURES/obfuscated-rce-skill/scripts/eval.ts"
  "4. Persistence: cron, bashrc, systemd, module path hijack|$FIXTURES/persistence-skill/scripts/persist.ts"
  "5. Privilege escalation: sudo -S, sudoers read, setuid(0)|$FIXTURES/privilege-escalation-skill/scripts/escalate.ts"
  "6. Secret exfiltration: AWS key in outbound fetch|$FIXTURES/typosquatting-leak-skill/scripts/client.ts"
  "7. Supply chain: npm install from a raw URL|$FIXTURES/supply-chain-skill/scripts/setup.js"
  "8. Scope creep: path traversal to /etc/passwd|$FIXTURES/workspace-actions-skill/SKILL.md"
)

have_jq=false
if command -v jq >/dev/null 2>&1; then
  have_jq=true
fi

for case in "${CASES[@]}"; do
  label="${case%%|*}"
  file="${case##*|}"

  echo "════════════════════════════════════════════════════════════════"
  echo "  $label"
  echo "  file: ${file#"$ROOT/"}"
  echo "════════════════════════════════════════════════════════════════"

  if [[ ! -f "$file" ]]; then
    echo "  (skipped — fixture not found: $file)"
    echo
    continue
  fi

  response="$(curl -s --data-binary @"$file" "$API")"

  if $have_jq; then
    echo "$response" | jq .
  else
    echo "$response"
  fi
  echo
done

echo "Done. All 8 requests were sent to the live SkillsGuard Cloud API:"
echo "  $API"
