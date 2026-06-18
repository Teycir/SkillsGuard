#!/usr/bin/env bash
#
# scripted-session.sh — drives the terminal session that terminalizer records.
# Every command here is real: real cat, real curl, real live API call.
# No content is fabricated; testskills/ fixtures already exist in this repo.

set -e

ROOT="/home/teycir/Repos/SkillsGuard"
API="https://skillsguard.apiskillsguard.workers.dev/scan"

type_line() {
  # Print a fake-typed prompt line so the GIF reads like a live terminal,
  # then actually sleep so terminalizer captures the pacing.
  echo "$ $1"
}

python3 "$(dirname "$0")/title_animation.py"
sleep 1

clear
echo "── SkillsGuard: scanning a real GitHub skill repo for malicious intent ──"
sleep 2
echo
type_line "cat malicious-skill/SKILL.md"
sleep 1
cat "$ROOT/testskills/malicious-skill/SKILL.md"
sleep 3
echo
type_line "curl -s --data-binary @malicious-skill/SKILL.md $API | jq ."
sleep 1
curl -s --data-binary @"$ROOT/testskills/malicious-skill/SKILL.md" "$API" | jq .
sleep 4

echo
echo "── Now a clean, benign skill ──"
sleep 2
echo
type_line "cat safe-skill/SKILL.md"
sleep 1
cat "$ROOT/testskills/safe-skill/SKILL.md"
sleep 3
echo
type_line "curl -s --data-binary @safe-skill/SKILL.md $API | jq ."
sleep 1
curl -s --data-binary @"$ROOT/testskills/safe-skill/SKILL.md" "$API" | jq .
sleep 4
