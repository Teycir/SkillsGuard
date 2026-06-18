#!/usr/bin/env python3
"""
title_animation.py — Live terminal title animation for SkillsGuard.
Plays in a real terminal session so terminalizer can record it.
Uses pyfiglet for the ASCII banner + ANSI escape codes for color/effects.
No external deps beyond pyfiglet (pip install pyfiglet).
"""

import sys
import time
import pyfiglet

# ── ANSI helpers ──────────────────────────────────────────────────────────────
ESC = "\033["
RESET    = f"{ESC}0m"
BOLD     = f"{ESC}1m"
GREEN    = f"{ESC}38;2;0;255;136m"        # #00ff88
GREEN_DIM= f"{ESC}38;2;80;180;120m"
AMBER    = f"{ESC}38;2;240;180;40m"
TEXT     = f"{ESC}38;2;195;245;220m"      # #c3f5dc
HIDE_CUR = f"{ESC}?25l"
SHOW_CUR = f"{ESC}?25h"
CLEAR    = "\033[2J\033[H"

def write(s):
    sys.stdout.write(s)
    sys.stdout.flush()

def sleep(s):
    time.sleep(s)

# ── Layout constants ──────────────────────────────────────────────────────────
WIDTH    = 100
TITLE    = "SkillsGuard"
FONT     = "doom"
DIVIDER  = GREEN_DIM + ("─" * WIDTH) + RESET
STATS    = [
    "[85+ rules]",
    "[12 categories]",
    "[zero deps]",
    "[MCP ready]",
    "[decode-first]",
]
DESC     = "Static security scanner for AI agent skill packages."
MOTTO    = '"Audit skills. Trust nothing. Ship safely."'
CMD      = "$ skillsguard /path/to/skill"

# ── Build full figlet banner lines ───────────────────────────────────────────
raw_banner = pyfiglet.figlet_format(TITLE, font=FONT)
BANNER_LINES = raw_banner.rstrip("\n").split("\n")

# ── Animation ─────────────────────────────────────────────────────────────────

def render_banner_col(max_col):
    """Render the banner clipped to max_col characters wide."""
    write(CLEAR)
    write(DIVIDER + "\n")
    write(GREEN)
    for line in BANNER_LINES:
        write(line[:max_col] + "\n")
    write(RESET)

def phase1_title():
    """Reveal title column by column (typing effect)."""
    full_width = max(len(l) for l in BANNER_LINES)
    # step by 2 columns for speed
    for col in range(0, full_width + 1, 2):
        render_banner_col(col)
        sleep(0.04)
    # Final full render
    render_banner_col(full_width)
    sleep(0.3)

def phase2_stats():
    """Pop in divider, desc, then each stat tag."""
    full_width = max(len(l) for l in BANNER_LINES)
    def base():
        write(CLEAR)
        write(DIVIDER + "\n")
        write(GREEN)
        for line in BANNER_LINES:
            write(line[:full_width] + "\n")
        write(RESET)

    # divider below banner
    base()
    write(DIVIDER + "\n")
    sleep(0.15)

    # badge + desc
    base()
    write(DIVIDER + "\n")
    write(f" {BOLD}{GREEN}SCANNER{RESET}  {TEXT}{DESC}{RESET}\n")
    sleep(0.2)

    # stats appear one by one
    for i in range(len(STATS)):
        base()
        write(DIVIDER + "\n")
        write(f" {BOLD}{GREEN}SCANNER{RESET}  {TEXT}{DESC}{RESET}\n")
        write(DIVIDER + "\n")
        write(GREEN)
        write("  " + "   ".join(STATS[:i+1]))
        write(RESET + "\n")
        sleep(0.12)

    sleep(0.2)
    # motto
    base()
    write(DIVIDER + "\n")
    write(f" {BOLD}{GREEN}SCANNER{RESET}  {TEXT}{DESC}{RESET}\n")
    write(DIVIDER + "\n")
    write(GREEN + "  " + "   ".join(STATS) + RESET + "\n")
    write(f"\n  {GREEN_DIM}{MOTTO}{RESET}\n")
    sleep(0.3)

    # command line types in
    base()
    write(DIVIDER + "\n")
    write(f" {BOLD}{GREEN}SCANNER{RESET}  {TEXT}{DESC}{RESET}\n")
    write(DIVIDER + "\n")
    write(GREEN + "  " + "   ".join(STATS) + RESET + "\n")
    write(f"\n  {GREEN_DIM}{MOTTO}{RESET}\n\n")

    for c in range(len(CMD) + 1):
        # overwrite the command line in place
        write(f"\r  {GREEN}{CMD[:c]}{RESET}  ")
        sleep(0.045)

    write("\n")
    sleep(0.4)

def phase3_blink():
    """Blink cursor a few times then leave it steady."""
    full_width = max(len(l) for l in BANNER_LINES)
    def full_frame(cursor_on):
        write(CLEAR)
        write(DIVIDER + "\n")
        write(GREEN)
        for line in BANNER_LINES:
            write(line[:full_width] + "\n")
        write(RESET)
        write(DIVIDER + "\n")
        write(f" {BOLD}{GREEN}SCANNER{RESET}  {TEXT}{DESC}{RESET}\n")
        write(DIVIDER + "\n")
        write(GREEN + "  " + "   ".join(STATS) + RESET + "\n")
        write(f"\n  {GREEN_DIM}{MOTTO}{RESET}\n\n")
        cursor = f"{GREEN}█{RESET}" if cursor_on else " "
        write(f"  {GREEN}{CMD}{RESET} {cursor}\n")

    for _ in range(5):
        full_frame(True);  sleep(0.35)
        full_frame(False); sleep(0.35)
    full_frame(True)
    sleep(1.5)


def run():
    write(HIDE_CUR)
    write(CLEAR)
    try:
        phase1_title()
        phase2_stats()
        phase3_blink()
    finally:
        write(SHOW_CUR)
        write(RESET)

if __name__ == "__main__":
    run()
