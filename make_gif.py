#!/usr/bin/env python3
"""
Generate skillsguard_ascii.gif — animated terminal banner for GitHub READMEs.
Renders SkillsGuard as large styled terminal text (no ASCII art fragility).
Uses only Pillow.
"""

from PIL import Image, ImageDraw, ImageFont
import os

# ── Palette ───────────────────────────────────────────────────────────────────
W, H        = 820, 260
BG          = (13, 17, 23)
GREEN       = (0, 255, 136)
GREEN_DIM   = (110, 232, 164)
TEXT_LIGHT  = (195, 245, 220)
AMBER       = (240, 180, 40)

# ── Fonts ─────────────────────────────────────────────────────────────────────
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
MONO_REG  = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

F_TITLE   = ImageFont.truetype(MONO_BOLD, 52)   # "SkillsGuard"
F_PROMPT  = ImageFont.truetype(MONO_BOLD, 18)   # "$ " prompt
F_TAG     = ImageFont.truetype(MONO_BOLD, 13)
F_STAT    = ImageFont.truetype(MONO_BOLD, 12)
F_BADGE   = ImageFont.truetype(MONO_BOLD, 10)
F_MOTTO   = ImageFont.truetype(MONO_REG,  12)

# ── Content ───────────────────────────────────────────────────────────────────
STATS      = ["[65+ rules]", "[11 categories]", "[zero deps]", "[MCP ready]", "[decode-first]"]
BADGE_TEXT = "SCANNER"
DESC_TEXT  = "Static security scanner for AI agent skill packages."
MOTTO_TEXT = '"Audit skills. Trust nothing. Ship safely."'
CMD_TEXT   = "skillsguard /path/to/skill"

# ── Layout ────────────────────────────────────────────────────────────────────
TITLE_Y  = 20
PROMPT_Y = TITLE_Y + 2          # vertically aligned with top of title
DIV1_Y   = 92
BADGE_Y  = 100
DIV2_Y   = 126
STAT_Y   = 135
MOTTO_Y  = 158
CMD_Y    = 182
CURSOR_Y = CMD_Y + 20

STAT_X = [18, 130, 266, 372, 474]

OUT_PATH = "/home/teycir/Repos/SkillsGuard/public/skillsguard_ascii.gif"

# ── Helpers ───────────────────────────────────────────────────────────────────
def base():
    img = Image.new("RGB", (W, H), BG)
    d   = ImageDraw.Draw(img)
    d.line([(0, 0), (W, 0)],     fill=GREEN, width=2)
    d.line([(0, H-1), (W, H-1)], fill=GREEN, width=2)
    return img, d

def draw_title(d, text, color=GREEN):
    # "$ " prompt in dim green, then title in bright green
    d.text((18, PROMPT_Y), "$ ", font=F_PROMPT, fill=GREEN_DIM)
    pw = d.textlength("$ ", font=F_PROMPT)
    d.text((18 + pw, TITLE_Y), text, font=F_TITLE, fill=color)

def draw_divider(d, y, opacity=80):
    c = tuple(int(v * opacity // 255) for v in GREEN)
    d.line([(18, y), (W-18, y)], fill=c, width=1)

def draw_badge_row(d):
    bw = 62
    d.rounded_rectangle([18, BADGE_Y, 18+bw, BADGE_Y+20], radius=3, fill=GREEN)
    d.text((22, BADGE_Y+4), BADGE_TEXT, font=F_BADGE, fill=BG)
    d.text((90, BADGE_Y+4), DESC_TEXT, font=F_TAG, fill=TEXT_LIGHT)

def draw_stats(d, n):
    for i in range(min(n, len(STATS))):
        d.text((STAT_X[i], STAT_Y), STATS[i], font=F_STAT, fill=GREEN)

def draw_motto(d):
    d.text((18, MOTTO_Y), MOTTO_TEXT, font=F_MOTTO, fill=GREEN_DIM)

def draw_cmd(d, chars):
    # prompt
    d.text((18, CMD_Y), "$ ", font=F_STAT, fill=GREEN_DIM)
    pw = d.textlength("$ ", font=F_STAT)
    d.text((18+pw, CMD_Y), CMD_TEXT[:chars], font=F_STAT, fill=GREEN)

def draw_cursor(d, after_chars=None):
    if after_chars is None:
        x = 18
    else:
        pw  = d.textlength("$ ", font=F_STAT)
        cw  = d.textlength(CMD_TEXT[:after_chars], font=F_STAT)
        x   = 18 + pw + cw
    d.rectangle([x, CURSOR_Y, x+8, CURSOR_Y+3], fill=GREEN)

# ── Animation frames ──────────────────────────────────────────────────────────
# Phase 1: Title types in character by character
# Phase 2: Info rows appear
# Phase 3: Command types in
# Phase 4: Cursor blinks

TITLE = "SkillsGuard"
CHAR_DUR = 80    # ms per title char
INFO_DUR = 100
CMD_DUR  = 60    # ms per cmd char
BLINK    = 220

frames, durations = [], []

def add(dur, fn):
    img, d = base()
    fn(d)
    frames.append(img.convert("P", palette=Image.ADAPTIVE, colors=48))
    durations.append(dur)

# 1. Type title
for n in range(1, len(TITLE)+1):
    def f(d, n=n):
        draw_title(d, TITLE[:n])
        draw_cursor(d)   # cursor after title (approximate)
    add(CHAR_DUR, f)

# 2. Pause after title complete
def f(d):
    draw_title(d, TITLE)
add(300, f)

# 3. Divider snaps in
def f(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
add(80, f)

# 4. Badge + desc
def f(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
add(120, f)

# 5. Second divider
def f(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
    draw_divider(d, DIV2_Y, opacity=50)
add(80, f)

# 6. Stats one by one
for s in range(1, len(STATS)+1):
    def f(d, s=s):
        draw_title(d, TITLE)
        draw_divider(d, DIV1_Y)
        draw_badge_row(d)
        draw_divider(d, DIV2_Y, opacity=50)
        draw_stats(d, s)
    add(INFO_DUR, f)

# 7. Motto
def f(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
    draw_divider(d, DIV2_Y, opacity=50)
    draw_stats(d, len(STATS))
    draw_motto(d)
add(180, f)

# 8. Divider before command line
def f(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
    draw_divider(d, DIV2_Y, opacity=50)
    draw_stats(d, len(STATS))
    draw_motto(d)
    draw_divider(d, MOTTO_Y + 14, opacity=30)
add(80, f)

# 9. Command types in
for n in range(1, len(CMD_TEXT)+1):
    def f(d, n=n):
        draw_title(d, TITLE)
        draw_divider(d, DIV1_Y)
        draw_badge_row(d)
        draw_divider(d, DIV2_Y, opacity=50)
        draw_stats(d, len(STATS))
        draw_motto(d)
        draw_divider(d, MOTTO_Y + 14, opacity=30)
        draw_cmd(d, n)
    add(CMD_DUR, f)

# 10. Cursor blinks after full command (8 blinks)
def full(d, cur=False):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
    draw_divider(d, DIV2_Y, opacity=50)
    draw_stats(d, len(STATS))
    draw_motto(d)
    draw_divider(d, MOTTO_Y + 14, opacity=30)
    draw_cmd(d, len(CMD_TEXT))
    if cur:
        draw_cursor(d, len(CMD_TEXT))

for _ in range(8):
    add(BLINK, lambda d: full(d, cur=True))
    add(BLINK, lambda d: full(d, cur=False))

# 11. Long hold
add(2000, lambda d: full(d, cur=True))

# ── Save ──────────────────────────────────────────────────────────────────────
frames[0].save(
    OUT_PATH,
    save_all=True,
    append_images=frames[1:],
    duration=durations,
    loop=0,
    optimize=True,
)
print(f"✅  {OUT_PATH}  ({os.path.getsize(OUT_PATH)//1024} KB)  {len(frames)} frames")
