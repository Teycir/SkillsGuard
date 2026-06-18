#!/usr/bin/env python3
"""
Generate skillsguard_ascii.gif — animated terminal banner for GitHub READMEs.
Renders SkillsGuard as large styled terminal text.
Uses only Pillow.
"""

from PIL import Image, ImageDraw, ImageFont
import os

# ── Canvas & Palette ──────────────────────────────────────────────────────────
W, H       = 820, 240
BG         = (13, 17, 23)
GREEN      = (0, 255, 136)
GREEN_DIM  = (100, 210, 150)
TEXT_LIGHT = (195, 245, 220)
AMBER      = (240, 180, 40)

OUT_PATH = os.path.join(os.path.dirname(__file__), "public", "skillsguard_ascii.gif")

# ── Fonts ─────────────────────────────────────────────────────────────────────
MONO_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
MONO_REG  = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

F_TITLE  = ImageFont.truetype(MONO_BOLD, 56)
F_PROMPT = ImageFont.truetype(MONO_BOLD, 18)
F_TAG    = ImageFont.truetype(MONO_BOLD, 13)
F_STAT   = ImageFont.truetype(MONO_BOLD, 12)
F_BADGE  = ImageFont.truetype(MONO_BOLD, 11)
F_MOTTO  = ImageFont.truetype(MONO_REG,  12)

# ── Content ───────────────────────────────────────────────────────────────────
TITLE      = "SkillsGuard"
STATS      = ["[85+ rules]", "[12 categories]", "[zero deps]", "[MCP ready]", "[decode-first]"]
DESC_TEXT  = "Static security scanner for AI agent skill packages."
MOTTO_TEXT = '"Audit skills. Trust nothing. Ship safely."'
CMD_TEXT   = "skillsguard /path/to/skill"

# ── Layout ────────────────────────────────────────────────────────────────────
TITLE_Y  = 18
PROMPT_Y = TITLE_Y + 6
DIV1_Y   = 90
BADGE_Y  = 98
DIV2_Y   = 122
STAT_Y   = 130
MOTTO_Y  = 152
CMD_Y    = 175
CURSOR_Y = CMD_Y + 17

STAT_X = [18, 130, 266, 372, 474]

# ── Helpers ───────────────────────────────────────────────────────────────────
def base():
    img = Image.new("RGB", (W, H), BG)
    d   = ImageDraw.Draw(img)
    d.line([(0, 0),    (W, 0)],    fill=GREEN, width=2)
    d.line([(0, H-1),  (W, H-1)],  fill=GREEN, width=2)
    return img, d

def draw_title(d, text):
    d.text((18, PROMPT_Y), "$", font=F_PROMPT, fill=GREEN_DIM)
    d.text((18 + 22, TITLE_Y), text, font=F_TITLE, fill=GREEN)

def draw_divider(d, y, alpha=80):
    col = tuple(int(v * alpha // 255) for v in GREEN)
    d.line([(18, y), (W - 18, y)], fill=col, width=1)

def draw_badge_row(d):
    bw = 68
    d.rounded_rectangle([18, BADGE_Y, 18 + bw, BADGE_Y + 20], radius=3, fill=GREEN)
    d.text((23, BADGE_Y + 4), "SCANNER", font=F_BADGE, fill=BG)
    d.text((96, BADGE_Y + 4), DESC_TEXT, font=F_TAG, fill=TEXT_LIGHT)

def draw_stats(d, n):
    for i in range(min(n, len(STATS))):
        d.text((STAT_X[i], STAT_Y), STATS[i], font=F_STAT, fill=GREEN)

def draw_motto(d):
    d.text((18, MOTTO_Y), MOTTO_TEXT, font=F_MOTTO, fill=GREEN_DIM)

def draw_cmd(d, chars):
    d.text((18, CMD_Y), "$", font=F_STAT, fill=GREEN_DIM)
    pw = int(d.textlength("$ ", font=F_STAT))
    d.text((18 + pw, CMD_Y), CMD_TEXT[:chars], font=F_STAT, fill=GREEN)

def draw_cursor(d, after_cmd_chars=None):
    if after_cmd_chars is None:
        x = 18 + 22 + int(d.textlength(TITLE, font=F_TITLE)) + 4
    else:
        pw = int(d.textlength("$ ", font=F_STAT))
        cw = int(d.textlength(CMD_TEXT[:after_cmd_chars], font=F_STAT))
        x  = 18 + pw + cw
    d.rectangle([x, CURSOR_Y, x + 9, CURSOR_Y + 3], fill=GREEN)

def render(draw_fn, dur):
    img, d = base()
    draw_fn(d)
    frames.append(img.convert("P", palette=Image.ADAPTIVE, colors=64))
    durations.append(dur)

# ── Build frames ──────────────────────────────────────────────────────────────
frames, durations = [], []

# Phase 1 — title types in
for n in range(1, len(TITLE) + 1):
    def f(d, n=n):
        draw_title(d, TITLE[:n])
    render(f, 75)

# Phase 2 — brief pause
render(lambda d: draw_title(d, TITLE), 250)

# Phase 3 — divider + badge pop in
def after_title(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
render(after_title, 80)

def after_badge(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
render(after_badge, 120)

def after_div2(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
    draw_divider(d, DIV2_Y, alpha=50)
render(after_div2, 80)

# Phase 4 — stats appear one by one
for s in range(1, len(STATS) + 1):
    def f(d, s=s):
        draw_title(d, TITLE)
        draw_divider(d, DIV1_Y)
        draw_badge_row(d)
        draw_divider(d, DIV2_Y, alpha=50)
        draw_stats(d, s)
    render(f, 90)

# Phase 5 — motto
def after_motto(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
    draw_divider(d, DIV2_Y, alpha=50)
    draw_stats(d, len(STATS))
    draw_motto(d)
render(after_motto, 200)

# Phase 6 — command types in
def base_state(d):
    draw_title(d, TITLE)
    draw_divider(d, DIV1_Y)
    draw_badge_row(d)
    draw_divider(d, DIV2_Y, alpha=50)
    draw_stats(d, len(STATS))
    draw_motto(d)

for n in range(1, len(CMD_TEXT) + 1):
    def f(d, n=n):
        base_state(d)
        draw_cmd(d, n)
    render(f, 55)

# Phase 7 — cursor blinks (10 times)
def full_on(d):
    base_state(d)
    draw_cmd(d, len(CMD_TEXT))
    draw_cursor(d, len(CMD_TEXT))

def full_off(d):
    base_state(d)
    draw_cmd(d, len(CMD_TEXT))

for _ in range(10):
    render(full_on,  210)
    render(full_off, 210)

# Final hold
render(full_on, 2500)

# ── Save ──────────────────────────────────────────────────────────────────────
os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
frames[0].save(
    OUT_PATH,
    save_all=True,
    append_images=frames[1:],
    duration=durations,
    loop=0,
    optimize=True,
)
size_kb = os.path.getsize(OUT_PATH) // 1024
print(f"✅  {OUT_PATH}  ({size_kb} KB, {len(frames)} frames)")
