#!/usr/bin/env python3
"""
run_recording.py — spawns terminalizer record inside a real PTY so it
can call setRawMode(), waits for the scripted session to finish, then
auto-presses Ctrl+D to save and exit.
"""
import os, sys, pty, time, select, subprocess, signal

TERMINALIZER = "/home/teycir/.nvm/versions/node/v20.20.0/bin/terminalizer"
REPO         = "/home/teycir/Repos/SkillsGuard"
OUT_YML      = f"{REPO}/demo/recording.yml"
CONFIG       = f"{REPO}/demo/config.yml"

cmd = [
    TERMINALIZER, "record", f"{REPO}/demo/recording",
    "--config", CONFIG,
    "--skip-sharing",
]

print(f"[run_recording] spawning: {' '.join(cmd)}")

master_fd, slave_fd = pty.openpty()

# Set terminal size: 100 cols × 38 rows (matches config.yml)
import fcntl, termios, struct
fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 38, 100, 0, 0))

proc = subprocess.Popen(
    cmd,
    stdin=slave_fd, stdout=slave_fd, stderr=slave_fd,
    cwd=REPO,
    env={**os.environ, "TERM": "xterm-256color", "COLUMNS": "100", "LINES": "38"},
    preexec_fn=os.setsid,
)
os.close(slave_fd)

buf = b""
session_done = False
sent_ctrlD   = False
start        = time.time()

print("[run_recording] session running …")
try:
    while True:
        elapsed = time.time() - start
        if proc.poll() is not None:
            print(f"[run_recording] process exited (rc={proc.returncode})")
            break

        try:
            r, _, _ = select.select([master_fd], [], [], 0.5)
        except (OSError, ValueError):
            break

        if r:
            try:
                chunk = os.read(master_fd, 4096)
            except OSError:
                break
            buf += chunk
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()

            # scripted-session.sh ends with `sleep 4` after the last curl.
            # Detect "safe" + "durationMs" in the last curl output as a signal
            # that the script is truly done, then send Ctrl+D.
            if not sent_ctrlD and b'"safe": true' in buf and b'"durationMs"' in buf:
                # Give the final sleep a moment to finish
                time.sleep(5)
                print("\n[run_recording] script finished — sending Ctrl+D")
                os.write(master_fd, b"\x04")
                sent_ctrlD = True

        # Safety timeout: 3 minutes
        if elapsed > 180 and not sent_ctrlD:
            print("\n[run_recording] timeout — sending Ctrl+D")
            os.write(master_fd, b"\x04")
            sent_ctrlD = True
        elif elapsed > 200:
            print("[run_recording] hard kill")
            proc.terminate()
            break

finally:
    try:
        os.close(master_fd)
    except OSError:
        pass
    proc.wait()

print(f"[run_recording] done. rc={proc.returncode}")
