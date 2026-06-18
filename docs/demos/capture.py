#!/usr/bin/env python3
"""Capture apisniff's real, colored terminal output to .ansi files.

The probe demo replays these captures instead of hitting the network on every
render: deterministic output, identical read-time pacing, and the live sites
are touched exactly once (here), never on regeneration.

apisniff writes its human-readable panels to stderr (machine output goes to
stdout), and only emits color when that stream is a TTY, so we run it with a
pseudo-terminal on stderr and capture that. stdout is dropped.

Usage (from repo root, with a fresh binary):
    go build -o apisniff ./cmd/apisniff
    python3 docs/demos/capture.py costco.com target.com walmart.com
"""
import os
import pty
import subprocess
import sys

OUT_DIR = os.path.join(os.path.dirname(__file__), "captures")


def capture(site: str) -> bytes:
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        ["./apisniff", "probe", site],
        stdout=subprocess.DEVNULL,
        stderr=slave,
        stdin=slave,
    )
    os.close(slave)
    chunks = []
    try:
        while True:
            data = os.read(master, 4096)
            if not data:
                break
            chunks.append(data)
    except OSError:
        pass
    proc.wait()
    os.close(master)
    # Drop the pty's leading control bytes (EOT, backspaces) by cutting to the
    # first ANSI escape, where the colored panel actually begins.
    data = b"".join(chunks)
    esc = data.find(b"\x1b")
    return data[esc:] if esc != -1 else data


def main() -> int:
    sites = sys.argv[1:]
    if not sites:
        print("usage: capture.py SITE [SITE ...]", file=sys.stderr)
        return 2
    os.makedirs(OUT_DIR, exist_ok=True)
    for site in sites:
        name = site.split("//")[-1].split("/")[0]
        data = capture(site)
        if len(data) < 200:
            print(f"FAIL {site}: captured {len(data)} bytes (no panel)", file=sys.stderr)
            return 1
        path = os.path.join(OUT_DIR, f"{name}.ansi")
        with open(path, "wb") as fh:
            fh.write(data)
        print(f"  {name}.ansi  {len(data)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
