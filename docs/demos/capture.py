#!/usr/bin/env python3
"""Capture apisniff's real, colored terminal output to .ansi files.

The demo tapes replay these captures instead of running apisniff live on every
render: deterministic output, identical read-time pacing, and live sites are
touched exactly once (here), never on regeneration.

apisniff writes its human-readable panels to stderr (machine output goes to
stdout) and only emits color when that stream is a TTY, so we run it with a
pseudo-terminal on stderr and capture that. stdout is dropped.

Files are keyed "<command>-<first-arg>.ansi" to match the demo-bin shim.

Usage (from repo root, with a fresh binary):
    go build -o apisniff ./cmd/apisniff
    python3 docs/demos/capture.py probe costco.com
    python3 docs/demos/capture.py --key spec-pokeapi.co spec /path/to/bundle

  --key KEY   override the capture filename (default "<arg0>-<arg1>"); use it
              when the real arg is a bundle path but the demo types a domain.
"""
import os
import pty
import subprocess
import sys

OUT_DIR = os.path.join(os.path.dirname(__file__), "captures")


def capture(argv: list[str]) -> bytes:
    master, slave = pty.openpty()
    proc = subprocess.Popen(
        ["./apisniff", *argv],
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
    argv = sys.argv[1:]
    key = None
    if argv and argv[0] == "--key":
        key = argv[1]
        argv = argv[2:]
    if len(argv) < 2:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        print("usage: capture.py [--key KEY] COMMAND ARG [ARG ...]", file=sys.stderr)
        return 2
    if key is None:
        key = f"{argv[0]}-{argv[1]}"
    os.makedirs(OUT_DIR, exist_ok=True)
    data = capture(argv)
    if len(data) < 200:
        print(f"FAIL {key}: captured {len(data)} bytes (no panel)", file=sys.stderr)
        return 1
    path = os.path.join(OUT_DIR, f"{key}.ansi")
    with open(path, "wb") as fh:
        fh.write(data)
    print(f"  {key}.ansi  {len(data)} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
