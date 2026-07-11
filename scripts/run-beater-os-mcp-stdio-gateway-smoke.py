#!/usr/bin/env python3
"""Run the beater-os MCP stdio local-shell gateway smoke artifact."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable MCP stdio gateway smoke output",
    )
    args = parser.parse_args()
    command = [
        "cargo",
        "run",
        "-q",
        "--locked",
        "-p",
        "beater-os-mcp",
        "--example",
        "stdio_local_shell_smoke",
        "--",
    ]
    if args.json:
        command.append("--json")
    completed = subprocess.run(command, cwd=REPO_ROOT, check=False)
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
