#!/usr/bin/env python3
"""Validate the effective RBM-rendered Firefox configure command."""
import argparse
from pathlib import Path

OPTION = "--enable-profile-generate=cross"


def configure_command(script):
    lines = script.splitlines()
    for index, line in enumerate(lines):
        if line.strip().startswith("./mach configure"):
            command = [line.strip()]
            while command[-1].endswith("\\") and index + 1 < len(lines):
                index += 1
                command.append(lines[index].strip())
            return "\n".join(command)
    raise SystemExit("rendered Firefox build has no ./mach configure command")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--pgo", type=Path, required=True)
    args = parser.parse_args()
    baseline = args.baseline.read_text(encoding="utf-8")
    pgo = args.pgo.read_text(encoding="utf-8")
    baseline_command = configure_command(baseline)
    pgo_command = configure_command(pgo)
    if OPTION in baseline or OPTION in baseline_command:
        raise SystemExit("normal baseline rendering unexpectedly enables PGO generation")
    if pgo.count(OPTION) != 1 or OPTION not in pgo_command:
        raise SystemExit("PGO option is not an argument of the rendered ./mach configure command")
    print("Verified baseline configure command has no PGO option.")
    print("Verified PGO configure command contains --enable-profile-generate=cross.")


if __name__ == "__main__":
    main()
