#!/usr/bin/env python3
"""Run every lightweight suite, including historical hyphenated filenames."""
from pathlib import Path
import os
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    environment = os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}
    failures = []
    for path in sorted((root / "tests").glob("test*.py")):
        print(f"\n=== {path.relative_to(root)} ===", flush=True)
        status = subprocess.run([sys.executable, str(path), "-v"], cwd=root, env=environment).returncode
        if status:
            failures.append(str(path.relative_to(root)))
    shell_test = root / "tests/test-resolve-upstream.sh"
    if subprocess.run(["bash", str(shell_test)], cwd=root, env=environment).returncode:
        failures.append(str(shell_test.relative_to(root)))
    for path in sorted((root / "scripts").glob("*.sh")):
        if subprocess.run(["bash", "-n", str(path)], cwd=root, env=environment).returncode:
            failures.append(str(path.relative_to(root)))
    for path in list((root / "scripts").glob("*.py")) + list((root / "tests").glob("*.py")):
        try:
            compile(path.read_bytes(), str(path), "exec")
        except SyntaxError as error:
            print(error, file=sys.stderr)
            failures.append(str(path.relative_to(root)))
    if failures:
        print("Failed: " + ", ".join(failures), file=sys.stderr)
        return 1
    print("All lightweight suites and syntax checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
