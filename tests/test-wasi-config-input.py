#!/usr/bin/env python3
"""Behavioral checks for the narrow, verified wasi-config source fallback."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/prepare-wasi-config-input.sh"

CONFIG = '''# pinned test fixture
version: '[% c("abbrev") %]'
git_url: https://git.savannah.gnu.org/git/config.git
git_hash: f992bcc08219edb283d2ab31dd3871a4a0e8220e
filename: '[% project %]-[% c("version") %].tar.[% c("compress_tar") %]'
'''


class WasiConfigInputTests(unittest.TestCase):
    def run_runner(self, primary="missing", mirror="valid", config_text=CONFIG):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "upstream"
            fake_bin = root / "bin"
            (upstream / "projects/wasi-config").mkdir(parents=True)
            fake_bin.mkdir()
            config = upstream / "projects/wasi-config/config"
            config.write_text(config_text, encoding="utf-8")

            # fake git script that inspects mode and behaves accordingly
            (fake_bin / "git").write_text(r'''#!/usr/bin/env bash
while (($#)); do
  if [[ $1 == clone ]]; then
    url=$3; stage=$4
    if [[ $url == https://git.savannah.gnu.org/* ]]; then mode=$PRIMARY_MODE; else mode=$MIRROR_MODE; fi
    [[ $mode != missing ]] || exit 22
    mkdir -p "$stage/.git"
    if [[ $mode == valid ]]; then
      echo f992bcc08219edb283d2ab31dd3871a4a0e8220e > "$stage/.git/head_commit"
    else
      echo badcommit00000000000000000000000000000000 > "$stage/.git/head_commit"
    fi
    exit 0
  fi
  if [[ $1 == -C ]]; then
    dir=$2; shift 2
    if [[ $1 == rev-parse ]]; then
      cat "$dir/.git/head_commit"
      exit 0
    fi
    if [[ $1 == remote && $2 == set-url ]]; then
      echo "$4" > "$dir/.git/remote_url"
      exit 0
    fi
    if [[ $1 == checkout ]]; then
      exit 0
    fi
  fi
  shift
done
''', encoding="utf-8")
            (fake_bin / "git").chmod(0o755)

            env = os.environ | {
                "UPSTREAM": str(upstream),
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "PRIMARY_MODE": primary,
                "MIRROR_MODE": mirror,
            }
            before = config.read_bytes()
            result = subprocess.run([RUNNER], env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    check=False)
            output = upstream / "git_clones/wasi-config"
            has_clone = output.is_dir() and (output / ".git").is_dir()
            return result, has_clone, before == config.read_bytes()

    def test_verified_primary_is_used_when_available(self):
        result, has_clone, config_unchanged = self.run_runner(primary="valid", mirror="missing")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(has_clone)
        self.assertTrue(config_unchanged)
        self.assertIn("Using verified wasi-config clone from official Savannah Git", result.stdout)

    def test_verified_mirror_fallback_is_published_when_primary_missing(self):
        result, has_clone, config_unchanged = self.run_runner(primary="missing", mirror="valid")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(has_clone)
        self.assertTrue(config_unchanged)
        self.assertIn("Using verified wasi-config clone from official freedesktop GitLab mirror", result.stdout)

    def test_invalid_commit_fails_closed(self):
        result, has_clone, _ = self.run_runner(primary="invalid", mirror="invalid")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(has_clone)

    def test_unrelated_upstream_configuration_fails_closed(self):
        unrelated = CONFIG.replace("git.savannah.gnu.org", "example.invalid")
        result, has_clone, config_unchanged = self.run_runner(config_text=unrelated)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(has_clone)
        self.assertTrue(config_unchanged)


if __name__ == "__main__":
    unittest.main()
