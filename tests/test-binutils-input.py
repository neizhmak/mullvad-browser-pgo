#!/usr/bin/env python3
"""Behavioral checks for the narrow, verified Binutils source fallback."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/prepare-binutils-input.sh"

CONFIG = '''# pinned test fixture
version: 9.99
input_files:
  - URL: https://ftpmirror.gnu.org/gnu/binutils/binutils-[% c("version") %].tar.xz
    sig_ext: sig
    file_gpg_id: 1
    gpg_keyring: binutils.gpg
  - project: container-image
'''


class BinutilsInputTests(unittest.TestCase):
    def run_runner(self, mirror="missing", primary="valid", config_text=CONFIG):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upstream = root / "upstream"
            fake_bin = root / "bin"
            (upstream / "projects/binutils").mkdir(parents=True)
            (upstream / "keyring").mkdir()
            fake_bin.mkdir()
            config = upstream / "projects/binutils/config"
            config.write_text(config_text, encoding="utf-8")
            (upstream / "keyring/binutils.gpg").write_text("pinned keyring",
                                                            encoding="utf-8")

            (fake_bin / "curl").write_text(r'''#!/usr/bin/env bash
while (($#)); do
  if [[ $1 == --output ]]; then output=$2; shift 2; continue; fi
  url=$1; shift
done
if [[ $url == https://ftpmirror.gnu.org/* ]]; then mode=$MIRROR_MODE; else mode=$PRIMARY_MODE; fi
if [[ $mode == partial ]]; then printf partial > "$output"; exit 22; fi
[[ $mode != missing ]] || exit 22
if [[ $url == *.sig ]]; then printf '%s\n' "$mode" > "$output"; else printf tarball > "$output"; fi
''', encoding="utf-8")
            (fake_bin / "gpg").write_text(r'''#!/usr/bin/env bash
echo verify >> "$GPG_CALLS"
signature=${@: -2:1}
grep -qx valid "$signature"
''', encoding="utf-8")
            for executable in (fake_bin / "curl", fake_bin / "gpg"):
                executable.chmod(0o755)

            env = os.environ | {
                "UPSTREAM": str(upstream),
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "MIRROR_MODE": mirror,
                "PRIMARY_MODE": primary,
                "GPG_CALLS": str(root / "gpg-calls"),
            }
            before = config.read_bytes()
            result = subprocess.run([RUNNER], env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    check=False)
            output = upstream / "out/binutils"
            files = sorted(path.name for path in output.glob("binutils-*") if path.is_file())
            gpg_calls = ((root / "gpg-calls").read_text(encoding="utf-8").splitlines()
                         if (root / "gpg-calls").exists() else [])
            return result, files, gpg_calls, before == config.read_bytes()

    def test_verified_primary_fallback_is_published_without_modifying_config(self):
        result, files, gpg_calls, config_unchanged = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(files, ["binutils-9.99.tar.xz", "binutils-9.99.tar.xz.sig"])
        self.assertEqual(gpg_calls, ["verify"])
        self.assertTrue(config_unchanged)
        self.assertIn("Using verified Binutils input from GNU primary fallback", result.stdout)

    def test_invalid_or_missing_signature_is_rejected(self):
        for signature in ("invalid", "missing"):
            with self.subTest(signature=signature):
                result, files, gpg_calls, _ = self.run_runner(primary=signature)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(files, [])
                self.assertEqual(len(gpg_calls), 0 if signature == "missing" else 1)

    def test_partial_download_never_becomes_canonical_input(self):
        result, files, _, _ = self.run_runner(mirror="partial", primary="partial")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(files, [])

    def test_unrelated_upstream_configuration_fails_closed(self):
        unrelated = CONFIG.replace("ftpmirror.gnu.org", "example.invalid")
        result, files, gpg_calls, config_unchanged = self.run_runner(config_text=unrelated)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(files, [])
        self.assertEqual(gpg_calls, [])
        self.assertTrue(config_unchanged)


if __name__ == "__main__":
    unittest.main()
