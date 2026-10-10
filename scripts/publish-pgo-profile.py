#!/usr/bin/env python3
"""Publish an immutable profile; verify every payload and upload registry last.

Use profile-artifacts.py release-tag --directory DIR to obtain the content-bound
technical release tag. Releases for the same upstream may coexist after retrain.
No asset is overwritten, and an existing committed registry is never trusted
without downloading and checking all its payloads.
"""
import argparse
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("profile_artifacts", Path(__file__).with_name("profile-artifacts.py"))
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--release", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    artifacts.publish(args.repository, args.release, args.directory)


if __name__ == "__main__":
    artifacts.cli(main)
