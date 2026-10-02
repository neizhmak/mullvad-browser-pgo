#!/usr/bin/env python3
"""Strictly restore the identity-bound official Node support checkpoint.

This read-only Release consumer never builds Node, renames an RBM output, or
accepts a missing cache. Both PGO targets must select the exact official archive.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys

from rbm_network import showconf

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pgo_support_identity", ROOT / "scripts/resolve-pgo-support-identity.py")
identity_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity_module)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--pgo-target", choices=("pgo-generate", "pgo-use"), required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--provenance", type=Path)
    parser.add_argument("--expected-release")
    parser.add_argument("--expected-identity")
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    args = parser.parse_args()
    if not args.repository or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository):
        parser.error("a safe repository owner/name is required")
    upstream = args.upstream.resolve(strict=True)
    identity = identity_module.resolve_identity(upstream)
    identity_sha = identity_module.canonical_sha(identity)
    release = identity_module.release_name(identity)
    if args.expected_identity is not None:
        identity_module.require(re.fullmatch(r"[0-9a-f]{64}", args.expected_identity) is not None
                                and args.expected_identity == identity_sha,
                                "Node support identity differs from expected checkpoint")
    identity_module.require(args.expected_release is None or args.expected_release == release,
                            "Node support release differs from expected checkpoint")
    selected = showconf(upstream, "firefox", "input_files_by_name/node",
                        identity_module.TARGETS + [args.pgo_target])
    identity_module.require(selected == identity["output_filename"],
                            "Firefox PGO target selected a different Node input")
    output = identity_module.no_symlink_path(args.output_directory)
    output.mkdir(parents=True, exist_ok=True)
    identity_path = output / "node-identity.json"
    identity_module.write_json(identity_path, identity)
    subprocess.run([sys.executable, str(ROOT / "scripts/rbm-release-artifacts.py"),
                    "restore-required", "--upstream", str(upstream), "--repository", args.repository,
                    "--release", release, "--stage", "node", "--identity-file", str(identity_path),
                    "--registry-dir", str(output / "registry")], check=True)
    record = identity_module.archive_record(upstream, identity)
    identity_module.verify_node_registry(output / "registry/registry-node.json", identity, record)
    if args.provenance:
        identity_module.require(not args.provenance.is_symlink(), "provenance must not be a symlink")
        identity_module.no_symlink_path(args.provenance)
        provenance = identity_module.load_json(args.provenance)
        identity_module.require(isinstance(provenance, dict), "provenance must be an object")
        identity_module.require(provenance.get("upstream_lock") == identity["upstream"],
                                "build provenance uses a different upstream lock")
        previous = provenance.get("build_support", {})
        if "build_support" in provenance:
            identity_module.require(isinstance(previous, dict) and set(previous) == {"node"},
                                    "invalid existing build_support provenance")
            identity_module.require(previous["node"] == record, "conflicting Node build_support provenance")
        provenance["build_support"] = {"node": record}
        identity_module.write_json(args.provenance, provenance)
    identity_module.write_json(output / "node-support.json", {"release": release, **record})
    print(f"Restored verified Node support {identity_sha}: {record['archive_filename']}")


if __name__ == "__main__":
    main()
