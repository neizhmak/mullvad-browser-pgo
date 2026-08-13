#!/usr/bin/env python3
"""Restore and publish immutable RBM outputs using a GitHub Release."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def run(*args):
    subprocess.run(args, check=True)


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def lock(root):
    with (root / "upstream.lock.json").open(encoding="utf-8") as stream:
        return json.load(stream)


def safe_output(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "out":
        raise SystemExit(f"unsafe RBM output path in registry: {relative}")
    return root / path


def release_exists(repository, release):
    return subprocess.run(
        ["gh", "release", "view", release, "--repo", repository],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def restore(args, root):
    destination = Path(args.upstream)
    registries = Path(args.registry_dir)
    registries.mkdir(parents=True, exist_ok=True)
    if not release_exists(args.repository, args.release):
        return
    run("gh", "release", "download", args.release, "--repo", args.repository,
        "--dir", str(registries), "--pattern", "registry-*.json", "--clobber")
    expected_lock = lock(root)
    for registry in sorted(registries.glob("registry-*.json")):
        data = json.loads(registry.read_text(encoding="utf-8"))
        if data.get("upstream") != expected_lock:
            raise SystemExit(f"provenance mismatch in {registry.name}")
        for artifact in data.get("artifacts", []):
            output = safe_output(destination, artifact["path"])
            asset = registries / artifact["asset"]
            run("gh", "release", "download", args.release, "--repo", args.repository,
                "--dir", str(registries), "--pattern", artifact["asset"], "--clobber")
            if asset.stat().st_size != artifact["size"] or digest(asset) != artifact["sha256"]:
                raise SystemExit(f"published artifact identity mismatch: {artifact['asset']}")
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(asset, output)
            if output.name != artifact["filename"]:
                raise SystemExit(f"filename mismatch in {registry.name}")


def snapshot(args):
    upstream = Path(args.upstream)
    paths = sorted(str(path.relative_to(upstream)) for path in (upstream / "out").glob("**/*") if path.is_file())
    Path(args.file).write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")


def publish(args, root):
    upstream = Path(args.upstream)
    before = set(Path(args.before).read_text(encoding="utf-8").splitlines())
    paths = sorted(path for path in (upstream / "out").glob("**/*")
                   if path.is_file() and str(path.relative_to(upstream)) not in before)
    provenance = lock(root)
    artifacts = []
    for path in paths:
        relative = str(path.relative_to(upstream))
        project = Path(relative).parts[1]
        asset = f"rbm-{provenance['commit'][:12]}--{project}--{path.name}"
        artifacts.append({"project": project, "filename": path.name, "path": relative,
                          "asset": asset, "sha256": digest(path), "size": path.stat().st_size})
    registry = Path(args.registry_dir) / f"registry-{args.stage}.json"
    registry.parent.mkdir(parents=True, exist_ok=True)
    if registry.exists():
        existing = json.loads(registry.read_text(encoding="utf-8"))
        if existing.get("upstream") != provenance or existing.get("stage") != args.stage:
            raise SystemExit(f"existing stage registry identity mismatch: {registry.name}")
        if paths:
            raise SystemExit(f"registered stage unexpectedly produced new outputs: {args.stage}")
        print(f"Stage already published and fully restored: {args.stage}")
        return
    registry.write_text(json.dumps({"schema": 1, "stage": args.stage,
                                    "upstream": provenance, "artifacts": artifacts},
                                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not release_exists(args.repository, args.release):
        run("gh", "release", "create", args.release, "--repo", args.repository,
            "--title", f"RBM dependencies for {provenance['tag']}",
            "--notes", "Unmodified outputs produced by the pinned official RBM recipes.")
    # The registry is uploaded last: it is the commit record for this stage.
    for path, artifact in zip(paths, artifacts):
        upload = registry.parent / artifact["asset"]
        shutil.copyfile(path, upload)
        run("gh", "release", "upload", args.release, "--repo", args.repository,
            str(upload))
    run("gh", "release", "upload", args.release, "--repo", args.repository, str(registry))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("restore", "snapshot", "publish"))
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--release", default=os.environ.get("RBM_RELEASE"))
    parser.add_argument("--registry-dir", default=os.environ.get("RUNNER_TEMP", "/tmp") + "/rbm-registry")
    parser.add_argument("--file")
    parser.add_argument("--before")
    parser.add_argument("--stage")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.command in ("restore", "publish") and (not args.repository or not args.release):
        parser.error("repository and release are required")
    if args.command == "restore": restore(args, root)
    elif args.command == "snapshot":
        if not args.file: parser.error("snapshot requires --file")
        snapshot(args)
    else:
        if not args.before or not args.stage: parser.error("publish requires --before and --stage")
        publish(args, root)


if __name__ == "__main__":
    main()
