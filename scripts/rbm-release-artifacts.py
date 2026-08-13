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

MAX_RELEASE_ASSET_SIZE = 2 * 1024 * 1024 * 1024
UPLOAD_TIMEOUT_SECONDS = int(os.environ.get("RBM_UPLOAD_TIMEOUT_SECONDS", 15 * 60))
UPLOAD_ATTEMPTS = int(os.environ.get("RBM_UPLOAD_ATTEMPTS", 3))


def run(*args):
    subprocess.run(args, check=True)


def output(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout


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


def release_assets(repository, release):
    data = json.loads(output("gh", "release", "view", release, "--repo", repository,
                             "--json", "assets"))
    return {asset["name"]: {key: asset.get(key) for key in ("name", "id", "state", "size", "digest")}
            for asset in data["assets"]}


def delete_incomplete_asset(args, asset):
    if asset["state"] == "uploaded":
        raise SystemExit(f"refusing to delete uploaded Release asset: {asset['name']}")
    print(f"Removing interrupted Release asset {asset['name']} "
          f"(id={asset['id']}, state={asset['state']}, size={asset['size']})")
    run("gh", "api", "--method", "DELETE",
        f"repos/{args.repository}/releases/assets/{asset['id']}")


def verify_uploaded_asset(args, path, asset):
    published = download_asset(args, asset["name"], Path(args.registry_dir) / "published")
    if published.stat().st_size != path.stat().st_size or digest(published) != digest(path):
        raise SystemExit(f"published artifact identity mismatch: {asset['name']}")
    print(f"Reusing identical published asset: {asset['name']}")


def upload_asset(args, path):
    name = path.name
    for attempt in range(1, UPLOAD_ATTEMPTS + 1):
        assets = release_assets(args.repository, args.release)
        existing = assets.get(name)
        if existing:
            if existing["state"] == "uploaded":
                verify_uploaded_asset(args, path, existing)
                return existing
            delete_incomplete_asset(args, existing)
        print(f"Uploading {name} (attempt {attempt}/{UPLOAD_ATTEMPTS}, "
              f"timeout {UPLOAD_TIMEOUT_SECONDS}s)")
        try:
            subprocess.run(
                ["gh", "release", "upload", args.release, "--repo", args.repository,
                 str(path)], check=True, timeout=UPLOAD_TIMEOUT_SECONDS,
            )
            uploaded = release_assets(args.repository, args.release).get(name)
            if uploaded and uploaded["state"] == "uploaded":
                return uploaded
            reason = "returned without producing an uploaded asset"
        except subprocess.TimeoutExpired:
            reason = f"timed out after {UPLOAD_TIMEOUT_SECONDS}s"
        except subprocess.CalledProcessError as error:
            reason = f"failed with exit status {error.returncode}"
        print(f"Upload of {name} {reason} (attempt {attempt}/{UPLOAD_ATTEMPTS})",
              file=sys.stderr)
    raise SystemExit(f"upload failed after {UPLOAD_ATTEMPTS} attempts: {name}")


def download_asset(args, name, directory):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    if path.exists():
        path.unlink()
    run("gh", "release", "download", args.release, "--repo", args.repository,
        "--dir", str(directory), "--pattern", name)
    return path



def stage_complete(args, root):
    if not release_exists(args.repository, args.release):
        print(f"Stage {args.stage} is not complete: dependency Release does not exist.")
        return False
    assets = release_assets(args.repository, args.release)
    registry_name = f"registry-{args.stage}.json"
    registry_asset = assets.get(registry_name)
    if not registry_asset or registry_asset["state"] != "uploaded":
        print(f"Stage {args.stage} is not complete: {registry_name} is missing or incomplete.")
        return False
    registry = download_asset(args, registry_name, Path(args.registry_dir) / "completion")
    data = json.loads(registry.read_text(encoding="utf-8"))
    if data.get("upstream") != lock(root) or data.get("stage") != args.stage:
        print(f"Stage {args.stage} is not complete: {registry_name} does not match the locked upstream.")
        return False
    for artifact in data.get("artifacts", []):
        if Path(artifact["path"]).name != artifact["filename"]:
            print(f"Stage {args.stage} is not complete: filename mismatch in {registry_name}.")
            return False
        asset = assets.get(artifact["asset"])
        if not asset or asset["state"] != "uploaded":
            print(f"Stage {args.stage} is not complete: {artifact['asset']} is missing or incomplete.")
            return False
        if asset["name"] != artifact["asset"] or asset["size"] != artifact["size"]:
            print(f"Stage {args.stage} is not complete: metadata mismatch for {artifact['asset']}.")
            return False
        github_digest = asset.get("digest")
        if github_digest and github_digest != f"sha256:{artifact['sha256']}":
            print(f"Stage {args.stage} is not complete: digest mismatch for {artifact['asset']}.")
            return False
    print(f"Stage {args.stage} is already complete; skipping RBM build.")
    return True

def restore(args, root):
    destination = Path(args.upstream)
    registries = Path(args.registry_dir)
    registries.mkdir(parents=True, exist_ok=True)
    if not release_exists(args.repository, args.release):
        return
    for old_registry in registries.glob("registry-*.json"):
        old_registry.unlink()
    registry_names = sorted(name for name, asset in release_assets(args.repository, args.release).items()
                            if name.startswith("registry-") and name.endswith(".json")
                            and asset["state"] == "uploaded")
    for name in registry_names:
        download_asset(args, name, registries)
    expected_lock = lock(root)
    for registry in sorted(registries.glob("registry-*.json")):
        data = json.loads(registry.read_text(encoding="utf-8"))
        if data.get("upstream") != expected_lock:
            raise SystemExit(f"provenance mismatch in {registry.name}")
        for artifact in data.get("artifacts", []):
            output = safe_output(destination, artifact["path"])
            asset = download_asset(args, artifact["asset"], registries)
            if asset.stat().st_size != artifact["size"] or digest(asset) != artifact["sha256"]:
                raise SystemExit(f"published artifact identity mismatch: {artifact['asset']}")
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(asset, output)
            if output.name != artifact["filename"]:
                raise SystemExit(f"filename mismatch in {registry.name}")


def restore_required(args, root):
    """Atomically validate and restore a caller-supplied set of RBM stages."""
    destination = Path(args.upstream)
    registries = Path(args.registry_dir)
    download_dir = registries / "required"
    if not release_exists(args.repository, args.release):
        raise SystemExit(f"required dependency Release does not exist: {args.release}")

    assets = release_assets(args.repository, args.release)
    expected_lock = lock(root)
    planned = []
    output_paths = {}
    for stage in args.stage:
        registry_name = f"registry-{stage}.json"
        registry_asset = assets.get(registry_name)
        if not registry_asset or registry_asset["state"] != "uploaded":
            raise SystemExit(f"required stage is incomplete: {registry_name}")
        registry = download_asset(args, registry_name, download_dir)
        data = json.loads(registry.read_text(encoding="utf-8"))
        if data.get("schema") != 1 or data.get("stage") != stage:
            raise SystemExit(f"invalid required stage registry: {registry_name}")
        if data.get("upstream") != expected_lock:
            raise SystemExit(f"provenance mismatch in {registry_name}")
        artifacts = data.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            raise SystemExit(f"required stage has no artifacts: {registry_name}")
        for artifact in artifacts:
            try:
                output_path = safe_output(destination, artifact["path"])
                filename = artifact["filename"]
                asset_name = artifact["asset"]
                size = artifact["size"]
                sha256 = artifact["sha256"]
            except (KeyError, TypeError) as error:
                raise SystemExit(f"invalid artifact record in {registry_name}: {error}")
            if output_path.name != filename or Path(asset_name).name != asset_name:
                raise SystemExit(f"filename mismatch in {registry_name}")
            identity = (asset_name, size, sha256)
            if output_path in output_paths:
                raise SystemExit(f"conflicting required output path: {artifact['path']}")
            output_paths[output_path] = identity
            release_asset = assets.get(asset_name)
            if (not release_asset or release_asset["state"] != "uploaded"
                    or release_asset["size"] != size):
                raise SystemExit(f"required artifact is missing or incomplete: {asset_name}")
            downloaded = download_asset(args, asset_name, download_dir)
            if downloaded.stat().st_size != size or digest(downloaded) != sha256:
                raise SystemExit(f"published artifact identity mismatch: {asset_name}")
            if (output_path.exists()
                    and (output_path.stat().st_size != size or digest(output_path) != sha256)):
                raise SystemExit(f"conflicting existing RBM output: {output_path}")
            planned.append((downloaded, output_path, sha256))

    # Do not alter out/ until every required registry and artifact has passed.
    for downloaded, output_path, sha256 in planned:
        if output_path.exists():
            print(f"Already restored verified RBM output: {output_path}")
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(downloaded, output_path)
        print(f"Restored verified RBM output: {output_path}")
    print("All required RBM stages restored: " + ", ".join(args.stage))
    shutil.rmtree(download_dir)
    print(f"Removed verified temporary downloads: {download_dir}")


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
        size = path.stat().st_size
        if size >= MAX_RELEASE_ASSET_SIZE:
            raise SystemExit(
                f"RBM artifact is too large for a GitHub Release asset "
                f"({size} bytes; must be below 2 GiB): {path}"
            )
        relative = str(path.relative_to(upstream))
        project = Path(relative).parts[1]
        asset = f"rbm-{provenance['commit'][:12]}--{project}--{path.name}"
        artifacts.append({"project": project, "filename": path.name, "path": relative,
                          "asset": asset, "sha256": digest(path), "size": size})
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
            "--notes", "Unmodified outputs produced by the pinned official RBM recipes.",
            "--prerelease", "--latest=false", "--target", os.environ["GITHUB_SHA"])
    # The registry is uploaded last: it is the commit record for this stage.
    for path, artifact in zip(paths, artifacts):
        upload = registry.parent / artifact["asset"]
        shutil.copyfile(path, upload)
        upload_asset(args, upload)
    # The stage registry remains the commit record and must always be uploaded last.
    upload_asset(args, registry)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("stage-complete", "restore", "restore-required",
                                            "snapshot", "publish"))
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--release", default=os.environ.get("RBM_RELEASE"))
    parser.add_argument("--registry-dir", default=os.environ.get("RUNNER_TEMP", "/tmp") + "/rbm-registry")
    parser.add_argument("--file")
    parser.add_argument("--before")
    parser.add_argument("--stage", action="append")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.command in ("stage-complete", "restore", "restore-required", "publish") and (not args.repository or not args.release):
        parser.error("repository and release are required")
    if args.command == "stage-complete":
        if not args.stage: parser.error("stage-complete requires --stage")
        args.stage = args.stage[0]
        raise SystemExit(0 if stage_complete(args, root) else 1)
    if args.command == "restore": restore(args, root)
    elif args.command == "restore-required":
        if not args.stage: parser.error("restore-required requires --stage")
        if len(set(args.stage)) != len(args.stage): parser.error("required stages must be unique")
        restore_required(args, root)
    elif args.command == "snapshot":
        if not args.file: parser.error("snapshot requires --file")
        snapshot(args)
    else:
        if not args.before or not args.stage: parser.error("publish requires --before and --stage")
        args.stage = args.stage[0]
        publish(args, root)


if __name__ == "__main__":
    main()
