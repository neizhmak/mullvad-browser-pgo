#!/usr/bin/env python3
"""Restore and publish immutable RBM outputs using a GitHub Release.

stage-complete exit codes: 0 = schema, provenance, metadata and bytes verified;
1 = Release, registry, or payload is absent/incomplete; 2 = invalid registry,
provenance/byte conflict, unsafe records, or an inspection/transport failure.
Callers must not rebuild on exit 2. Other commands fail closed with nonzero.
"""

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

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


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"invalid JSON in {path.name}: {error}")


def expected_identity(args, root):
    identity = read_json(Path(args.identity_file)) if args.identity_file else {"upstream": lock(root)}
    if not isinstance(identity, dict) or not identity:
        raise SystemExit("registry identity must be a nonempty JSON object")
    return identity


def registry_identity(data):
    # Schema 1 official registries predate the explicit identity object.
    return data.get("identity", {"upstream": data.get("upstream")})


def safe_name(name):
    # Names are passed as exact gh download patterns, not globs or paths.
    if (not isinstance(name, str) or name in ("", ".", "..")
            or name.startswith("-") or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(char in name for char in "/\\*?[]#")):
        raise SystemExit(f"unsafe Release asset or RBM name: {name!r}")
    return name


def safe_output(root, relative):
    if not isinstance(relative, str):
        raise SystemExit(f"unsafe RBM output path in registry: {relative!r}")
    parts = relative.split("/")
    if len(parts) < 3 or parts[0] != "out":
        raise SystemExit(f"unsafe RBM output path in registry: {relative}")
    output_path = Path(root).resolve()
    for part in parts:
        safe_name(part)
        output_path = output_path / part
        if output_path.is_symlink():
            raise SystemExit(f"unsafe symlink in RBM output path: {relative}")
    return output_path


def validate_registry(data, args, root, stage, name, required=False):
    if (not isinstance(data, dict) or type(data.get("schema")) is not int
            or data["schema"] != 1 or data.get("stage") != stage):
        raise SystemExit(f"invalid {'required ' if required else ''}stage registry: {name}")
    if data.get("upstream") != lock(root) or registry_identity(data) != expected_identity(args, root):
        raise SystemExit(f"provenance mismatch in {name}")
    artifacts = data.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise SystemExit(f"{'required ' if required else ''}stage has no artifacts: {name}")
    paths, assets = set(), set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise SystemExit(f"invalid artifact record in {name}")
        try:
            output_path = safe_output(args.upstream, artifact["path"])
            filename = safe_name(artifact["filename"])
            asset = safe_name(artifact["asset"])
            size, sha256 = artifact["size"], artifact["sha256"]
        except KeyError as error:
            raise SystemExit(f"invalid artifact record in {name}: missing {error}")
        project = Path(artifact["path"]).parts[1]
        if output_path.name != filename or artifact.get("project", project) != project:
            raise SystemExit(f"filename or project mismatch in {name}")
        if asset.startswith("registry-") and asset.endswith(".json"):
            raise SystemExit(f"reserved registry asset name in {name}: {asset}")
        if type(size) is not int or not 0 <= size < MAX_RELEASE_ASSET_SIZE:
            raise SystemExit(f"invalid artifact size in {name}: {size!r}")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise SystemExit(f"invalid artifact SHA-256 in {name}")
        if output_path in paths or asset in assets:
            raise SystemExit(f"duplicate artifact path or asset in {name}")
        paths.add(output_path)
        assets.add(asset)
    return artifacts


def verify_file(path, size, sha256, label):
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != size
            or digest(path) != sha256):
        raise SystemExit(f"{label}: {path.name}")


def require_asset(assets, name, size=None, sha256=None):
    asset = assets.get(name)
    if not asset or asset.get("state") != "uploaded":
        raise SystemExit(f"required artifact is missing or incomplete: {name}")
    actual_size = asset.get("size")
    if type(actual_size) is not int or actual_size < 0 or (size is not None and actual_size != size):
        raise SystemExit(f"published artifact identity mismatch (metadata): {name}")
    github_digest = asset.get("digest")
    if github_digest not in (None, ""):
        if (not isinstance(github_digest, str)
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", github_digest)
                or (sha256 is not None and github_digest != f"sha256:{sha256}")):
            raise SystemExit(f"published artifact digest mismatch: {name}")
    return asset


def download_registry(args, assets, name, directory):
    asset = require_asset(assets, name)
    downloaded = download_asset(args, name, directory)
    if downloaded.stat().st_size != asset["size"]:
        raise SystemExit(f"published registry metadata mismatch: {name}")
    if asset.get("digest") and f"sha256:{digest(downloaded)}" != asset["digest"]:
        raise SystemExit(f"published registry digest mismatch: {name}")
    return downloaded, read_json(downloaded)


def download_verified(args, assets, artifact, directory):
    require_asset(assets, artifact["asset"], artifact["size"], artifact["sha256"])
    downloaded = download_asset(args, artifact["asset"], directory)
    verify_file(downloaded, artifact["size"], artifact["sha256"],
                "published artifact identity mismatch")
    return downloaded


def release_exists(repository, release):
    result = subprocess.run(
        ["gh", "release", "view", release, "--repo", repository],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
    )
    if result.returncode == 0:
        return True
    # gh distinguishes its known missing Release message from auth/network errors.
    if result.returncode == 1 and result.stderr.strip().lower() == "release not found":
        return False
    detail = result.stderr.strip() or f"gh exited {result.returncode}"
    raise SystemExit(f"cannot inspect dependency Release {release}: {detail}")


def release_assets(repository, release):
    data = json.loads(output("gh", "release", "view", release, "--repo", repository,
                             "--json", "assets"))
    assets = {}
    for asset in data["assets"]:
        name = safe_name(asset.get("name"))
        if name in assets:
            raise SystemExit(f"duplicate Release asset name: {name}")
        assets[name] = {key: asset.get(key) for key in ("name", "id", "state", "size", "digest")}
    return assets


def delete_incomplete_asset(args, asset):
    if asset["state"] == "uploaded":
        raise SystemExit(f"refusing to delete uploaded Release asset: {asset['name']}")
    print(f"Removing interrupted Release asset {asset['name']} "
          f"(id={asset['id']}, state={asset['state']}, size={asset['size']})")
    run("gh", "api", "--method", "DELETE",
        f"repos/{args.repository}/releases/assets/{asset['id']}")


def verify_uploaded_asset(args, path, asset, expected=None):
    size = expected["size"] if expected is not None else path.stat().st_size
    sha256 = expected["sha256"] if expected is not None else digest(path)
    verify_file(path, size, sha256, "conflicting existing RBM output")
    require_asset({asset["name"]: asset}, asset["name"], size, sha256)
    published = download_asset(args, asset["name"], Path(args.registry_dir) / "published")
    try:
        verify_file(published, size, sha256, "published artifact identity mismatch")
    finally:
        published.unlink(missing_ok=True)


def upload_asset(args, path, expected=None):
    name = safe_name(path.name)
    for attempt in range(1, UPLOAD_ATTEMPTS + 1):
        assets = release_assets(args.repository, args.release)
        existing = assets.get(name)
        if existing:
            if existing["state"] == "uploaded":
                verify_uploaded_asset(args, path, existing, expected)
                print(f"Reusing identical published asset: {name}")
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
                verify_uploaded_asset(args, path, uploaded, expected)
                print(f"Verified published asset: {name}")
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
    safe_name(name)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    if path.is_symlink():
        raise SystemExit(f"unsafe symlink at Release download path: {path}")
    if path.exists():
        if not path.is_file():
            raise SystemExit(f"unsafe Release download destination: {path}")
        path.unlink()
    run("gh", "release", "download", args.release, "--repo", args.repository,
        "--dir", str(directory), "--pattern", name)
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"Release download did not produce a regular file: {name}")
    return path


def stage_complete(args, root):
    if not release_exists(args.repository, args.release):
        print(f"Stage {args.stage} is not complete: dependency Release does not exist.")
        return False
    assets = release_assets(args.repository, args.release)
    registry_name = f"registry-{safe_name(args.stage)}.json"
    registry_asset = assets.get(registry_name)
    if not registry_asset or registry_asset["state"] != "uploaded":
        print(f"Stage {args.stage} is not complete: {registry_name} is missing or incomplete.")
        return False
    directory = Path(args.registry_dir)
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".completion-", dir=directory) as temporary:
        verification_dir = Path(temporary)
        _, data = download_registry(args, assets, registry_name, verification_dir)
        artifacts = validate_registry(data, args, root, args.stage, registry_name)
        for artifact in artifacts:
            asset = assets.get(artifact["asset"])
            if not asset or asset["state"] != "uploaded":
                print(f"Stage {args.stage} is not complete: "
                      f"{artifact['asset']} is missing or incomplete.")
                return False
            # Download even when GitHub supplies a digest: verify committed bytes.
            downloaded = download_verified(args, assets, artifact, verification_dir)
            downloaded.unlink()
    print(f"Stage {args.stage} is already complete; skipping RBM build.")
    return True


def restore_registries(args, root, stages=None):
    destination = Path(args.upstream)
    registries = Path(args.registry_dir)
    registries.mkdir(parents=True, exist_ok=True)
    if not release_exists(args.repository, args.release):
        if stages is not None:
            raise SystemExit(f"required dependency Release does not exist: {args.release}")
        return
    assets = release_assets(args.repository, args.release)
    if stages is None:
        registry_names = sorted(name for name, asset in assets.items()
                                if name.startswith("registry-") and name.endswith(".json")
                                and asset["state"] == "uploaded")
    else:
        registry_names = [f"registry-{safe_name(stage)}.json" for stage in stages]
    records, output_paths, asset_names = [], set(), set()
    with tempfile.TemporaryDirectory(prefix=".restore-", dir=registries) as temporary:
        download_dir = Path(temporary)
        # Validate all records before downloading payloads or changing any out/ path.
        for registry_name in registry_names:
            stage = registry_name[len("registry-"):-len(".json")]
            asset = assets.get(registry_name)
            if not asset or asset["state"] != "uploaded":
                raise SystemExit(f"required stage is incomplete: {registry_name}")
            registry_path = registries / registry_name
            if registry_path.is_symlink() or (registry_path.exists() and not registry_path.is_file()):
                raise SystemExit(f"unsafe stage registry destination: {registry_path}")
            downloaded, data = download_registry(args, assets, registry_name, download_dir)
            artifacts = validate_registry(data, args, root, stage, registry_name,
                                          required=stages is not None)
            records.append((downloaded, artifacts))
            for artifact in artifacts:
                output_path = safe_output(destination, artifact["path"])
                if output_path in output_paths or artifact["asset"] in asset_names:
                    raise SystemExit(f"conflicting required output path or asset: {artifact['path']}")
                output_paths.add(output_path)
                asset_names.add(artifact["asset"])
                if output_path.exists():
                    verify_file(output_path, artifact["size"], artifact["sha256"],
                                "conflicting existing RBM output")
        planned = []
        for _, artifacts in records:
            for artifact in artifacts:
                downloaded = download_verified(args, assets, artifact, download_dir)
                output_path = safe_output(destination, artifact["path"])
                if output_path.exists():
                    downloaded.unlink()
                else:
                    planned.append((downloaded, output_path, artifact))
        # Do not alter out/ until every registry and payload has passed.
        for downloaded, output_path, artifact in planned:
            safe_output(destination, artifact["path"])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            if output_path.exists():
                verify_file(output_path, artifact["size"], artifact["sha256"],
                            "conflicting existing RBM output")
                downloaded.unlink()
                continue
            shutil.move(downloaded, output_path)
            print(f"Restored verified RBM output: {output_path}")
        # Keep commit records for publish's no-op/conflict checks, not payload copies.
        for downloaded, _ in records:
            registry = registries / downloaded.name
            if registry.is_symlink():
                raise SystemExit(f"unsafe symlink at registry path: {registry}")
            shutil.move(downloaded, registry)
    if stages is not None:
        print("All required RBM stages restored: " + ", ".join(stages))
    print(f"Removed verified temporary downloads: {download_dir}")


def restore(args, root):
    restore_registries(args, root)


def restore_required(args, root):
    """Validate all required records and bytes before restoring outputs."""
    restore_registries(args, root, args.stage)


def snapshot(args):
    upstream = Path(args.upstream)
    paths = sorted(str(path.relative_to(upstream)) for path in (upstream / "out").glob("**/*")
                   if path.is_file())
    for relative in paths:
        safe_output(upstream, relative)
    Path(args.file).write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")


def temporary_upload(source, destination):
    """Use a temporary hardlink, copying only when the filesystem cannot link."""
    try:
        os.link(source, destination)
    except OSError as error:
        if error.errno not in (errno.EXDEV, errno.EPERM, errno.EACCES, errno.ENOTSUP):
            raise
        shutil.copyfile(source, destination)


def verify_committed_stage(args, root, assets, registry_name, registry, paths):
    with tempfile.TemporaryDirectory(prefix=".committed-", dir=registry.parent) as temporary:
        directory = Path(temporary)
        downloaded_registry, data = download_registry(args, assets, registry_name, directory)
        artifacts = validate_registry(data, args, root, args.stage, registry_name)
        registered_paths = {safe_output(args.upstream, artifact["path"]) for artifact in artifacts}
        if any(path.resolve() not in registered_paths for path in paths):
            raise SystemExit(f"registered stage unexpectedly produced new outputs: {args.stage}")
        for artifact in artifacts:
            if args.project and artifact.get("project", Path(artifact["path"]).parts[1]) != args.project:
                raise SystemExit(f"registered stage has unexpected RBM project: {args.stage}")
            output_path = safe_output(args.upstream, artifact["path"])
            verify_file(output_path, artifact["size"], artifact["sha256"],
                        "conflicting existing RBM output")
            downloaded = download_verified(args, assets, artifact, directory)
            downloaded.unlink()
        shutil.copyfile(downloaded_registry, registry)
    print(f"Stage already published and fully restored: {args.stage}")


def publish(args, root):
    upstream = Path(args.upstream)
    before = set(Path(args.before).read_text(encoding="utf-8").splitlines())
    paths = sorted(path for path in (upstream / "out").glob("**/*")
                   if path.is_file() and str(path.relative_to(upstream)) not in before)
    if args.project:
        safe_name(args.project)
        paths = [path for path in paths
                 if path.relative_to(upstream).parts[1] == args.project]
    provenance = lock(root)
    identity = expected_identity(args, root)
    artifacts = []
    for path in paths:
        relative = str(path.relative_to(upstream))
        safe_output(upstream, relative)
        size = path.stat().st_size
        if size >= MAX_RELEASE_ASSET_SIZE:
            raise SystemExit(
                f"RBM artifact is too large for a GitHub Release asset "
                f"({size} bytes; must be below 2 GiB): {path}"
            )
        project = Path(relative).parts[1]
        asset = f"rbm-{provenance['commit'][:12]}--{project}--{path.name}"
        artifacts.append({"project": project, "filename": path.name, "path": relative,
                          "asset": asset, "sha256": digest(path), "size": size})
    registry_name = f"registry-{safe_name(args.stage)}.json"
    registry = Path(args.registry_dir) / registry_name
    registry.parent.mkdir(parents=True, exist_ok=True)
    if registry.is_symlink() or (registry.exists() and not registry.is_file()):
        raise SystemExit(f"unsafe stage registry destination: {registry}")
    exists = release_exists(args.repository, args.release)
    assets = release_assets(args.repository, args.release) if exists else {}
    committed = assets.get(registry_name)
    if committed and committed["state"] == "uploaded":
        verify_committed_stage(args, root, assets, registry_name, registry, paths)
        return
    # A local registry is not a commit marker. Resume an interrupted upload only
    # after validating its records and all currently present payloads.
    if registry.exists():
        data = read_json(registry)
        recorded = validate_registry(data, args, root, args.stage, registry_name)
        if artifacts and artifacts != recorded:
            raise SystemExit(f"existing stage registry identity mismatch: {registry_name}")
        artifacts = recorded
        paths = [safe_output(upstream, artifact["path"]) for artifact in artifacts]
        for path, artifact in zip(paths, artifacts):
            verify_file(path, artifact["size"], artifact["sha256"],
                        "conflicting existing RBM output")
    data = {"schema": 1, "stage": args.stage, "upstream": provenance,
            "identity": identity, "artifacts": artifacts}
    validate_registry(data, args, root, args.stage, registry_name)
    if args.project and any(artifact.get("project", Path(artifact["path"]).parts[1]) != args.project
                            for artifact in artifacts):
        raise SystemExit(f"unexpected RBM project in stage registry: {args.stage}")
    registry.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if not exists:
        run("gh", "release", "create", args.release, "--repo", args.repository,
            "--title", f"RBM dependencies for {provenance['tag']}",
            "--notes", "Outputs produced by the pinned RBM recipes; see registry provenance.",
            "--prerelease", "--latest=false", "--target", os.environ["GITHUB_SHA"])
    # Upload and verify each payload without retaining a second local output tree.
    with tempfile.TemporaryDirectory(prefix=".uploads-", dir=registry.parent) as temporary:
        for path, artifact in zip(paths, artifacts):
            verify_file(path, artifact["size"], artifact["sha256"],
                        "conflicting existing RBM output")
            upload = Path(temporary) / artifact["asset"]
            try:
                temporary_upload(path, upload)
                upload_asset(args, upload, artifact)
            finally:
                upload.unlink(missing_ok=True)
    # The stage registry remains the commit record and must be uploaded last.
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
    parser.add_argument("--identity-file", help="exact registry identity/provenance JSON")
    parser.add_argument("--project", help="publish only new outputs from this RBM project")
    parser.add_argument("--stage", action="append")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if args.command in ("stage-complete", "restore", "restore-required", "publish") and (not args.repository or not args.release):
        parser.error("repository and release are required")
    if args.command == "stage-complete":
        if not args.stage or len(args.stage) != 1:
            parser.error("stage-complete requires exactly one --stage")
        args.stage = args.stage[0]
        try:
            complete = stage_complete(args, root)
        except (SystemExit, OSError, ValueError, KeyError, TypeError,
                subprocess.SubprocessError) as error:
            print(str(error), file=sys.stderr)
            raise SystemExit(2)
        raise SystemExit(0 if complete else 1)
    if args.command == "restore": restore(args, root)
    elif args.command == "restore-required":
        if not args.stage: parser.error("restore-required requires --stage")
        if len(set(args.stage)) != len(args.stage): parser.error("required stages must be unique")
        restore_required(args, root)
    elif args.command == "snapshot":
        if not args.file: parser.error("snapshot requires --file")
        snapshot(args)
    else:
        if not args.before or not args.stage or len(args.stage) != 1:
            parser.error("publish requires --before and exactly one --stage")
        args.stage = args.stage[0]
        publish(args, root)


if __name__ == "__main__":
    main()
