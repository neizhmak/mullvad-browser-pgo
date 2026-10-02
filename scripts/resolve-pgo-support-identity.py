#!/usr/bin/env python3
"""Resolve a Node-only official RBM support identity before its archive exists.

The compact, sorted JSON identity (not pretty-printed file bytes) determines the
full identity SHA-256 and technical Release name. Archive bytes are bound later
by the existing verified RBM registry. No Firefox/Rust overlay bytes enter this
identity: the unchanged Node recipe is shared by generation and profile use.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

from rbm_network import showconf

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git"
TARGETS = ["alpha", "mullvadbrowser-windows-x86_64"]
PROJECT = "node"
SOURCE_FILES = ["projects/node/config", "projects/node/build", "rbm.conf",
                "projects/container-image/config", "projects/container-image/build"]


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def canonical_sha(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True).encode("utf-8")).hexdigest()


def release_name(identity):
    return f"pgo-support-{identity['upstream']['tag']}-{canonical_sha(identity)}"


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SystemExit(f"cannot read valid JSON: {Path(path).name}: {error}")


def load_lock():
    data = load_json(ROOT / "upstream.lock.json")
    require(isinstance(data, dict) and set(data) == {"repository", "tag", "tag_object", "commit"},
            "invalid upstream lock schema")
    require(data["repository"] == REPOSITORY, "upstream lock is not the official repository")
    require(isinstance(data["tag"], str) and re.fullmatch(r"mb-\d+\.\d+a\d+-build\d+", data["tag"]),
            "invalid upstream Alpha tag")
    for field in ("tag_object", "commit"):
        require(isinstance(data[field], str) and re.fullmatch(r"[0-9a-f]{40}", data[field]),
                f"invalid upstream {field}")
    return data


def regular_file(path, base):
    path, base = Path(path), Path(base)
    try:
        relative = path.relative_to(base)
        path.resolve(strict=True).relative_to(base.resolve(strict=True))
    except (ValueError, OSError):
        raise SystemExit(f"support file escapes or is missing: {path.name}")
    current = base
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), f"support file has a symlink component: {path.name}")
    require(path.is_file() and path.stat().st_size > 0,
            f"support file must be a nonempty regular file: {path.name}")
    return path


def git(upstream, *arguments, binary=False):
    value = subprocess.check_output(["git", "-C", str(upstream), *arguments], text=not binary)
    return value if binary else value.strip()


def boolean(upstream, key, undefined=False):
    try:
        value = showconf(upstream, PROJECT, key, TARGETS)
    except subprocess.CalledProcessError as error:
        # The pinned RBM emits exactly this when a nonselected platform flag
        # is undefined. A transport/ref/other failure is never treated as false.
        if (undefined and error.returncode == 1 and not (error.stdout or "").strip()
                and (error.stderr or "").strip() == "Error: Undefined"):
            return False
        raise
    require(value in ("", "0", "1", "false", "true"), f"ambiguous Node flag: {key}")
    return value in ("1", "true")


def resolve_identity(upstream, project=PROJECT):
    require(project == PROJECT, "only the official Node support project is supported")
    upstream = Path(upstream).resolve(strict=True)
    require(upstream.is_dir(), "upstream must be a directory")
    locked = load_lock()
    require(git(upstream, "rev-parse", "HEAD") == locked["commit"],
            "Node support requires the exact locked upstream commit")
    require(git(upstream, "remote", "get-url", "origin") == locked["repository"],
            "Node support source repository is not official")
    require(git(upstream, "rev-parse", "refs/tags/" + locked["tag"]) == locked["tag_object"],
            "Node support upstream tag object differs from lock")
    require(git(upstream, "rev-parse", "refs/tags/" + locked["tag"] + "^{}") == locked["commit"],
            "Node support upstream peeled tag differs from lock")
    require(git(upstream, "cat-file", "-t", locked["tag_object"]) == "tag",
            "Node support upstream tag must be annotated")
    hashes = {}
    for relative in SOURCE_FILES:
        path = regular_file(upstream / relative, upstream)
        official = git(upstream, "show", locked["commit"] + ":" + relative, binary=True)
        require(path.read_bytes() == official, f"modified official Node support source: {relative}")
        hashes[relative] = sha(path)
    link = git(upstream, "ls-tree", locked["commit"], "rbm")
    match = re.fullmatch(r"160000 commit ([0-9a-f]{40})\trbm", link)
    require(match is not None, "upstream does not pin an unambiguous RBM gitlink")
    require(not (upstream / "rbm").is_symlink(), "RBM directory must not be a symlink")
    require(git(upstream / "rbm", "rev-parse", "HEAD") == match[1],
            "RBM submodule differs from pinned gitlink")
    require(not boolean(upstream, "var/linux", undefined=True),
            "Node support unexpectedly selected the Linux compiler branch")
    require(boolean(upstream, "var/windows-x86_64") and boolean(upstream, "var/windows"),
            "Node support must select Windows x86_64")
    require(boolean(upstream, "var/no_crosscompile"), "Node support must remain native no_crosscompile")
    version = showconf(upstream, PROJECT, "version", TARGETS)
    require(re.fullmatch(r"[1-9]\d*\.\d+\.\d+", version) is not None, "invalid Node version")
    recipe = (upstream / "projects/node/config").read_text(encoding="utf-8")
    pinned_versions = re.findall(r"(?m)^  node_version:\s*([1-9]\d*\.\d+\.\d+)\s*$", recipe)
    require(pinned_versions == [version], "evaluated Node version differs from the pinned recipe")
    filename = showconf(upstream, PROJECT, "filename", TARGETS)
    require(re.fullmatch(r"node-" + re.escape(version) + r"-[A-Za-z0-9._-]+\.tar\.(?:zst|xz|gz)", filename)
            is not None, "invalid exact Node output filename")
    suite = showconf(upstream, PROJECT, "var/container/suite", TARGETS)
    arch = showconf(upstream, PROJECT, "var/container/arch", TARGETS)
    require((suite, arch) == ("trixie", "amd64"), "unexpected pinned Node container suite or arch")
    source_sha = showconf(upstream, PROJECT, "var/node_sha256", TARGETS)
    require(re.fullmatch(r"[0-9a-f]{64}", source_sha) is not None, "invalid pinned Node source SHA-256")
    pinned_sums = re.findall(r"(?m)^  node_sha256:\s*([0-9a-f]{64})\s*$", recipe)
    require(pinned_sums == [source_sha], "evaluated Node source SHA-256 differs from the pinned recipe")
    raw_inputs = showconf(upstream, PROJECT, "input_files", TARGETS)
    require(bool(raw_inputs), "empty Node input_files identity")
    return {"schema": 1, "kind": "official-rbm-support-node", "upstream": locked,
            "project": PROJECT, "targets": TARGETS, "version": version,
            "output_filename": filename, "config_sha256": hashes["projects/node/config"],
            "build_sha256": hashes["projects/node/build"], "source_inputs": raw_inputs,
            "source": {"url": f"https://nodejs.org/dist/v{version}/node-v{version}.tar.xz",
                       "sha256": source_sha},
            "container": {"suite": suite, "arch": arch,
                          "config_sha256": hashes["projects/container-image/config"],
                          "build_sha256": hashes["projects/container-image/build"]},
            "rbm_gitlink": match[1], "rbm_conf_sha256": hashes["rbm.conf"],
            "compiler_inputs": []}


def archive_record(upstream, identity):
    path = regular_file(Path(upstream) / "out/node" / identity["output_filename"], upstream)
    return {"identity_sha256": canonical_sha(identity), "archive_filename": path.name,
            "sha256": sha(path), "size": path.stat().st_size}


def verify_node_registry(path, identity, record):
    data = load_json(path)
    require(isinstance(data, dict) and data.get("schema") == 1 and data.get("stage") == "node"
            and data.get("identity") == identity and data.get("upstream") == identity["upstream"],
            "restored Node registry does not match its support identity")
    artifacts = data.get("artifacts")
    require(isinstance(artifacts, list) and len(artifacts) == 1 and isinstance(artifacts[0], dict),
            "Node support registry must contain only its exact built archive")
    artifact = artifacts[0]
    require(artifact.get("path") == "out/node/" + record["archive_filename"]
            and artifact.get("project") == "node" and artifact.get("filename") == record["archive_filename"]
            and artifact.get("sha256") == record["sha256"] and artifact.get("size") == record["size"],
            "restored Node archive differs from its committed registry")


def no_symlink_path(path):
    path = Path(path).absolute()
    current = Path(path.anchor)
    for part in path.parts[1:]:
        require(part not in (".", ".."), "unsafe support destination path")
        current = current / part
        require(not current.is_symlink(), f"unsafe support destination symlink: {path.name}")
    return path


def write_json(path, value):
    path = no_symlink_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix="." + path.name + ".", delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=Path, required=True)
    parser.add_argument("--project", default=PROJECT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-output", type=Path)
    parser.add_argument("--verify-output", action="store_true")
    parser.add_argument("--registry", type=Path, help="verify exact single-archive registry after restoration")
    args = parser.parse_args()
    identity = resolve_identity(args.upstream, args.project)
    if args.verify_output or args.registry:
        record = archive_record(args.upstream.resolve(), identity)
        if args.registry:
            verify_node_registry(args.registry, identity, record)
    write_json(args.output, identity)
    metadata = {"release": release_name(identity), "identity_sha256": canonical_sha(identity)}
    if args.metadata_output:
        write_json(args.metadata_output, metadata)
    print(json.dumps(metadata, sort_keys=True))


if __name__ == "__main__":
    main()
