#!/usr/bin/env python3
"""Verify PGO training, immutable profile bundles, and strict profile-use inputs.

Only schema-2 bundles are accepted. The registry is the last publication asset;
its identity binds complete provenance, including merged/profile payload hashes.
All external commands use their native exit status. No dependency installs occur
here: the pinned Firefox mach command prepares its own build Python environment.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile

PAYLOAD_NAMES = ("merged.profdata", "jarlog", "provenance.json")
REGISTRY_NAME = "profile-registry.json"
TRAINING_NAME = "training-manifest.json"
KIND = "mullvad-browser-cross-pgo-profile"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
SOURCE_BINDINGS = ("upstream_lock", "firefox", "profileserver", "pgo_overlay_sha256",
                   "pgo_languages", "rust_pgo_identity_sha256", "clang_identity",
                   "rust_identity", "toolchains", "generation_targets", "generation_configure_flags",
                   "browser_executable")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha(data):
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def load_json(path):
    # Do not silently allow duplicate keys in a purported immutable manifest.
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    with Path(path).open(encoding="utf-8-sig") as stream:
        return json.load(stream, object_pairs_hook=pairs,
                         parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def write_json(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n",
                         encoding="utf-8")
    temporary.replace(path)


def describe(path):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size > 0,
            f"missing/empty/non-regular profile asset: {path}")
    return {"sha256": sha(path), "size": path.stat().st_size}


def valid_descriptor(data, name):
    require(isinstance(data, dict) and set(data) == {"sha256", "size"},
            f"invalid asset descriptor: {name}")
    require(isinstance(data["sha256"], str) and HEX64.fullmatch(data["sha256"]),
            f"invalid asset SHA-256: {name}")
    require(type(data["size"]) is int and data["size"] > 0, f"invalid asset size: {name}")


def check_asset(path, expected):
    valid_descriptor(expected, str(path))
    require(describe(path) == expected, f"asset hash/size mismatch: {path}")


def nonempty(data, key):
    require(isinstance(data.get(key), str) and bool(data[key].strip()), f"missing {key}")


def validate_build_support(data):
    # Support compilers are optional for older bundles, but a declared archive
    # must carry the exact immutable Node identity and restored payload bytes.
    require(isinstance(data, dict) and set(data) == {"node"},
            "build_support must bind exactly the node project")
    node = data["node"]
    require(isinstance(node, dict)
            and set(node) == {"identity_sha256", "archive_filename", "sha256", "size"},
            "invalid node build support descriptor")
    require(isinstance(node["identity_sha256"], str)
            and HEX64.fullmatch(node["identity_sha256"]), "invalid node build support identity SHA-256")
    require(isinstance(node["archive_filename"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", node["archive_filename"]),
            "unsafe node build support archive filename")
    valid_descriptor({key: node[key] for key in ("sha256", "size")}, "node build support archive")


def match_build_support(actual, expected, context):
    # An absent legacy field is valid only when it is absent on BOTH sides.
    # Otherwise a consumer could silently drop a compiler support identity.
    if "build_support" in actual or "build_support" in expected:
        require("build_support" in actual and "build_support" in expected
                and actual["build_support"] == expected["build_support"],
                f"{context}: build_support missing or mismatched")


def validate_build(data, require_package=True):
    require(isinstance(data, dict) and type(data.get("schema")) is int
            and data["schema"] in (1, 2), "unsupported build provenance schema")
    for key in SOURCE_BINDINGS:
        require(key in data, f"missing build provenance field: {key}")
    if "build_support" in data:
        validate_build_support(data["build_support"])
    lock = data["upstream_lock"]
    firefox = data["firefox"]
    server = data["profileserver"]
    require(isinstance(lock, dict) and isinstance(firefox, dict) and isinstance(server, dict),
            "missing source identity")
    for key in ("repository", "tag"):
        nonempty(lock, key)
    for key in ("commit", "tag_object"):
        require(isinstance(lock.get(key), str) and HEX40.fullmatch(lock[key]),
                f"invalid upstream {key}")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", lock["tag"]),
            "unsafe upstream tag for immutable release")
    for key in ("repository", "ref"):
        nonempty(firefox, key)
    require(isinstance(firefox.get("revision"), str) and HEX40.fullmatch(firefox["revision"]),
            "invalid Firefox revision")
    require(server.get("path") == "build/pgo/profileserver.py"
            and server.get("revision") == firefox["revision"], "profileserver source mismatch")
    for key, value in (("profileserver SHA-256", server.get("sha256")),
                       ("overlay SHA-256", data["pgo_overlay_sha256"]),
                       ("Rust PGO identity SHA-256", data["rust_pgo_identity_sha256"])):
        require(isinstance(value, str) and HEX64.fullmatch(value), f"invalid {key}")
    require(isinstance(data["pgo_languages"], list)
            and sorted(data["pgo_languages"]) == ["c++", "rust"],
            "C++ AND Rust PGO are required")
    require(data["generation_targets"] == ["alpha", "mullvadbrowser-windows-x86_64", "pgo-generate"],
            "profile scope must be Alpha Windows x86_64 generation")
    require(data["generation_configure_flags"] == ["--enable-profile-generate=cross"],
            "profile generation flags must not disable Rust or enable profile use")
    require(data["browser_executable"] == "mullvadbrowser.exe",
            "browser executable must match locked Mullvad Windows scope")
    nonempty(data, "clang_identity")
    nonempty(data, "rust_identity")
    require(isinstance(data["toolchains"], dict), "missing exact toolchain archives")
    for language in ("clang", "rust"):
        toolchain = data["toolchains"].get(language)
        require(isinstance(toolchain, dict), f"missing {language} archive identity")
        valid_descriptor({k: toolchain.get(k) for k in ("sha256", "size")}, language)
        nonempty(toolchain, "archive_filename")
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]*", toolchain["archive_filename"]),
                f"unsafe {language} archive filename")
        nonempty(toolchain, "version")
    if require_package:
        require(isinstance(data.get("instrumented_package_sha256"), str)
                and HEX64.fullmatch(data["instrumented_package_sha256"]),
                "missing instrumented package SHA-256")


def release_tag(provenance):
    return "pgo-profile-" + provenance["upstream_lock"]["tag"] + "-" + canonical_sha(provenance)


def registry_for(directory, provenance):
    return {"schema": 2, "kind": KIND, "committed": True,
            "identity_sha256": canonical_sha(provenance), "release_tag": release_tag(provenance),
            "provenance": provenance,
            "assets": {name: describe(Path(directory) / name) for name in PAYLOAD_NAMES}}


def validate_registry(data, expected_identity=None):
    require(isinstance(data, dict) and type(data.get("schema")) is int and data["schema"] == 2
            and data.get("kind") == KIND and data.get("committed") is True,
            "unsupported/uncommitted profile registry")
    provenance = data.get("provenance")
    validate_build(provenance)
    require(isinstance(data.get("identity_sha256"), str)
            and data["identity_sha256"] == canonical_sha(provenance), "profile identity mismatch")
    require(data.get("release_tag") == release_tag(provenance), "immutable release identity mismatch")
    if expected_identity is not None:
        require(HEX64.fullmatch(expected_identity) is not None, "invalid expected profile identity")
        require(data["identity_sha256"] == expected_identity, "unexpected profile identity")
    assets = data.get("assets")
    require(isinstance(assets, dict) and set(assets) == set(PAYLOAD_NAMES),
            "registry must bind exactly the three named payload assets")
    for name, asset in assets.items():
        valid_descriptor(asset, name)
    require(provenance.get("merged_profdata_sha256") == assets["merged.profdata"]["sha256"],
            "merged profile hash is not bound to provenance")
    require(provenance.get("jarlog_sha256") == assets["jarlog"]["sha256"],
            "jarlog hash is not bound to provenance")
    evidence = provenance.get("counter_evidence")
    require(isinstance(evidence, dict) and evidence.get("positive_cpp_functions", 0) > 0
            and evidence.get("positive_rust_functions", 0) > 0,
            "missing positive C++ AND Rust counter evidence")
    for key in ("total_functions", "total_blocks", "total_count"):
        require(type(evidence.get(key)) is int and evidence[key] > 0,
                f"missing positive counter summary: {key}")
    require(type(evidence.get("maximum_function_count")) is int
            and type(evidence.get("maximum_internal_block_count")) is int
            and max(evidence["maximum_function_count"], evidence["maximum_internal_block_count"]) > 0,
            "profile has no useful function/block counts")
    training = provenance.get("training")
    require(isinstance(training, dict) and type(training.get("schema")) is int and training["schema"] == 1
            and training.get("kind") == "exact-firefox-profileserver-training"
            and type(training.get("profileserver_exit_code")) is int
            and training["profileserver_exit_code"] == 0, "missing successful training provenance")
    require(training.get("instrumented_package_sha256") == provenance["instrumented_package_sha256"]
            and training.get("browser_executable") == provenance["browser_executable"]
            and training.get("profileserver_sha256") == provenance["profileserver"]["sha256"],
            "training source/package is not bound to profile provenance")
    match_build_support(training, provenance, "training/profile provenance")
    require(training.get("jarlog") == assets["jarlog"], "training jarlog is not bound to published payload")
    raw = training.get("raw_profiles")
    require(isinstance(raw, list) and raw, "missing raw profile provenance")
    seen = set()
    for record in raw:
        require(isinstance(record, dict) and set(record) == {"name", "sha256", "size"},
                "invalid published raw profile provenance")
        name = record["name"]
        require(isinstance(name, str) and name.endswith(".profraw") and "\\" not in name
                and all(part not in ("", ".", "..") for part in name.split("/")) and name not in seen,
                "unsafe/duplicate published raw profile name")
        seen.add(name)
        valid_descriptor({key: record[key] for key in ("sha256", "size")}, name)
    for field in ("llvm_profdata_binary_sha256", "training_manifest_sha256", "llvm_summary_sha256", "llvm_functions_sha256"):
        require(isinstance(provenance.get(field), str) and HEX64.fullmatch(provenance[field]),
                f"missing profile evidence digest: {field}")
    return data


def validate_bundle(directory, expected=None, expected_identity=None):
    directory = Path(directory)
    require(directory.is_dir() and not directory.is_symlink(), "invalid profile bundle directory")
    registry_path = directory / REGISTRY_NAME
    describe(registry_path)
    registry = validate_registry(load_json(registry_path), expected_identity)
    for name in PAYLOAD_NAMES:
        check_asset(directory / name, registry["assets"][name])
    provenance = load_json(directory / "provenance.json")
    require(provenance == registry["provenance"], "payload and registry provenance differ")
    if expected is not None:
        validate_build(expected, require_package=False)
        match_build_support(provenance, expected, "unexpected profile build provenance")
        for key, value in expected.items():
            require(key in provenance and provenance[key] == value,
                    f"unexpected profile build provenance: {key}")
    return registry


def training_files(directory):
    paths = sorted(Path(directory).rglob("*.profraw"))
    require(paths, "no raw LLVM profiles")
    for path in paths:
        describe(path)
    return paths


def check_training_logs(directory):
    directory = Path(directory)
    for name in ("profileserver.log", "profile-run-1.log", "profile-run-2.log"):
        path = directory / name
        # Successful native Firefox launches can be silent. The log must exist
        # (proof both launches ran), but zero bytes is not a training failure.
        require(path.is_file() and not path.is_symlink(), f"missing native training log: {name}")
        with path.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                require("LLVM Profile Error" not in line and "PROCESS-CRASH" not in line,
                        f"profile error or crash reported in {name}")
    require(not list(directory.rglob("*.dmp")), "training left crash minidumps")


def record_training(directory, build_path, source_directory, package):
    directory = Path(directory)
    build = load_json(build_path)
    validate_build(build)
    require(describe(package)["sha256"] == build["instrumented_package_sha256"],
            "instrumented package SHA-256 mismatch")
    server = Path(source_directory) / build["profileserver"]["path"]
    require(describe(server)["sha256"] == build["profileserver"]["sha256"],
            "profileserver.py SHA-256 does not match generation provenance")
    status = load_json(directory / "native-status.json")
    require(status.get("bootstrap_exit_code") == 0 and status.get("profileserver_exit_code") == 0
            and status.get("timed_out") is False, "training did not exit successfully")
    check_training_logs(directory)
    raw = training_files(directory)
    manifest = {"schema": 1, "kind": "exact-firefox-profileserver-training",
                "build_provenance_sha256": sha(build_path),
                "instrumented_package_sha256": build["instrumented_package_sha256"],
                "browser_executable": build["browser_executable"],
                "profileserver_sha256": build["profileserver"]["sha256"],
                "profileserver_exit_code": 0,
                "raw_profiles": [{"name": path.relative_to(directory).as_posix(), **describe(path)}
                                 for path in raw],
                "jarlog": describe(directory / "jarlog")}
    if "build_support" in build:
        manifest["build_support"] = build["build_support"]
    write_json(directory / TRAINING_NAME, manifest)
    return manifest


def validate_training(directory, build_path):
    directory = Path(directory)
    build = load_json(build_path)
    validate_build(build)
    manifest = load_json(directory / TRAINING_NAME)
    require(type(manifest.get("schema")) is int and manifest["schema"] == 1
            and manifest.get("kind") == "exact-firefox-profileserver-training"
            and manifest.get("profileserver_exit_code") == 0,
            "unsupported/unsuccessful training manifest")
    require(manifest.get("build_provenance_sha256") == sha(build_path),
            "raw profiles were generated from different build provenance")
    require(manifest.get("instrumented_package_sha256") == build["instrumented_package_sha256"]
            and manifest.get("browser_executable") == build["browser_executable"]
            and manifest.get("profileserver_sha256") == build["profileserver"]["sha256"],
            "training source/package provenance mismatch")
    match_build_support(manifest, build, "training/build provenance")
    records = manifest.get("raw_profiles")
    require(isinstance(records, list) and records, "no raw profile records")
    actual = {path.relative_to(directory).as_posix(): path for path in training_files(directory)}
    require(len(records) == len(actual), "unrecorded/missing raw profiles")
    seen = set()
    for record in records:
        require(isinstance(record, dict) and set(record) == {"name", "sha256", "size"},
                "invalid raw profile record")
        name = record["name"]
        require(isinstance(name, str) and name in actual and name not in seen,
                "unsafe/duplicate/unrecorded raw profile name")
        seen.add(name)
        check_asset(actual[name], {key: record[key] for key in ("sha256", "size")})
    check_asset(directory / "jarlog", manifest.get("jarlog"))
    check_training_logs(directory)
    return build, manifest, list(actual.values())


class NativeFailure(Exception):
    def __init__(self, command, exit_code):
        super().__init__(f"native command exited {exit_code}: {command}")
        self.exit_code = exit_code


def exit_code(code):
    return 128 - code if code < 0 and os.name != "nt" else code


def stop_process_tree(process, stream):
    if os.name == "nt":
        # Killing only mach leaves its Python/Firefox children alive. Windows
        # taskkill /T applies the timeout to the complete native process tree.
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=stream, stderr=subprocess.STDOUT, check=False, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as error:
            stream.write((f"Failed to terminate full Windows process tree: {error}\n").encode())
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)


def run_logged(command, log, cwd=None, env=None, timeout=None):
    print("Running: " + " ".join(map(str, command)), flush=True)
    with Path(log).open("wb") as stream:
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, **options)
        try:
            status = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stream.write(b"\nPGO native process tree exceeded its timeout.\n")
            stream.flush()
            stop_process_tree(process, stream)
            raise NativeFailure(command, 124)
        except KeyboardInterrupt:
            stop_process_tree(process, stream)
            raise
    if status:
        print(Path(log).read_text(encoding="utf-8", errors="replace")[-12000:], file=sys.stderr)
        raise NativeFailure(command, status)


def run_profileserver(source, binary, output, build_path, timeout=3600, bootstrap_timeout=600):
    source, binary, output = (Path(path).resolve() for path in (source, binary, output))
    build = load_json(build_path)
    validate_build(build)
    require(describe(source / "build/pgo/profileserver.py")["sha256"]
            == build["profileserver"]["sha256"], "pinned profileserver SHA-256 mismatch")
    describe(source / "mach")
    describe(binary)
    require(binary.name.casefold() == build["browser_executable"].casefold(),
            "training binary does not match the provenance browser executable")
    output.mkdir(parents=True, exist_ok=True)
    require(not list(output.rglob("*.profraw")) and not (output / "jarlog").exists()
            and not (output / TRAINING_NAME).exists(), "refusing stale training outputs")
    for path in source.glob("*.profraw"):
        path.unlink()
    env = os.environ.copy()
    for key in ("LLVM_PROFDATA", "LLVM_PROFILE_FILE", "MACH_USE_SYSTEM_PYTHON", "UPLOAD_DIR"):
        env.pop(key, None)
    # MOZ_AUTOMATION otherwise selects native-package source 'none'. Exact mach
    # ensure() builds/populates the virtualenv from pinned python/sites manifests.
    env["MACH_BUILD_PYTHON_NATIVE_PACKAGE_SOURCE"] = "pip"
    env["PYTHONUNBUFFERED"] = "1"
    env["JARLOG_FILE"] = str(output / "jarlog")
    env["UPLOAD_PATH"] = str(output)
    crash_tools = output / "crash-tools"
    crash_tools.mkdir(exist_ok=True)
    env["MOZ_FETCHES_DIR"] = str(crash_tools)
    if sys.platform == "win32":
        mb_dir = Path(env.get("MOZILLABUILD", output / "mozilla-build"))
        for sub in ("msys2/usr/bin", "msys/bin", "bin"):
            (mb_dir / sub).mkdir(parents=True, exist_ok=True)
        version_file = mb_dir / "VERSION"
        if not version_file.is_file():
            version_file.write_text("4.1.0\n", encoding="utf-8")
        env["MOZILLABUILD"] = str(mb_dir)
    # Exact mozcrash saves dumps and counts crashes without a stackwalker. This
    # directory prevents profileserver's missing MOZ_FETCHES_DIR exception. A
    # missing binary produces a diagnostic on crash, never a false success.
    probe = ("import sys,mozcrash,mozhttpd,mozprofile,mozrunner; "
             "from mozbuild.base import MozbuildObject; "
             "from pathlib import Path; "
             f"assert Path(MozbuildObject.from_environment().topsrcdir).resolve()==Path({str(source)!r}); "
             "print('Pinned build Python:',sys.executable,sys.version)")
    status = {"schema": 1, "bootstrap_exit_code": None,
              "profileserver_exit_code": None, "timed_out": False}
    command = [sys.executable, "mach", "python", "--virtualenv", "build"]
    try:
        try:
            run_logged(command + ["-c", probe], output / "bootstrap.log", source, env, bootstrap_timeout)
            status["bootstrap_exit_code"] = 0
        except NativeFailure as failure:
            status["bootstrap_exit_code"] = failure.exit_code
            status["timed_out"] = failure.exit_code == 124
            raise
        try:
            run_logged(command + ["build/pgo/profileserver.py", "--binary", str(binary)],
                       output / "profileserver.log", source, env, timeout)
            status["profileserver_exit_code"] = 0
        except NativeFailure as failure:
            status["profileserver_exit_code"] = failure.exit_code
            status["timed_out"] = failure.exit_code == 124
            raise
    finally:
        write_json(output / "native-status.json", status)
        # Keep newly produced raw diagnostics on native failure as well. A
        # manifest is written separately, only after all validation succeeds.
        for path in sorted(source.glob("*.profraw")):
            shutil.move(str(path), output / path.name)
    check_training_logs(output)


def gh(*args, capture=False):
    result = subprocess.run(["gh", *map(str, args)], check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout


def release_assets(repository, tag):
    data = json.loads(gh("release", "view", tag, "--repo", repository,
                         "--json", "assets,isPrerelease", capture=True))
    require(data.get("isPrerelease") is True, "profile destination must be a technical prerelease")
    result = {}
    for asset in data["assets"]:
        name = asset["name"]
        require(name not in result, f"duplicate release asset: {name}")
        result[name] = asset
    return result


def download(repository, tag, name, path):
    gh("release", "download", tag, "--repo", repository, "--pattern", name, "--output", path)


def download_bundle(repository, tag, directory):
    current = release_assets(repository, tag)
    for name in (*PAYLOAD_NAMES, REGISTRY_NAME):
        require(name in current, f"uncommitted/incomplete profile: missing {name}")
        download(repository, tag, name, Path(directory) / name)
        require(current[name].get("size") == (Path(directory) / name).stat().st_size,
                f"release asset size changed while downloading: {name}")
    registry = validate_bundle(directory)
    require(registry["release_tag"] == tag, "release tag does not match verified profile identity")
    return registry


def publish(repository, tag, directory):
    directory = Path(directory)
    local = validate_bundle(directory)
    require(local["release_tag"] == tag, "use the immutable release tag from the profile registry")
    current = release_assets(repository, tag)
    with tempfile.TemporaryDirectory(prefix="pgo-publication-") as temporary:
        remote = Path(temporary)
        if REGISTRY_NAME in current:
            # A matching registry alone is not enough: verify every committed
            # payload. Missing/tampered assets are fatal and never overwritten.
            download_bundle(repository, tag, remote)
            require(sha(remote / REGISTRY_NAME) == sha(directory / REGISTRY_NAME),
                    "conflicting verified profile already committed")
            print("Identical registry AND payloads already committed; nothing to overwrite.")
            return
        for name in PAYLOAD_NAMES:
            if name in current:
                download(repository, tag, name, remote / name)
                check_asset(remote / name, local["assets"][name])
        # Validate every existing interrupted-publication asset before uploading
        # any new asset. Never use --clobber, including on the commit marker.
        for name in PAYLOAD_NAMES:
            if name not in current:
                gh("release", "upload", tag, directory / name, "--repo", repository)
        # Download back before committing, not merely trust successful uploads.
        for name in PAYLOAD_NAMES:
            check = remote / ("verified-" + name)
            download(repository, tag, name, check)
            check_asset(check, local["assets"][name])
        gh("release", "upload", tag, directory / REGISTRY_NAME, "--repo", repository)
    print(f"Committed immutable profile {local['identity_sha256']} to {tag}")


def restore(directory, expected_path, expected_identity, source=None, repository=None, tag=None):
    destination = Path(directory).absolute()
    expected = load_json(expected_path)
    validate_build(expected, require_package=False)
    require(isinstance(expected_identity, str) and HEX64.fullmatch(expected_identity),
            "strict restore requires an expected identity SHA-256")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pgo-restore-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "verified"
        staged.mkdir()
        if source is not None:
            source = Path(source)
            validate_bundle(source, expected, expected_identity)
            for name in (*PAYLOAD_NAMES, REGISTRY_NAME):
                shutil.copyfile(source / name, staged / name)
        else:
            download_bundle(repository, tag, staged)
        verified = validate_bundle(staged, expected, expected_identity)
        if destination.exists():
            require(destination.is_dir() and not destination.is_symlink(), "unsafe restore destination")
            if list(destination.iterdir()):
                present = validate_bundle(destination, expected, expected_identity)
                require(present == verified, "conflicting profile-use destination")
                print("Identical verified profile-use inputs already restored.")
                return verified
            destination.rmdir()
        staged.replace(destination)
    print(f"Restored verified C++ AND Rust profile-use inputs: {destination}")
    return verified


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "identity", "release-tag"):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)
    record = commands.add_parser("record-training")
    record.add_argument("--training-directory", type=Path, required=True)
    record.add_argument("--build-provenance", type=Path, required=True)
    record.add_argument("--source-directory", type=Path, required=True)
    record.add_argument("--instrumented-package", type=Path, required=True)
    train = commands.add_parser("run-profileserver")
    train.add_argument("--source-directory", type=Path, required=True)
    train.add_argument("--binary", type=Path, required=True)
    train.add_argument("--output-directory", type=Path, required=True)
    train.add_argument("--build-provenance", type=Path, required=True)
    train.add_argument("--timeout-seconds", type=int, default=3600)
    train.add_argument("--bootstrap-timeout-seconds", type=int, default=600)
    consume = commands.add_parser("restore")
    consume.add_argument("--directory", type=Path, required=True)
    consume.add_argument("--expected-provenance", type=Path, required=True)
    consume.add_argument("--expected-identity", required=True)
    origin = consume.add_mutually_exclusive_group(required=True)
    origin.add_argument("--source-directory", type=Path)
    origin.add_argument("--repository")
    consume.add_argument("--release")
    args = parser.parse_args()
    if args.command in ("validate", "identity", "release-tag"):
        registry = validate_bundle(args.directory)
        print(registry["identity_sha256"] if args.command == "identity" else
              registry["release_tag"] if args.command == "release-tag" else "Verified C++ AND Rust profile bundle.")
    elif args.command == "record-training":
        record_training(args.training_directory, args.build_provenance,
                        args.source_directory, args.instrumented_package)
        print("Recorded verified exact Firefox training payloads.")
    elif args.command == "run-profileserver":
        require(args.timeout_seconds > 0 and args.bootstrap_timeout_seconds > 0, "timeouts must be positive")
        run_profileserver(args.source_directory, args.binary, args.output_directory, args.build_provenance,
                          args.timeout_seconds, args.bootstrap_timeout_seconds)
    elif args.command == "restore":
        require(bool(args.source_directory) or bool(args.release), "release is required with repository")
        require(not args.source_directory or not args.release, "release cannot be combined with source-directory")
        restore(args.directory, args.expected_provenance, args.expected_identity,
                args.source_directory, args.repository, args.release)


def cli(entrypoint):
    try:
        entrypoint()
    except (NativeFailure, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        status = exit_code(error.exit_code if isinstance(error, NativeFailure) else error.returncode)
        if os.name == "nt":
            # sys.exit's signed C int conversion may replace high-bit Windows
            # exception DWORDs with -1. ExitProcess preserves all 32 bits.
            import ctypes
            sys.stdout.flush()
            sys.stderr.flush()
            ctypes.WinDLL("kernel32").ExitProcess(ctypes.c_uint32(status & 0xffffffff))
        sys.exit(status)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"PGO verification failed: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    cli(main)
