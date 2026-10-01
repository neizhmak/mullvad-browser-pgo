#!/usr/bin/env python3
"""Verify optimized Firefox handoffs and collect both Windows product packages."""
import argparse
import configparser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = "/var/tmp/dist/pgo/merged.profdata"
JARLOG_PATH = "/var/tmp/dist/pgo/jarlog"
OFFICIAL_UPDATE_URL = "https://cdn.mullvad.net/browser/update_responses/update_1"
OFFICIAL_MAR_CHANNEL = "mullvadbrowser-mullvad-alpha"
UPDATE_OPTIONS = {
    "MOZ_UPDATER": "1", "BASE_BROWSER_UPDATE": "1", "MOZ_VERIFY_MAR_SIGNATURE": "1",
    "MOZ_USE_NSS_FOR_MAR": "1", "MOZ_UPDATE_CHANNEL": "alpha",
    "BB_UPDATER_URL": OFFICIAL_UPDATE_URL, "MAR_CHANNEL_ID": OFFICIAL_MAR_CHANNEL,
    "ACCEPTED_MAR_CHANNEL_IDS": OFFICIAL_MAR_CHANNEL,
}
DISABLED_UPDATE_OPTIONS = ("MOZ_MAINTENANCE_SERVICE", "MOZ_UPDATE_AGENT", "DISABLE_UPDATER_AUTHENTICODE_CHECK")


def locked_alpha_version():
    tag = read_json(ROOT / "upstream.lock.json")["tag"]
    match = re.fullmatch(r"mb-([0-9]+\.[0-9]+a[0-9]+)-build[0-9]+", tag)
    if not match:
        raise SystemExit("secure updater proof requires an explicit locked Alpha tag")
    return match.group(1)


def verify_update_configuration(proof):
    substs, defines = proof.get("substs", {}), proof.get("defines", {})
    version = locked_alpha_version()
    expected_defines = {"MOZ_VERIFY_MAR_SIGNATURE": "1", "BASE_BROWSER_VERSION": version,
                        "BASE_BROWSER_VERSION_QUOTED": '"' + version + '"'}
    for section, expected in ((substs, UPDATE_OPTIONS), (defines, expected_defines)):
        for key, value in expected.items():
            if section.get(key) != value:
                raise SystemExit("secure official Alpha updater configuration mismatch: " + key)
    for key in DISABLED_UPDATE_OPTIONS:
        if substs.get(key) or defines.get(key):
            raise SystemExit("unexpected updater security/background option: " + key)


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def safe_name(name):
    path = PurePosixPath(name)
    if (path.is_absolute() or ".." in path.parts or not path.parts
            or "\\" in name or str(path) != name or ":" in name):
        raise SystemExit("unsafe artifact path: " + name)
    return path


def profile_hashes(directory):
    directory = Path(directory)
    return {"pgo_profile_sha256": sha(directory / "merged.profdata"),
            "pgo_jarlog_sha256": sha(directory / "jarlog")}


def verify_proof(proof, profile_directory):
    if proof.get("schema") != 1:
        raise SystemExit("invalid Firefox profile-use proof schema")
    for key, value in profile_hashes(profile_directory).items():
        if proof.get(key) != value:
            raise SystemExit("Firefox proof profile identity mismatch: " + key)
    provenance = read_json(Path(profile_directory) / "provenance.json")
    if proof.get("firefox_revision") != provenance["firefox"]["revision"]:
        raise SystemExit("Firefox proof source revision mismatch")
    substs = proof.get("substs", {})
    if any(not substs.get(key) for key in ("MOZ_PROFILE_USE", "MOZ_PGO_RUST")):
        raise SystemExit("Firefox proof does not enable both C++ and Rust PGO")
    if substs.get("MOZ_PROFILE_GENERATE"):
        raise SystemExit("Firefox proof still enables generation")
    if substs.get("PGO_PROFILE_PATH") != PROFILE_PATH:
        raise SystemExit("Firefox proof uses the wrong profile path")
    if "-fprofile-use=" + PROFILE_PATH not in substs.get("PROFILE_USE_CFLAGS", []):
        raise SystemExit("Firefox proof lacks C++ profile-use flags")
    if substs.get("PGO_JARLOG_PATH") not in (JARLOG_PATH, [JARLOG_PATH]):
        raise SystemExit("Firefox proof lacks the training jarlog")
    verify_update_configuration(proof)


def snapshot_firefox(args):
    directory = args.directory.resolve()
    if not directory.is_dir() or not re.fullmatch(r"firefox-[A-Za-z0-9._-]+", args.rbm_filename):
        raise SystemExit("invalid selected Firefox output directory")
    for pattern in ("browser.tar.*", "nsis-plugins.tar.*", "mar-tools-*.zip"):
        matches = list(directory.glob(pattern))
        if len(matches) != 1 or not matches[0].is_file() or matches[0].stat().st_size == 0:
            raise SystemExit("selected Firefox output is incomplete: " + pattern)
    proof = read_json(directory / "pgo-use-proof.json")
    verify_proof(proof, args.profile_directory)
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or (not path.is_file() and not path.is_dir()):
            raise SystemExit("Firefox output contains a non-regular entry")
        if path.is_file():
            name = path.relative_to(directory).as_posix()
            safe_name(name)
            files.append({"path": name, "sha256": sha(path), "size": path.stat().st_size})
    args.output_directory.mkdir(parents=True, exist_ok=True)
    archive_path = args.output_directory / "firefox-output.tar"
    with tarfile.open(archive_path, "w", format=tarfile.GNU_FORMAT) as archive:
        for item in files:
            info = tarfile.TarInfo(item["path"])
            info.size = item["size"]
            info.mode = 0o644
            info.uid = info.gid = info.mtime = 0
            with (directory / item["path"]).open("rb") as stream:
                archive.addfile(info, stream)
    manifest = {"schema": 1, "kind": "windows-cross-pgo-firefox-output",
                "rbm_filename": args.rbm_filename, "profile_identity": args.profile_identity,
                "upstream_lock": read_json(ROOT / "upstream.lock.json"),
                "pgo_use_overlay_sha256": sha(ROOT / "patches/firefox-pgo-use.patch"),
                "proof": proof, "files": files,
                "archive": {"filename": archive_path.name, "sha256": sha(archive_path),
                            "size": archive_path.stat().st_size}}
    write_json(args.output_directory / "firefox-output.json", manifest)
    print("Persisted the exact optimized Firefox output: " + args.rbm_filename)


def verify_firefox(args):
    manifest = read_json(args.artifact_directory / "firefox-output.json")
    if (manifest.get("schema") != 1 or manifest.get("kind") != "windows-cross-pgo-firefox-output"
            or manifest.get("profile_identity") != args.profile_identity
            or manifest.get("upstream_lock") != read_json(ROOT / "upstream.lock.json")
            or manifest.get("pgo_use_overlay_sha256") != sha(ROOT / "patches/firefox-pgo-use.patch")):
        raise SystemExit("optimized Firefox handoff identity mismatch")
    verify_proof(manifest["proof"], args.profile_directory)
    recorded = manifest["archive"]
    if recorded.get("filename") != "firefox-output.tar":
        raise SystemExit("unexpected Firefox archive filename")
    archive_path = args.artifact_directory / "firefox-output.tar"
    if (archive_path.is_symlink() or not archive_path.is_file()
            or archive_path.stat().st_size != recorded["size"] or sha(archive_path) != recorded["sha256"]):
        raise SystemExit("optimized Firefox archive checksum mismatch")
    expected = {}
    for item in manifest["files"]:
        safe_name(item["path"])
        if item["path"] in expected:
            raise SystemExit("duplicate Firefox manifest path")
        expected[item["path"]] = item
    if not expected or "pgo-use-proof.json" not in expected:
        raise SystemExit("empty optimized Firefox inventory")
    with tarfile.open(archive_path, "r:") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or set(names) != set(expected):
            raise SystemExit("Firefox archive inventory mismatch")
        for member in members:
            safe_name(member.name)
            item = expected[member.name]
            if not member.isfile() or member.size != item["size"]:
                raise SystemExit("invalid Firefox archive member")
            value = hashlib.sha256()
            stream = archive.extractfile(member)
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                value.update(block)
            if value.hexdigest() != item["sha256"]:
                raise SystemExit("Firefox member checksum mismatch: " + member.name)
        proof_file = archive.extractfile("pgo-use-proof.json")
        if json.load(proof_file) != manifest["proof"]:
            raise SystemExit("Firefox archive proof differs from its handoff manifest")
    print(recorded["sha256"])
    return manifest


def verify_package_updates(archive, prefix):
    app = configparser.ConfigParser(interpolation=None)
    settings = configparser.ConfigParser(interpolation=None)
    try:
        app.read_string(archive.read(prefix + "Browser/application.ini").decode("utf-8-sig"))
        settings.read_string(archive.read(prefix + "Browser/update-settings.ini").decode("utf-8-sig"))
        url = app.get("AppUpdate", "URL")
        channel = settings.get("Settings", "ACCEPTED_MAR_CHANNEL_IDS")
    except (UnicodeError, KeyError, configparser.Error) as error:
        raise SystemExit("invalid packaged updater configuration: " + str(error))
    expected_url = OFFICIAL_UPDATE_URL + "/%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL"
    if url != expected_url:
        raise SystemExit("portable package changed the official Alpha update URL")
    if channel != OFFICIAL_MAR_CHANNEL:
        raise SystemExit("portable package changed accepted signed MAR channels")
    return {"url": url, "accepted_mar_channel_ids": channel,
            "route": "unchanged official signed Mullvad Alpha",
            "mar_update_integration_tested": False}


def portable_layout(path, application_directory):
    prefix = application_directory + "/"
    required = ["Browser/firefox.exe", "Browser/xul.dll", "Browser/omni.ja",
                "Browser/browser/omni.ja", "Browser/application.ini", "Browser/updater.exe",
                "Browser/postupdate.exe", "Browser/update-settings.ini", "Start Mullvad Browser.cmd",
                "Browser/distribution/extensions/uBlock0@raymondhill.net.xpi",
                "Browser/distribution/extensions/{73a6fe31-595d-460b-a920-fcc0f8843232}.xpi",
                "Browser/distribution/extensions/{d19a89b9-76c1-4a61-bcd4-49e8de916403}.xpi"]
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise SystemExit("portable ZIP contains duplicate paths")
        for info in infos:
            name = info.filename.rstrip("/")
            safe_name(name)
            if not info.filename.startswith(prefix) or stat.S_ISLNK(info.external_attr >> 16):
                raise SystemExit("portable ZIP has an unexpected root or symlink")
        if prefix + "Browser/system-install" in names:
            raise SystemExit("portable ZIP contains the system-install marker")
        for relative in required:
            name = prefix + relative
            if name not in names or archive.getinfo(name).file_size == 0:
                raise SystemExit("portable ZIP is incomplete: " + relative)
        updates = verify_package_updates(archive, prefix)
        launcher = archive.read(prefix + "Start Mullvad Browser.cmd")
        if b'"%~dp0Browser\\firefox.exe" %*' not in launcher:
            raise SystemExit("portable launcher does not start its own Browser/firefox.exe")
        for relative in ("Browser/firefox.exe", "Browser/xul.dll", "Browser/updater.exe"):
            with archive.open(prefix + relative) as binary:
                if binary.read(2) != b"MZ":
                    raise SystemExit("portable ZIP contains a non-PE executable: " + relative)
    return {"root": application_directory, "launcher": "Start Mullvad Browser.cmd",
            "portable_detection": "absence of Browser/system-install", "complete_browser_tree": True,
            "updates": updates}


def collect_packages(args):
    if not re.fullmatch(r"[0-9]+\.[0-9]+a[0-9]+", args.version):
        raise SystemExit("only an explicit Mullvad Alpha version is supported")
    if args.version != locked_alpha_version():
        raise SystemExit("final package version differs from the locked Alpha")
    filenames = {"installer": f"mullvad-browser-windows-x86_64-{args.version}.exe",
                 "portable": f"mullvad-browser-windows-x86_64-portable-{args.version}.zip"}
    files = {}
    for kind, filename in filenames.items():
        path = args.directory / filename
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise SystemExit("missing required " + kind + " package: " + filename)
        files[kind] = path
    with files["installer"].open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise SystemExit("installer is not a Windows PE executable")
    layout = portable_layout(files["portable"], args.application_directory)
    firefox = read_json(args.firefox_manifest)
    if firefox.get("profile_identity") != args.profile_identity:
        raise SystemExit("final package profile identity mismatch")
    verify_update_configuration(firefox.get("proof", {}))
    if args.destination.exists() and any(args.destination.iterdir()):
        raise SystemExit("refusing to collect into a nonempty final package directory")
    args.destination.mkdir(parents=True, exist_ok=True)
    assets = []
    for kind, path in files.items():
        destination = args.destination / path.name
        shutil.copyfile(path, destination)
        assets.append({"kind": kind, "filename": destination.name,
                       "sha256": sha(destination), "size": destination.stat().st_size})
    manifest = {"schema": 1, "kind": "unofficial-mullvad-windows-alpha-pgo",
                "version": args.version, "platform": "windows-x86_64", "channel": "alpha",
                "profile_identity": args.profile_identity,
                "upstream_lock": read_json(ROOT / "upstream.lock.json"),
                "firefox": firefox, "portable_layout": layout, "assets": assets,
                "public_browser_release": False,
                "updates": "unchanged official signed Mullvad Alpha update track"}
    write_json(args.destination / "packages.json", manifest)
    print("Collected verified installer and standalone portable ZIP.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot-firefox")
    snapshot.add_argument("--directory", type=Path, required=True)
    snapshot.add_argument("--rbm-filename", required=True)
    snapshot.add_argument("--profile-directory", type=Path, required=True)
    snapshot.add_argument("--profile-identity", required=True)
    snapshot.add_argument("--output-directory", type=Path, required=True)
    snapshot.set_defaults(function=snapshot_firefox)
    verify = commands.add_parser("verify-firefox")
    verify.add_argument("--artifact-directory", type=Path, required=True)
    verify.add_argument("--profile-directory", type=Path, required=True)
    verify.add_argument("--profile-identity", required=True)
    verify.set_defaults(function=verify_firefox)
    collect = commands.add_parser("collect")
    collect.add_argument("--directory", type=Path, required=True)
    collect.add_argument("--destination", type=Path, required=True)
    collect.add_argument("--version", required=True)
    collect.add_argument("--application-directory", default="Mullvad Browser")
    collect.add_argument("--firefox-manifest", type=Path, required=True)
    collect.add_argument("--profile-identity", required=True)
    collect.set_defaults(function=collect_packages)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
