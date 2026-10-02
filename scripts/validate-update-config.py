#!/usr/bin/env python3
"""Offline lint for updater preparation. This does not configure or deploy updates."""

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_BASE = "https://cdn.mullvad.net/browser/update_responses/update_1/"
OFFICIAL_CHANNEL = "mullvadbrowser-mullvad-alpha"
URL_SUFFIX = "%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL"
FIELDS = {
    "schema_version", "preparation_only", "publication_enabled", "platform",
    "channel", "upstream_tag", "automatic_updates", "update_strategy",
    "update_url_base", "mar_signature_verification", "mar_channel_id",
    "accepted_mar_channel_ids", "mar_certificate", "complete_mar_required",
    "partial_updates", "acknowledge_pgo_replacement", "authenticode_required",
}


class ConfigError(ValueError):
    """An unsafe or unsupported preparation setting."""


def require(condition, message):
    if not condition:
        raise ConfigError(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ConfigError(f"non-standard JSON constant: {value}")


def load_config(path):
    require(path.stat().st_size <= 32768, "configuration exceeds 32768 bytes")
    return json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=unique_object, parse_constant=reject_constant)


def check_url(base):
    require(isinstance(base, str) and len(base) <= 2048, "update_url_base must be a URL string")
    require(base.isascii() and not any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base),
            "update_url_base must use ASCII without spaces or control characters")
    require(not any(c in base for c in "\\%{}<>"),
            "update_url_base must not contain escapes, tokens, backslashes, or placeholders")
    try:
        parsed = urlsplit(base)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("invalid update_url_base") from exc
    require(parsed.scheme == "https" and host, "update_url_base must use HTTPS and a host")
    require(parsed.username is None and parsed.password is None,
            "update_url_base must not contain credentials")
    require(port in (None, 443), "update_url_base must use the standard HTTPS port")
    require(not parsed.query and not parsed.fragment,
            "update_url_base must not contain a query or fragment")
    require(host == host.rstrip("."), "update_url_base must not use a trailing-dot host")
    require("." in host and len(host) <= 253, "update_url_base requires a fully qualified host")
    labels = host.split(".")
    require(re.fullmatch(r"[a-z][a-z0-9-]*", labels[-1]) is not None,
            "update_url_base must not use an alternate numeric IP notation")
    require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels),
            "update_url_base must use an ASCII DNS host")
    reserved = (".localhost", ".local", ".internal", ".invalid", ".test", ".example", ".onion")
    require(not host.endswith(reserved) and host not in {"example.com", "example.net", "example.org"}
            and not any(host.endswith("." + name) for name in ("example.com", "example.net", "example.org")),
            "update_url_base must not use a local, reserved, or example host")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    require(address is None, "update_url_base must use a DNS host, not an IP literal")
    require(parsed.path.startswith("/") and parsed.path.endswith("/"),
            "update_url_base must have a directory path with a trailing slash")
    require(not any(part in (".", "..") for part in parsed.path.split("/")),
            "update_url_base must not contain dot path segments")
    require("//" not in parsed.path, "update_url_base must not contain empty path segments")
    require(re.fullmatch(r"/[A-Za-z0-9/_-]*/", parsed.path) is not None,
            "update_url_base path must use simple directory names")
    return host


def validate_config(config, locked_tag):
    require(type(config) is dict and set(config) == FIELDS,
            "configuration must contain exactly the documented fields")
    require(type(config["schema_version"]) is int and config["schema_version"] == 1,
            "only schema_version 1 is supported")
    fixed = {
        "preparation_only": True,
        "publication_enabled": False,
        "automatic_updates": True,
        "mar_signature_verification": True,
        "complete_mar_required": True,
        "partial_updates": False,
    }
    for key, expected in fixed.items():
        require(config[key] is expected, f"{key} must be {str(expected).lower()} in this preparation")
    require(config["platform"] == "windows-x86_64", "only windows-x86_64 is prepared")
    require(config["channel"] == "alpha", "only the locked alpha channel is prepared")
    require(config["upstream_tag"] == locked_tag, "upstream_tag does not match upstream.lock.json")
    require(re.fullmatch(r"mb-\d+\.\d+a\d+-build\d+", locked_tag) is not None,
            "upstream lock must identify an Alpha build")
    require(type(config["authenticode_required"]) is bool, "authenticode_required must be a boolean")
    host = check_url(config["update_url_base"])
    mar_id = config["mar_channel_id"]
    require(isinstance(mar_id, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,126}", mar_id),
            "mar_channel_id must be one non-empty channel ID without separators or wildcards")
    require(type(config["accepted_mar_channel_ids"]) is list
            and config["accepted_mar_channel_ids"] == [mar_id],
            "accepted_mar_channel_ids must contain exactly mar_channel_id")
    certificate = config["mar_certificate"]
    require(type(certificate) is dict and set(certificate) == {"source", "sha256"},
            "mar_certificate must contain only source and sha256; never put keys in configuration")
    strategy = config["update_strategy"]
    if strategy == "upstream-signed":
        require(config["update_url_base"] == OFFICIAL_BASE and mar_id == OFFICIAL_CHANNEL,
                "upstream-signed must retain the exact official Mullvad URL and Alpha MAR ID")
        require(certificate == {"source": "upstream", "sha256": None},
                "upstream-signed must retain the official embedded certificates")
        require(config["acknowledge_pgo_replacement"] is True,
                "upstream-signed requires acknowledgement that official updates replace PGO binaries")
    elif strategy == "private-signed":
        require(not any(host == h or host.endswith("." + h) for h in (
            "mullvad.net", "mullvad.se", "torproject.org", "mozilla.org", "mozilla.com")),
            "private-signed must not use an upstream-owned update host")
        require(mar_id != OFFICIAL_CHANNEL and re.fullmatch(
            r"mullvadbrowser-[a-z0-9]+(?:-[a-z0-9]+)*-pgo-alpha", mar_id) is not None,
                "private-signed requires a distinct mullvadbrowser-<owner>-pgo-alpha MAR ID")
        require(certificate["source"] == "publisher" and isinstance(certificate["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", certificate["sha256"]) is not None
                and certificate["sha256"] != "0" * 64,
                "private-signed requires the SHA-256 of the publisher public DER certificate")
        require(config["acknowledge_pgo_replacement"] is False,
                "private-signed is not the upstream PGO-replacement strategy")
    else:
        raise ConfigError("update_strategy must be upstream-signed or private-signed")
    return config["update_url_base"] + URL_SUFFIX


def check_public_certificate(path, expected_sha256):
    """Check a public DER certificate, not a signing key or a MAR signature."""
    require(path.stat().st_size <= 65536, "public DER certificate exceeds 65536 bytes")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == expected_sha256,
            "public certificate SHA-256 does not match configuration")
    # A single DER SEQUENCE must fill the file. Reject PEM and trailing data,
    # including accidentally concatenated private-key material.
    require(len(raw) >= 2 and raw[0] == 0x30, "certificate must be one DER X.509 object, not PEM or a key")
    length = raw[1]
    offset = 2
    if length & 0x80:
        count = length & 0x7f
        require(1 <= count <= 3 and len(raw) >= 2 + count and raw[2] != 0,
                "invalid DER certificate length")
        length = int.from_bytes(raw[2:2 + count], "big")
        offset += count
        require(length >= 128, "non-canonical DER certificate length")
    require(offset + length == len(raw), "DER certificate contains truncated or trailing data")
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl is required only for --certificate inspection")
    result = subprocess.run([openssl, "x509", "-inform", "DER", "-pubkey", "-noout"],
                            input=raw, capture_output=True, timeout=10)
    require(result.returncode == 0, "file is not an X.509 DER certificate")
    key = subprocess.run([openssl, "rsa", "-pubin", "-text", "-noout"],
                         input=result.stdout, capture_output=True, timeout=10)
    require(key.returncode == 0, "MAR signing requires an RSA public certificate")
    bits = re.search(rb"Public-Key: \((\d+) bit\)", key.stdout)
    require(bits is not None and int(bits.group(1)) >= 2048,
            "publisher RSA key must be at least 2048 bits (upstream's key script uses 4096)")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path, nargs="?",
                        default=ROOT / "config/update-settings.example.json")
    parser.add_argument("--lock", type=Path, default=ROOT / "upstream.lock.json")
    parser.add_argument("--certificate", type=Path,
                        help="optionally inspect an existing publisher public DER certificate")
    args = parser.parse_args(argv)
    try:
        lock = load_config(args.lock)
        require(type(lock) is dict and isinstance(lock.get("tag"), str), "lock has no tag")
        config = load_config(args.config)
        template = validate_config(config, lock["tag"])
        if args.certificate:
            require(config["update_strategy"] == "private-signed",
                    "--certificate is only for the private-signed publisher certificate")
            check_public_certificate(args.certificate, config["mar_certificate"]["sha256"])
    except (ConfigError, OSError, UnicodeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print("Validated updater PREPARATION only; no build, signing, network, or deployment was performed.")
    print(f"Expected compiled update URL template (not installed): {template}")
    if config["update_strategy"] == "upstream-signed":
        print("Official signed updates can replace the unofficial PGO build with upstream non-PGO binaries.")
    else:
        print("Private track still needs certificate embedding, protected signing, hosting, and update tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
