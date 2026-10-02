#!/usr/bin/env python3
"""Offline security contract tests. No keys are generated and no host is contacted."""

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate-update-config.py"
spec = importlib.util.spec_from_file_location("update_config", SCRIPT)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
EXAMPLE = json.loads((ROOT / "config/update-settings.example.json").read_text())
LOCKED_TAG = json.loads((ROOT / "upstream.lock.json").read_text())["tag"]
# Existing PUBLIC upstream certificate. Parser fixture only, never a custom signing key.
# Source: mullvad/mullvad-browser a8a167fe41226f38158d8e169623e95a1bff846a
# toolkit/mozapps/update/updater/release_secondary.der
PUBLIC_CERT = base64.b64decode(
    "MIIFBTCCAu2gAwIBAgIFAL7vaeowDQYJKoZIhvcNAQEMBQAwRDFCMEAGA1UEAxM5TXVsbHZhZCBCcm93c2VyIE1BUiBzaWduaW5nIGtleSAobXVsbHZhZC1icm93c2VyLW5zc2RiLTIpMB4XDTIzMDMyMjExMTgwNVoXDTIzMDYyMjExMTgwNVowRDFCMEAGA1UEAxM5TXVsbHZhZCBCcm93c2VyIE1BUiBzaWduaW5nIGtleSAobXVsbHZhZC1icm93c2VyLW5zc2RiLTIpMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3udk/4eE7fLehRwipeQs4E0PIqoduEtg6X//+lJRtrukVgFdRc7Cja2+QPpbSMvWnWVUVeW9QmH2BGHHiCsBPUx16nA8QO2EcR4oud2FSZLFOktG6oK2UtbLHB+cJ2VZQcNBbALZQIm7Z4XT6oJ/TMhHCDhhyxpahe85HK774L1a0jHt6egM70VK5FRgnc0fy6IqLl1WHAKU5evqVYJboLH+RDsm65ky8yYX5qv5b8T4KGJnfXOaJ1jl+A2v2+JW5jlVPEX7zhFMR9XQiai8DjbuFJaMl76kv1PqN6kfHs351XBeQ8Rt/i4F50nXVjKUw48cswtxwNXNjSnuJfgL4GEcilMkIRvyfdTpNK+glXBGRqP9MM+tZZIaFr/hEaBwFcS9ihJ6cjn14d727j0qe4iF+/9FxQgZ87Is4WK9ado/dQVCmTd9P+HLxF1Z982RvbHrPuX3kRIqKeTJFH61QCIyS8/cv6Hjfg75UyidvKtd6S37Mu9utQp8Y/DRYbfNTfOlu169UgwvyQ4IzcGGGnxWDMS/J9iTCHHZFR0RTIJO/yqO9t4xAXsI1LhmgAmKa3BGv9hr7ey+PwZjfin06g98VWaH6krl9wpvIytNKV/JXBY+nXz8P9i0eCZuOdMjfupU8Q2dOj0qscUXiZmY6NGXNkvGLFdYcvcU/gIizr8CAwEAATANBgkqhkiG9w0BAQwFAAOCAgEARCJnkHq2IevZHPLDWmnNzi/s5kG5rFzJ0G4lJYoKGgtginMKrlCH4NsaCMx5h3OdhWwKHGzaP0gXA38KlspR4e8KSM+RzBeReGweU6wEel/6wzTOt+t/fHAFyADcLJEiPqDD1OvdPFJKwzlVKg6Ns4L4FiNm1Frrb6Fr2pqDfgpWYrgqVstCF7jHVslcucHSTFPPctBWKFOcbr8miqWb4aEKmO3DXsjkQJJBo94nr7+XGM0nVSMvPlpn7LyZsXe9AMqmEjiFLXWW4M6mmTQgatB1xg5GwDnv3T3QCWH3IZgrEZyRhjK/uQAjBGM7ffuTcMTcEjHABFMxoJP+MM934+KBSp/XvYP9/pjYZ97z7csFe7H30PPHR9F4/1fg87dGkRXRatztZzW15/CUudG9sY7EkCzHAL0OnhkbofqTxIonHOjg0kh5kIjsqCZI2SxZHImt5Npv0pdAnZYKqodazG7sSrDB4xaWGhIP0k/dyQfYcdFA5o5htKhsU0djKDFIez1nUzjjZfOJZL8p0F9nRMf5q0w5NA9MpEfz4vpl/c/FokPj43N/bzMqTzyqfTesEjHSS5zoxUGSALhCTH095CnI6GJV6yaJg/S8fKMzE2lidolcDmeJcUKhyvdtAr9ZHWLfFGVKct32viv6+C/YsJPSul6DLB17jb4XBhiWApQ="
)


class UpdateConfigTests(unittest.TestCase):
    def private_config(self):
        config = copy.deepcopy(EXAMPLE)
        config.update({
            "update_strategy": "private-signed",
            "update_url_base": "https://updates.neizhmak.org/mullvad-pgo/update_1/",
            "mar_channel_id": "mullvadbrowser-neizhmak-pgo-alpha",
            "accepted_mar_channel_ids": ["mullvadbrowser-neizhmak-pgo-alpha"],
            "mar_certificate": {"source": "publisher", "sha256": "1" * 64},
            "acknowledge_pgo_replacement": False,
        })
        return config

    def reject(self, config):
        with self.assertRaises(validator.ConfigError):
            validator.validate_config(config, LOCKED_TAG)

    def test_example_preserves_official_signed_alpha_track(self):
        template = validator.validate_config(EXAMPLE, LOCKED_TAG)
        self.assertEqual(template, validator.OFFICIAL_BASE + validator.URL_SUFFIX)
        self.assertTrue(EXAMPLE["acknowledge_pgo_replacement"])

    def test_private_preparation_uses_distinct_channel_and_public_fingerprint(self):
        config = self.private_config()
        template = validator.validate_config(config, LOCKED_TAG)
        self.assertIn("/%CHANNEL%/%BUILD_TARGET%/%VERSION%/ALL", template)

    def test_verification_and_preparation_guards_cannot_be_disabled(self):
        for key in ("preparation_only", "publication_enabled", "automatic_updates",
                    "mar_signature_verification", "complete_mar_required", "partial_updates"):
            with self.subTest(key=key):
                config = copy.deepcopy(EXAMPLE)
                config[key] = not config[key]
                self.reject(config)

    def test_boolean_integers_are_not_accepted(self):
        for key in ("preparation_only", "publication_enabled", "automatic_updates",
                    "mar_signature_verification", "complete_mar_required", "partial_updates",
                    "acknowledge_pgo_replacement", "authenticode_required"):
            with self.subTest(key=key):
                config = copy.deepcopy(EXAMPLE)
                config[key] = int(config[key])
                self.reject(config)
        config = copy.deepcopy(EXAMPLE)
        config["schema_version"] = True
        self.reject(config)

    def test_official_track_cannot_be_redirected_or_use_custom_cert(self):
        cases = {
            "update_url_base": "https://updates.neizhmak.org/update_1/",
            "mar_channel_id": "mullvadbrowser-neizhmak-pgo-alpha",
            "mar_certificate": {"source": "publisher", "sha256": "1" * 64},
            "acknowledge_pgo_replacement": False,
        }
        for key, value in cases.items():
            with self.subTest(key=key):
                config = copy.deepcopy(EXAMPLE)
                config[key] = value
                self.reject(config)

    def test_private_track_cannot_claim_upstream_endpoint(self):
        for host in ("cdn.mullvad.net", "mullvad.se", "aus1.torproject.org",
                     "mozilla.org", "updates.mozilla.com"):
            config = self.private_config()
            config["update_url_base"] = f"https://{host}/update_1/"
            self.reject(config)

    def test_reject_insecure_or_placeholder_urls(self):
        urls = [
            "http://updates.neizhmak.org/update_1/",
            "https://user:password@updates.neizhmak.org/update_1/",
            "https://updates.neizhmak.org:8443/update_1/",
            "https://updates.neizhmak.org/update_1/?token=secret",
            "https://updates.neizhmak.org/update_1/#fragment",
            "https://updates.neizhmak.org/update_1",
            "https://updates.neizhmak.org/%CHANNEL%/",
            "https://updates.neizhmak.org/../update_1/",
            "https://updates.neizhmak.org//update_1/",
            "https://updates.neizhmak.org/%2e%2e/update_1/",
            "https://updates.neizhmak.org./update_1/",
            "https://localhost/update_1/",
            "https://127.0.0.1/update_1/",
            "https://169.254.169.254/update_1/",
            "https://[::1]/update_1/",
            "https://updates.local/update_1/",
            "https://updates.internal/update_1/",
            "https://updates.example.invalid/update_1/",
            "https://updates.example.com/update_1/",
            "https://updates.test/update_1/",
            "https://updates.neizhmak.org/update_1/\n",
            "https://updates.neizhmak.org/\\update_1/",
        ]
        for url in urls:
            with self.subTest(url=url):
                config = self.private_config()
                config["update_url_base"] = url
                self.reject(config)

    def test_only_current_platform_alpha_and_lock_are_supported(self):
        for key, value in (("platform", "linux-x86_64"), ("channel", "release"),
                           ("upstream_tag", "mb-16.0a8-build1"), ("schema_version", 2)):
            config = copy.deepcopy(EXAMPLE)
            config[key] = value
            self.reject(config)
        with self.assertRaises(validator.ConfigError):
            validator.validate_config(EXAMPLE, "mb-16.0-build1")

    def test_channel_allowlist_must_be_one_explicit_id(self):
        for ids in ([], ["*"], [validator.OFFICIAL_CHANNEL, "extra"],
                    [validator.OFFICIAL_CHANNEL] * 2, validator.OFFICIAL_CHANNEL):
            config = copy.deepcopy(EXAMPLE)
            config["accepted_mar_channel_ids"] = ids
            self.reject(config)
        for mar_id in ("", "*", "alpha,release", "alpha release", "alpha\t", "alpha;true"):
            config = self.private_config()
            config["mar_channel_id"] = mar_id
            config["accepted_mar_channel_ids"] = [mar_id]
            self.reject(config)

    def test_private_track_needs_owner_scoped_id_and_fingerprint(self):
        for mar_id in (validator.OFFICIAL_CHANNEL, "alpha", "mullvadbrowser-pgo-alpha",
                       "mullvadbrowser-neizhmak-pgo-release"):
            config = self.private_config()
            config["mar_channel_id"] = mar_id
            config["accepted_mar_channel_ids"] = [mar_id]
            self.reject(config)
        for value in (None, "", "0" * 64, "A" * 64, "1" * 63, "1" * 65):
            config = self.private_config()
            config["mar_certificate"]["sha256"] = value
            self.reject(config)
        config = self.private_config()
        config["mar_certificate"]["source"] = "upstream"
        self.reject(config)

    def test_unknown_missing_and_secret_fields_are_rejected(self):
        config = copy.deepcopy(EXAMPLE)
        del config["automatic_updates"]
        self.reject(config)
        for key in ("private_key", "password", "disable_signature_verification", "app.update.url"):
            config = copy.deepcopy(EXAMPLE)
            config[key] = "never-store-secrets"
            self.reject(config)
        config = self.private_config()
        config["mar_certificate"]["private_key"] = "never-store-secrets"
        self.reject(config)

    def test_authenticode_is_independent_of_required_mar_verification(self):
        config = copy.deepcopy(EXAMPLE)
        config["authenticode_required"] = True
        validator.validate_config(config, LOCKED_TAG)
        config["mar_signature_verification"] = False
        self.reject(config)

    def test_duplicate_keys_and_nonstandard_json_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            for content in ('{"schema_version":1,"schema_version":1}',
                            '{"value":NaN}', '{"value":Infinity}'):
                path.write_text(content)
                with self.assertRaises(validator.ConfigError):
                    validator.load_config(path)
            path.write_text(" " * 32769)
            with self.assertRaises(validator.ConfigError):
                validator.load_config(path)

    def test_existing_public_certificate_is_inspected_without_key_generation(self):
        if not shutil.which("openssl"):
            self.skipTest("openssl is optional for public certificate inspection")
        digest = hashlib.sha256(PUBLIC_CERT).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "marsigner.der"
            path.write_bytes(PUBLIC_CERT)
            validator.check_public_certificate(path, digest)
            with self.assertRaises(validator.ConfigError):
                validator.check_public_certificate(path, "1" * 64)
            path.write_bytes(PUBLIC_CERT + b"trailing")
            with self.assertRaises(validator.ConfigError):
                validator.check_public_certificate(path, hashlib.sha256(path.read_bytes()).hexdigest())
            path.write_bytes(b"-----BEGIN PRIVATE KEY-----")
            with self.assertRaises(validator.ConfigError):
                validator.check_public_certificate(path, hashlib.sha256(path.read_bytes()).hexdigest())
            path.write_bytes(b"\x30\x02\x05\x00")  # DER SEQUENCE, not X.509
            with self.assertRaises(validator.ConfigError):
                validator.check_public_certificate(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_cli_is_explicitly_preparation_only(self):
        result = subprocess.run([sys.executable, str(SCRIPT)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PREPARATION only", result.stdout)
        self.assertIn("no build, signing, network, or deployment", result.stdout)
        self.assertIn("replace", result.stdout)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.json"
            path.write_text('{"mar_signature_verification":false}')
            result = subprocess.run([sys.executable, str(SCRIPT), str(path)], text=True, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
