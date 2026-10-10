#!/usr/bin/env python3
"""Run the existing offline Windows harness against only the verified stock baseline.

This checks the native installer and file:// PNG/JavaScript measurement path. It
neither builds nor validates PGO packages. Product privacy and timer preferences
are not changed. Prepare the known baseline with windows-runtime-check.py first.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("baseline_smoke_runtime", ROOT / "scripts/windows-runtime-check.py")
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)
REPORT_NAME = "runtime-baseline-smoke-report.json"


def run_smoke(args):
    output = args.output_directory.resolve()
    if args.output_directory.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        runtime.fail("refusing a stale or linked baseline smoke output directory")
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema": 1, "kind": "baseline-offline-harness-smoke", "status": "failed",
              "baseline_only": True, "validated_pipeline": False, "public_browser_release": False,
              "offline": True, "suite": runtime.SUITE, "default_preferences_modified": False,
              "timer_preferences_modified": False,
              "browser_diagnostics": getattr(args, "browser_diagnostics", False),
              "network_scope": "Firefox --offline and file-only CSP-denied workload; not an OS-wide egress sandbox",
              "evidence_scope": "stock baseline installer and offline harness only; no PGO build or comparison",
              "samples": [], "cleanup": [], "errors": []}
    work, destination, error = None, None, None
    installed, measured = False, False

    def record_error(phase, exception):
        nonlocal error
        report["errors"].append({"phase": phase, "error": str(exception)})
        if error is None:
            error = exception
            report["error"] = str(exception)

    try:
        runtime.require_windows()
        lock = runtime.read_json(args.upstream_lock)
        # Recheck the known successful run, committed current lock, ZIP digest,
        # and extracted installer binding before executing any native bytes.
        baseline, installer = runtime.verify_baseline(args.baseline_directory, lock)
        version = runtime.locked_version(lock)
        report.update(upstream_lock=lock, baseline=baseline,
                      baseline_installer_sha256=baseline["installer"]["sha256"],
                      benchmark_template_sha256=runtime.sha256(ROOT / "scripts/benchmark-page.html"),
                      target_milliseconds=args.target_milliseconds, requested_samples=args.samples,
                      runner={"system": platform.system(), "release": platform.release(),
                              "machine": platform.machine(), "python": platform.python_version(),
                              "github_run_id": os.environ.get("GITHUB_RUN_ID"),
                              "github_sha": os.environ.get("GITHUB_SHA")})
        runtime.reject_existing_install()
        work = Path(tempfile.mkdtemp(prefix="mb-baseline-smoke-"))
        staged = work / "assets"
        staged.mkdir()
        shutil.copyfile(installer, staged / "baseline.exe")
        installer = runtime.checked_file(staged, dict(baseline["installer"], filename="baseline.exe"))
        destination = work / "baseline-install"
        destination.mkdir()
        installed = True  # A partially completed installer must also be cleaned.
        runtime.run_native(runtime.installer_command(installer, destination), output / "baseline-install.log",
                           args.installer_timeout_seconds)
        # The shared helper writes exact installed layout before validation.
        report["installed_tree"] = runtime.verify_browser_tree(
            destination, version, portable=False, inventory_path=output / "baseline-installed-files.json")
        binary = destination / "mullvadbrowser.exe"
        binary_record = {"filename": "mullvadbrowser.exe", "size": binary.stat().st_size,
                         "sha256": runtime.sha256(binary)}
        report["browser_executable"] = binary_record
        runtime.write_json(output / REPORT_NAME, report)

        def launch(label, *, iterations=None):
            # Verify the installed executable and secure Alpha configuration
            # before each launch. run_browser owns isolated profiles, native
            # process deadlines/jobs, PNG decoding, nonce and JS checksums.
            runtime.verify_browser_tree(destination, version, portable=False)
            checked_binary = runtime.checked_file(destination, binary_record)
            options = {"iterations": iterations, "target_ms": args.target_milliseconds}
            if report["browser_diagnostics"]:
                options["diagnostics"] = True
            return runtime.run_browser(checked_binary, output, label, args.browser_timeout_seconds, **options)

        calibration = launch("calibration-baseline")
        iterations = runtime.validate_workloads(calibration)
        report.update(calibration=calibration, iterations=iterations)
        runtime.write_json(output / REPORT_NAME, report)
        for index in range(args.samples):
            result = launch(f"sample-{index + 1:02d}-baseline", iterations=iterations)
            report["samples"].append(result)
            runtime.write_json(output / REPORT_NAME, report)
        measured = True
    except Exception as exception:
        record_error("smoke", exception)
    finally:
        if installed:
            # Capture partial installs or retry a missing inventory before
            # uninstall. Only the disposable install is inspected.
            try:
                inventory_path = output / "baseline-installed-files.json"
                if not inventory_path.is_file():
                    inventory = runtime.record_browser_inventory(destination, inventory_path)
                else:
                    inventory = runtime.read_json(inventory_path)
                report["installed_inventory"] = {"filename": inventory_path.name,
                                                 "sha256": runtime.sha256(inventory_path),
                                                 "entries": len(inventory["entries"])}
            except Exception as exception:
                record_error("installed-inventory", exception)
            try:
                uninstaller = destination / "uninstall.exe"
                if uninstaller.is_symlink() or not uninstaller.is_file():
                    runtime.fail("installed baseline has no safe uninstaller; runner disposal may be required")
                with uninstaller.open("rb") as stream:
                    if stream.read(2) != b"MZ":
                        runtime.fail("installed baseline uninstaller is not a Windows PE executable")
                metadata = runtime.run_native([str(uninstaller), "/S"], output / "baseline-uninstall.log",
                                              args.installer_timeout_seconds)
                report["cleanup"].append({"variant": "baseline", "uninstalled": True, "native_process": metadata})
            except Exception as exception:
                report["cleanup"].append({"variant": "baseline", "uninstalled": False, "error": str(exception)})
                record_error("uninstall", exception)
            try:
                runtime.reject_existing_install()
                report["registry_cleanup_verified"] = True
            except Exception as exception:
                report["registry_cleanup_verified"] = False
                record_error("registry-cleanup", exception)
        if work:
            try:
                shutil.rmtree(work)
                report["temporary_cleanup_verified"] = True
            except Exception as exception:
                report["temporary_cleanup_verified"] = False
                record_error("temporary-cleanup", exception)
        # Never upload test profile preferences/cache, including a profile left
        # by a failed browser or profile-cleanup error. Preserve other evidence.
        try:
            for profile in output.glob("*/profile"):
                if profile.is_symlink():
                    profile.unlink()
                else:
                    shutil.rmtree(profile)
            report["profiles_removed"] = not any(output.glob("*/profile"))
        except Exception as exception:
            report["profiles_removed"] = False
            record_error("profile-cleanup", exception)
        if measured and error is None:
            report["status"] = "passed"
        runtime.write_json(output / REPORT_NAME, report)
    if error:
        raise error
    print("Baseline-only native offline harness: " + report["status"])
    print("Not a validated PGO pipeline. Report: " + str(output / REPORT_NAME))
    return report


def main(argv=None):
    temporary = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir()))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-directory", type=Path, default=temporary / "baseline-smoke",
                        help="verified prepare-baseline output (default: runner temp/baseline-smoke)")
    parser.add_argument("--output-directory", type=Path, default=temporary / "baseline-harness",
                        help="fresh diagnostics directory (default: runner temp/baseline-harness)")
    parser.add_argument("--upstream-lock", type=Path, default=ROOT / "upstream.lock.json")
    parser.add_argument("--browser-diagnostics", action="store_true",
                        help="opt in to native browser navigation logs; does not change preferences or workload")
    parser.add_argument("--samples", type=runtime.positive_int, default=1,
                        help="fixed-count measured launches after calibration, 1..3 (default: 1)")
    parser.add_argument("--target-milliseconds", type=runtime.positive_int, default=1200)
    parser.add_argument("--browser-timeout-seconds", type=runtime.positive_int, default=180)
    parser.add_argument("--installer-timeout-seconds", type=runtime.positive_int, default=300)
    args = parser.parse_args(argv)
    if args.samples > 3 or args.target_milliseconds < 1000:
        parser.error("use 1..3 samples and calibration target >=1000ms; keep privacy timer defaults")
    try:
        run_smoke(args)
        return 0
    except Exception as exception:
        print("Baseline harness failed: " + str(exception), file=sys.stderr)
        return exception.returncode if isinstance(exception, runtime.NativeError) else 1


if __name__ == "__main__":
    runtime.exit_process(main())
