#!/usr/bin/env python3
"""Merge exact Firefox training and commit a hash-bound C++ AND Rust bundle.

Usage: merge-pgo-profile.py --llvm-profdata /pinned/bin/llvm-profdata
  --training-directory /training --build-provenance /provenance/build.json
  --output-directory /profile

The merge compiler must match the generated Clang version. Rust LLVM versions
are recorded, not assumed equivalent: native llvm-profdata validates every raw
input. A successful merge still needs positive C++ and Rust function counters.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import shutil
import sys

spec = importlib.util.spec_from_file_location("profile_artifacts", Path(__file__).with_name("profile-artifacts.py"))
artifacts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifacts)

SUMMARY_FIELDS = {"Total functions": "total_functions", "Total number of blocks": "total_blocks",
                  "Total count": "total_count", "Maximum function count": "maximum_function_count",
                  "Maximum internal block count": "maximum_internal_block_count"}
RUST_SYMBOL = re.compile(r"(?:^|[:;])_?_(?:R[A-Za-z0-9_]+|ZN.*17h[0-9a-f]{16}E)(?:[.$].*)?$")
CPP_SYMBOL = re.compile(r"(?:^|[:;])(?:_?_Z[A-Za-z0-9_]+|\?.+)(?:[.$].*)?$")


def llvm_version(text, compiler=False):
    label = r"clang version" if compiler else r"LLVM version"
    match = re.search(label + r"\s+(\d+\.\d+\.\d+)(?:[\s\-+]|$)", text, re.IGNORECASE)
    artifacts.require(match is not None, f"cannot resolve pinned {'Clang' if compiler else 'LLVM'} version")
    return match.group(1)


def summary_counts(path):
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"([^:]+):\s*(\d+)\s*", line)
        if match and match.group(1) in SUMMARY_FIELDS:
            key = SUMMARY_FIELDS[match.group(1)]
            artifacts.require(key not in result, f"duplicate LLVM summary field: {key}")
            result[key] = int(match.group(2))
    artifacts.require(set(result) == set(SUMMARY_FIELDS.values()), "incomplete instrumentation counter summary")
    artifacts.require(all(result[key] > 0 for key in ("total_functions", "total_blocks", "total_count")),
                      "merged profile has no positive function/counter data")
    artifacts.require(max(result["maximum_function_count"], result["maximum_internal_block_count"]) > 0,
                      "merged profile has only zero counters")
    return result


def language_counts(path):
    # LLVM 21 show --all-functions --counts writes each name at indent 2 and its
    # counter list at indent 4. Read as a stream: Firefox has many functions.
    result = {"positive_cpp_functions": 0, "positive_rust_functions": 0}
    examples = {"c++": [], "rust": []}
    name, count, positive = None, 0, False

    def finish():
        if name is None or count <= 0 or not positive:
            return
        language = "rust" if RUST_SYMBOL.search(name) else "c++" if CPP_SYMBOL.search(name) else None
        if language:
            result["positive_rust_functions" if language == "rust" else "positive_cpp_functions"] += 1
            if len(examples[language]) < 3:
                examples[language].append(name)

    with path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if line.startswith("  ") and not line.startswith("   ") and line.rstrip().endswith(":"):
                finish()
                name, count, positive = line.strip()[:-1], 0, False
            else:
                match = re.fullmatch(r"\s{4}Counters:\s*(\d+)\s*", line.rstrip())
                if match:
                    count = int(match.group(1))
                match = re.fullmatch(r"\s{4}Function count:\s*(\d+)\s*", line.rstrip())
                if match:
                    positive = positive or int(match.group(1)) > 0
                match = re.fullmatch(r"\s{4}Block counts:\s*\[([0-9, ]*)\]\s*", line.rstrip())
                if match:
                    positive = positive or any(int(value.strip()) > 0 for value in match.group(1).split(",") if value.strip())
    finish()
    artifacts.require(result["positive_cpp_functions"] > 0, "no positive C++ mangled function counters")
    artifacts.require(result["positive_rust_functions"] > 0, "no positive Rust mangled function counters")
    return {**result, "symbol_examples": examples}


def merge(args):
    output = args.output_directory.resolve()
    artifacts.require(not output.is_symlink() and output not in
                      (args.training_directory.resolve(), args.build_provenance.parent.resolve()),
                      "merge output must be a separate directory")
    output.mkdir(parents=True, exist_ok=True)
    artifacts.require(not any((output / name).exists() for name in (*artifacts.PAYLOAD_NAMES, artifacts.REGISTRY_NAME)),
                      "refusing to overwrite an existing merged profile bundle")
    build, training, raw = artifacts.validate_training(args.training_directory, args.build_provenance)
    tool = str(args.llvm_profdata.resolve())
    artifacts.describe(args.llvm_profdata)
    artifacts.run_logged([tool, "--version"], output / "llvm-profdata-version.log")
    version_text = (output / "llvm-profdata-version.log").read_text(encoding="utf-8")
    artifacts.require(llvm_version(version_text) == llvm_version(build["clang_identity"], compiler=True),
                      "llvm-profdata does not match instrumented Clang")
    # Do not drop zero functions (--sparse) or tolerate a malformed raw input.
    # Native exit codes and diagnostic files survive every failure.
    artifacts.run_logged([tool, "merge", "--failure-mode=any", "-o", str(output / "merged.profdata"),
                          *map(str, raw)], output / "llvm-profdata-merge.log")
    artifacts.describe(output / "merged.profdata")
    # Ordinary show prints the summary. LLVM 21 has no --summary-only option.
    artifacts.run_logged([tool, "show", str(output / "merged.profdata")], output / "llvm-profdata-summary.log")
    counters = summary_counts(output / "llvm-profdata-summary.log")
    artifacts.run_logged([tool, "show", "--all-functions", "--counts", str(output / "merged.profdata")],
                          output / "llvm-profdata-functions.log")
    counters.update(language_counts(output / "llvm-profdata-functions.log"))
    shutil.copyfile(args.training_directory / "jarlog", output / "jarlog")
    provenance = {**build, "llvm_profdata_identity": version_text.strip(),
                  "llvm_profdata_binary_sha256": artifacts.sha(args.llvm_profdata),
                  "merged_profdata_sha256": artifacts.sha(output / "merged.profdata"),
                  "jarlog_sha256": artifacts.sha(output / "jarlog"),
                  "counter_evidence": counters, "training": training,
                  "training_manifest_sha256": artifacts.sha(args.training_directory / artifacts.TRAINING_NAME),
                  "llvm_summary_sha256": artifacts.sha(output / "llvm-profdata-summary.log"),
                  "llvm_functions_sha256": artifacts.sha(output / "llvm-profdata-functions.log")}
    artifacts.write_json(output / "provenance.json", provenance)
    # The registry is created last locally, just as it is published last remotely.
    registry = artifacts.registry_for(output, provenance)
    artifacts.write_json(output / artifacts.REGISTRY_NAME, registry)
    artifacts.validate_bundle(output)
    print(f"Verified {counters['positive_cpp_functions']} C++ and {counters['positive_rust_functions']} Rust functions.")
    print(f"PROFILE_IDENTITY={registry['identity_sha256']}")
    print(f"PROFILE_RELEASE={registry['release_tag']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-profdata", type=Path, required=True)
    parser.add_argument("--training-directory", type=Path, required=True)
    parser.add_argument("--build-provenance", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    merge(parser.parse_args())


if __name__ == "__main__":
    artifacts.cli(main)
