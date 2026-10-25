#!/usr/bin/env python3
import json
import sys
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Usage: render-privacytests-scorecard.py <results.json> [summary_file]")
        sys.exit(1)

    out_f = Path(sys.argv[1])
    summary_f = Path(sys.argv[2]) if len(sys.argv) > 2 else None

    if not out_f.is_file():
        print(f"Results file not found: {out_f}")
        sys.exit(0)

    with open(out_f, encoding="utf-8") as fp:
        raw = json.load(fp)

    test_run = raw.get("all_tests", [{}])[0]
    results = test_run.get("testResults", {})

    md = "# 🛡️ Official PrivacyTests.org Scorecard: Mullvad Browser Android\n\n"
    md += f"**Package:** `{test_run.get('browser')}` (version `{test_run.get('reportedVersion')}`)\n"
    md += f"**Platform:** {raw.get('platform')} ({test_run.get('os')} {test_run.get('os_version')})\n\n"

    total_passed = 0
    total_failed = 0
    total_unsupported = 0
    cat_tables = []

    for cat_name, tests in results.items():
        if not isinstance(tests, dict) or not tests:
            continue
        c_passed = 0
        c_failed = 0
        rows = []
        for t_name, t_val in tests.items():
            if not isinstance(t_val, dict):
                continue
            is_pass = t_val.get("passed") is True
            is_unsupp = t_val.get("unsupported") is True
            if is_unsupp:
                total_unsupported += 1
                status = "⚪ Unsupported"
            elif is_pass:
                total_passed += 1
                c_passed += 1
                status = "✅ Pass"
            else:
                total_failed += 1
                c_failed += 1
                status = "❌ Fail"
            desc = str(t_val.get("description", "")).replace("|", "-")
            rows.append(f"| **{t_name}** | {status} | {desc} |")

        denom = c_passed + c_failed
        pct = round((c_passed / denom) * 100) if denom > 0 else 100
        t_md = f"### Category: {cat_name.capitalize()}\n"
        t_md += f"**Score:** {c_passed} / {denom} passed ({pct}%)\n\n"
        t_md += "| Test | Status | Description |\n| :--- | :---: | :--- |\n" + "\n".join(rows) + "\n\n"
        cat_tables.append(t_md)

    overall_denom = total_passed + total_failed
    overall_pct = round((total_passed / overall_denom) * 100) if overall_denom > 0 else 100
    md += f"## 🏆 Overall Privacy Score: {total_passed} / {overall_denom} Passed ({overall_pct}%)\n\n"
    md += f"- **Passed (Protected):** {total_passed} ✅\n"
    md += f"- **Failed (Leaked):** {total_failed} ❌\n"
    md += f"- **Unsupported / N/A:** {total_unsupported} ⚪\n\n---\n\n"
    md += "".join(cat_tables)

    print(md)
    if summary_f:
        with open(summary_f, "a", encoding="utf-8") as sfp:
            sfp.write(md)

if __name__ == "__main__":
    main()
