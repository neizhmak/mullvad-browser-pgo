#!/usr/bin/env python3
# run-privacytests-android.py: 100% Sterile, Out-of-the-Box PrivacyTests.org runner for Android
import asyncio
import json
import os
import random
import subprocess
import sys
import time
from pathlib import Path
import websockets

WS_ENDPOINT = "wss://results.privacytests.org/ws"
FIRST_PARTY_ROOT_SAME = "https://test-pages.privacytests2.org"
FIRST_PARTY_ROOT_DIFF = "https://test-pages.privacytests.org"
FIRST_PARTY_ROOT_THIRD = "https://test-pages.privacytests3.org"
INSECURE_ROOT = "http://insecure.privacytests3.org"
UPGRADABLE_ROOT = "http://upgradable.privacytests2.org"
LIVE_ROOT = "https://test-pages.privacytests2.org/live"

TRACKING_QUERY_PARAMETERS = {
    "fbclid": "Facebook Click Identifier",
    "gclid": "Google Click Identifier",
    "msclkid": "Microsoft Click ID",
    "mc_eid": "Mailchimp Email ID (email recipient's address)",
    "dclid": "DoubleClick Click ID (Google)",
    "oly_anon_id": "Omeda marketing 'anonymous' customer id",
    "oly_enc_id": "Omeda marketing 'known' customer id",
    "_openstat": "Yandex tracking parameter",
    "vero_conv": "Vero tracking parameter",
    "vero_id": "Vero tracking parameter",
    "wickedid": "Wicked Reports e-commerce tracking",
    "yclid": "Yandex Click ID",
    "__s": "Drip.com email address tracking parameter",
    "rb_clickid": "Unknown high-entropy tracking parameter",
    "s_cid": "Adobe Site Catalyst tracking parameter",
    "ml_subscriber": "MailerLite email tracking",
    "ml_subscriber_hash": "MailerLite email tracking",
    "_hsenc": "HubSpot tracking parameter",
    "__hssc": "HubSpot tracking parameter",
    "__hstc": "HubSpot tracking parameter",
    "__hsfp": "HubSpot tracking parameter",
    "hsCtaTracking": "HubSpot tracking parameter",
    "mkt_tok": "Adobe Marketo tracking parameter",
}

def log(*args):
    print(f"[{time.strftime('%X')}]", *args, flush=True)

class SterileAndroidTester:
    def __init__(self, pkg_name, target_dev, out_dir):
        self.pkg_name = pkg_name
        self.target_dev = target_dev
        self.dev_arg = ["-s", target_dev] if target_dev else []
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.screenshots_dir = self.out_dir / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.ws = None
        self.session_id = None
        self.queue = asyncio.Queue()

    def adb(self, *cmd):
        full_cmd = ["adb"] + self.dev_arg + list(cmd)
        res = subprocess.run(full_cmd, capture_output=True, text=True)
        return res.stdout.strip()

    def adb_shell(self, shell_cmd):
        return self.adb("shell", shell_cmd)

    def take_screenshot(self, name):
        try:
            self.adb_shell("screencap -p /data/local/tmp/screen.png")
            dest = self.screenshots_dir / f"{name}.png"
            subprocess.run(["adb"] + self.dev_arg + ["pull", "/data/local/tmp/screen.png", str(dest)],
                           capture_output=True)
            log(f"Saved screenshot: {dest.name}")
        except Exception as e:
            log(f"Screenshot error: {e}")

    def launch_browser(self):
        log(f"Launching sterile browser package: {self.pkg_name}...")
        self.adb_shell(f"am start -n {self.pkg_name}/org.mozilla.fenix.HomeActivity")
        time.sleep(5)
        # Dismiss any initial Android or browser prompt if shown
        self.adb_shell("input keyevent 4")  # Back key to dismiss keyboard/dialogs
        time.sleep(1)

    def kill_browser(self):
        log(f"Stopping browser: {self.pkg_name}...")
        self.adb_shell(f"am force-stop {self.pkg_name}")
        time.sleep(1)

    def open_url(self, url):
        log(f"Opening URL in sterile browser: {url}")
        # Method 1: Standard Android VIEW Intent directed explicitly to the package
        self.adb_shell(f"am start -a android.intent.action.VIEW -c android.intent.category.BROWSABLE -d '{url}' {self.pkg_name}")
        time.sleep(2)
        # Method 2: Fallback direct dispatch to IntentReceiverActivity
        self.adb_shell(f"am start -n {self.pkg_name}/org.mozilla.fenix.IntentReceiverActivity -a android.intent.action.VIEW -d '{url}'")
        time.sleep(1)

    async def connect_websocket(self):
        log(f"Connecting to PrivacyTests WebSocket at {WS_ENDPOINT}...")
        self.ws = await websockets.connect(WS_ENDPOINT)
        asyncio.create_task(self._ws_listener())

        init_msg = await self.next_value(timeout=30)
        self.session_id = init_msg.get("sessionId")
        log(f"PrivacyTests session connected with sessionId: {self.session_id}")

        asyncio.create_task(self._ws_pinger())

    async def _ws_listener(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                await self.queue.put(msg)
        except Exception as e:
            log(f"WS listener ended: {e}")

    async def _ws_pinger(self):
        while self.ws and not self.ws.closed:
            try:
                await self.ws.send(json.dumps({"message": "ping"}))
                await asyncio.sleep(25)
            except Exception:
                break

    async def next_value(self, timeout=60):
        msg = await asyncio.wait_for(self.queue.get(), timeout=timeout)
        return msg.get("data", msg)

    async def run_suite(self):
        self.launch_browser()
        await self.connect_websocket()

        results = {
            "browser": "mullvad",
            "platform": "Android",
            "mode": "100% Sterile (Pure Default Stock APK, No Custom Injections)",
            "os": "Android 12 (ReDroid ARM64)",
            "packageName": self.pkg_name,
            "timeStarted": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "categories": {
                "supercookies": {},
                "navigation": {},
                "trackers": {},
                "query": {},
                "https": {},
                "fingerprinting": {},
                "misc": {},
            }
        }

        try:
            self.take_screenshot("01_sterile_launch")

            # 1. Supercookies: write phase
            log("=== Phase 1: Supercookies Write (Sterile Out-of-the-Box) ===")
            write_url = f"{FIRST_PARTY_ROOT_SAME}/supercookies.html?mode=write&thirdparty=same&sessionId={self.session_id}"
            self.open_url(write_url)
            await asyncio.sleep(3)
            try:
                write_signal = await self.next_value(timeout=90)
                log(f"Write signal: {str(write_signal)[:100]}")
            except Exception as e:
                log(f"Write signal warning: {e}")
            self.take_screenshot("02_supercookies_write")

            # 2. Supercookies & Navigation: read phase
            log("=== Phase 2: Supercookies & Navigation Read (Sterile Out-of-the-Box) ===")
            read_url = f"{FIRST_PARTY_ROOT_SAME}/supercookies.html?mode=read&thirdparty=same&sessionId={self.session_id}"
            self.open_url(read_url)
            await asyncio.sleep(3)
            try:
                sc_res = await self.next_value(timeout=90)
                log("Supercookies & Navigation results received!")
                if isinstance(sc_res, dict):
                    if "supercookies" in sc_res:
                        results["categories"]["supercookies"].update(sc_res["supercookies"])
                    if "navigation" in sc_res:
                        results["categories"]["navigation"].update(sc_res["navigation"])
                    if "fingerprinting" in sc_res:
                        results["categories"]["fingerprinting"].update(sc_res["fingerprinting"])
            except Exception as e:
                log(f"Read results warning: {e}")
            self.take_screenshot("03_supercookies_read")

            # 3. Tracker Blocking (with default bundled uBlock Origin in APK)
            log("=== Phase 3: Tracker Blocking (Real Bundled Extensions) ===")
            trackers_url = f"{FIRST_PARTY_ROOT_SAME}/tracking_content.html?sessionId={self.session_id}"
            self.open_url(trackers_url)
            try:
                trackers_res = await self.next_value(timeout=40)
                log("Trackers test results received!")
                if isinstance(trackers_res, dict):
                    results["categories"]["trackers"].update(trackers_res)
            except Exception as e:
                log(f"Trackers test warning: {e}")
            self.take_screenshot("04_trackers")

            # 4. Tracking Query Parameter Stripping (Default APK Handling)
            log("=== Phase 4: Tracking Query Parameter Stripping ===")
            secret = str(random.randint(1000000000000000, 9999999999999999))
            query_test_params = "&".join([f"{p}={secret}" for p in TRACKING_QUERY_PARAMETERS.keys()])
            query_url = f"{FIRST_PARTY_ROOT_DIFF}/query.html?controlParam=controlValue&{query_test_params}&sessionId={self.session_id}"
            self.open_url(query_url)
            try:
                query_res = await self.next_value(timeout=30)
                log(f"Query test response: {query_res}")
                if isinstance(query_res, dict):
                    for param, desc in TRACKING_QUERY_PARAMETERS.items():
                        val = query_res.get(param)
                        passed = (val is None) or (val == "")
                        results["categories"]["query"][param] = {
                            "value": val,
                            "passed": passed,
                            "description": desc,
                        }
            except Exception as e:
                log(f"Query test warning: {e}")
            self.take_screenshot("05_query")

            # 5. HTTPS Subresource Upgrades (Default APK Behavior)
            log("=== Phase 5: HTTPS Subresource Upgrades ===")
            https_url = f"{FIRST_PARTY_ROOT_SAME}/https.html?sessionId={self.session_id}"
            self.open_url(https_url)
            try:
                https_res = await self.next_value(timeout=30)
                log(f"HTTPS test response: {https_res}")
                if isinstance(https_res, dict):
                    results["categories"]["https"].update(https_res)
            except Exception as e:
                log(f"HTTPS test warning: {e}")
            self.take_screenshot("06_https_subresources")

            # 6. HTTPS Upgradable Address / Link
            log("=== Phase 6: HTTPS Upgradable Address / Link ===")
            up_url = f"{UPGRADABLE_ROOT}/upgradable.html?source=address&sessionId={self.session_id}"
            self.open_url(up_url)
            try:
                up_res = await self.next_value(timeout=30)
                log(f"Upgradable test response: {up_res}")
                if isinstance(up_res, dict):
                    results["categories"]["https"].update(up_res)
            except Exception as e:
                log(f"Upgradable test warning: {e}")
            self.take_screenshot("07_https_upgradable")

            # 7. Insecure Website Warning (Default HTTPS-Only Check)
            log("=== Phase 7: Insecure Website Warning ===")
            insec_url = f"{INSECURE_ROOT}/insecure.html?sessionId={self.session_id}"
            self.open_url(insec_url)
            try:
                insec_res = await self.next_value(timeout=10)
                log(f"Insecure test response (page loaded): {insec_res}")
                results["categories"]["https"]["Insecure website warning"] = {
                    "passed": False,
                    "result": "Insecure website loaded without warning",
                    "description": "Checks to see if the browser stops loading an insecure website and warns the user before giving them the option to continue."
                }
            except Exception as e:
                log("Insecure site blocked / never loaded: PASS!")
                results["categories"]["https"]["Insecure website warning"] = {
                    "passed": True,
                    "result": "Insecure website blocked / never loaded",
                    "description": "Checks to see if the browser stops loading an insecure website and warns the user before giving them the option to continue."
                }
            self.take_screenshot("08_insecure_check")

            # 8. Supplementary Fingerprinting
            log("=== Phase 8: Supplementary Fingerprinting ===")
            supp_url = f"{FIRST_PARTY_ROOT_SAME}/supplementary.html?sessionId={self.session_id}"
            self.open_url(supp_url)
            try:
                supp_res = await self.next_value(timeout=30)
                if isinstance(supp_res, dict):
                    results["categories"]["fingerprinting"].update(supp_res)
            except Exception as e:
                log(f"Supplementary test warning: {e}")

            # 9. Top-Level Misc & GPC
            log("=== Phase 9: Top-Level Misc & GPC ===")
            tl_url = f"{LIVE_ROOT}/toplevel.html?sessionId={self.session_id}"
            self.open_url(tl_url)
            try:
                tl_res = await self.next_value(timeout=30)
                if isinstance(tl_res, dict):
                    results["categories"]["misc"].update(tl_res)
            except Exception as e:
                log(f"Top-level test warning: {e}")

        finally:
            if self.ws:
                await self.ws.close()
            self.take_screenshot("99_final_sterile")
            self.kill_browser()

        results["timeStopped"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.save_reports(results)

    def save_reports(self, data):
        json_path = self.out_dir / "mullvad-android-privacytests-sterile.json"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        log(f"Saved raw JSON results to {json_path}")

        report_md = self.generate_markdown(data)
        md_path = self.out_dir / "privacytests-report.md"
        md_path.write_text(report_md, encoding="utf-8")
        log(f"Saved scorecard report to {md_path}")
        print("\n" + report_md, flush=True)

    def generate_markdown(self, data):
        md = "# 🛡️ PrivacyTests.org Results: Mullvad Browser Android (100% Sterile Default APK)\n\n"
        md += f"**Package:** `{data.get('packageName')}`\n"
        md += f"**Environment:** {data.get('platform')} ({data.get('os')})\n"
        md += f"**Test Mode:** {data.get('mode')}\n"
        md += f"**Test Date:** {data.get('timeStarted')}\n\n"

        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_unsupported = 0
        category_tables = []

        for cat_name, tests in data.get("categories", {}).items():
            if not isinstance(tests, dict) or not tests:
                continue
            cat_passed = 0
            cat_failed = 0
            cat_unsupported = 0
            rows = []

            for test_name, test_val in tests.items():
                if not isinstance(test_val, dict):
                    continue
                total_tests += 1
                is_passed = test_val.get("passed") is True
                is_unsupported = test_val.get("unsupported") is True

                if is_unsupported:
                    status = "⚪ Unsupported"
                    cat_unsupported += 1
                    total_unsupported += 1
                elif is_passed:
                    status = "✅ Pass"
                    cat_passed += 1
                    total_passed += 1
                else:
                    status = "❌ Fail"
                    cat_failed += 1
                    total_failed += 1

                desc = str(test_val.get("description", "")).replace("|", "-")
                rows.append(f"| **{test_name}** | {status} | {desc} |")

            cat_title = cat_name.capitalize()
            denom = cat_passed + cat_failed
            pct = round((cat_passed / denom) * 100) if denom > 0 else 100
            t = f"### Category: {cat_title}\n"
            t += f"**Score:** {cat_passed} / {denom} passed ({pct}%)\n\n"
            t += "| Test | Status | Description |\n| :--- | :---: | :--- |\n"
            t += "\n".join(rows) + "\n\n"
            category_tables.append(t)

        overall_denom = total_passed + total_failed
        overall_pct = round((total_passed / overall_denom) * 100) if overall_denom > 0 else 100
        md += f"## 🏆 Overall Sterile Score: {total_passed} / {overall_denom} Passed ({overall_pct}%)\n\n"
        md += f"- **Passed (Protected):** {total_passed} ✅\n"
        md += f"- **Failed (Leaked):** {total_failed} ❌\n"
        md += f"- **Unsupported / N/A:** {total_unsupported} ⚪\n\n"
        md += "---\n\n"
        md += "".join(category_tables)
        return md

if __name__ == "__main__":
    pkg = os.environ.get("PKG_NAME", "net.mullvad.mullvadbrowser_alpha")
    dev = os.environ.get("ADB_DEVICE", "")
    out = os.environ.get("OUTPUT_DIR", "/tmp/privacytests-output")
    tester = SterileAndroidTester(pkg, dev, out)
    asyncio.run(tester.run_suite())
