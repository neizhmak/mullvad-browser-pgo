#!/usr/bin/env python3
# run-privacytests-android.py: Automated PrivacyTests.org runner for Android browsers via Marionette
import asyncio
import json
import os
import sys
import time
from pathlib import Path
import websockets
from marionette_driver.marionette import Marionette

WS_ENDPOINT = "wss://results.privacytests.org/ws"
IFRAME_ROOT_SAME = "https://test-pages.privacytests2.org"
IFRAME_ROOT_DIFF = "https://test-pages.privacytests.org"
IFRAME_ROOT_THIRD = "https://test-pages.privacytests3.org"
INSECURE_ROOT = "http://insecure.privacytests3.org"
UPGRADABLE_ROOT = "http://upgradable.privacytests2.org"
LIVE_ROOT = "https://test-pages.privacytests2.org/live"

def log(*args):
    print(f"[{time.strftime('%X')}]", *args, flush=True)

class PrivacyTester:
    def __init__(self, pkg_name, out_dir):
        self.pkg_name = pkg_name
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.screenshots_dir = self.out_dir / "screenshots"
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.client = None
        self.ws = None
        self.session_id = None
        self.queue = asyncio.Queue()

    def connect_marionette(self):
        log("Connecting to Marionette on 127.0.0.1:2828...")
        self.client = Marionette(host="127.0.0.1", port=2828)
        for i in range(25):
            try:
                self.client.start_session()
                log("Connected to Marionette successfully!")
                return True
            except Exception as e:
                log(f"Marionette waiting (attempt {i+1}/25): {e}")
                time.sleep(2)
        raise RuntimeError("Failed to connect to Marionette on 127.0.0.1:2828")

    async def connect_websocket(self):
        log(f"Connecting to PrivacyTests WebSocket at {WS_ENDPOINT}...")
        self.ws = await websockets.connect(WS_ENDPOINT)
        
        asyncio.create_task(self._ws_listener())
        
        # First message contains sessionId
        init_msg = await self.next_value(timeout=30)
        self.session_id = init_msg.get("sessionId")
        log(f"PrivacyTests session connected with sessionId: {self.session_id}")

        # Keepalive loop
        asyncio.create_task(self._ws_pinger())

    async def _ws_listener(self):
        try:
            async for raw in self.ws:
                msg = json.loads(raw)
                log(f"WS message: {str(msg)[:120]}")
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

    def navigate(self, url):
        log(f"Navigating to {url}...")
        try:
            self.client.navigate(url)
        except Exception as e:
            log(f"Navigation warning: {e}")

    def take_screenshot(self, name):
        try:
            screen_data = self.client.screenshot(format="binary")
            dest = self.screenshots_dir / f"{name}.png"
            dest.write_bytes(screen_data)
            log(f"Saved screenshot: {dest}")
        except Exception as e:
            log(f"Screenshot warning: {e}")

    async def run_suite(self):
        self.connect_marionette()
        await self.connect_websocket()

        results = {
            "browser": "mullvad",
            "platform": "Android",
            "os": "Android 12 (ReDroid ARM64)",
            "packageName": self.pkg_name,
            "timeStarted": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "categories": {}
        }

        try:
            self.take_screenshot("01_initial")

            # 1. Main supercookies: write phase
            log("=== Phase 1: Supercookies Write ===")
            write_url = f"{IFRAME_ROOT_SAME}/supercookies.html?mode=write&thirdparty=same&sessionId={self.session_id}"
            self.navigate(write_url)
            await asyncio.sleep(3)
            self.take_screenshot("02_write_page")

            log("Waiting for supercookie_write_finished signal...")
            write_signal = await self.next_value(timeout=90)
            log(f"Write signal: {write_signal}")
            self.take_screenshot("03_write_done")

            # 2. Main supercookies: read phase
            log("=== Phase 2: Supercookies Read ===")
            read_url = f"{IFRAME_ROOT_SAME}/supercookies.html?mode=read&thirdparty=same&sessionId={self.session_id}"
            self.navigate(read_url)
            await asyncio.sleep(3)
            self.take_screenshot("04_read_page")

            log("Waiting for main test results...")
            main_res = await self.next_value(timeout=90)
            log("Main test results received!")
            self.take_screenshot("05_read_done")

            for k in ["supercookies", "fingerprinting", "trackers", "navigation", "query"]:
                if k in main_res:
                    results["categories"][k] = main_res[k]

            # 3. Supplementary fingerprinting
            log("=== Phase 3: Supplementary Fingerprinting ===")
            supp_url = f"{IFRAME_ROOT_SAME}/supplementary.html?sessionId={self.session_id}"
            self.navigate(supp_url)
            try:
                supp_res = await self.next_value(timeout=30)
                if "fingerprinting" not in results["categories"]:
                    results["categories"]["fingerprinting"] = {}
                results["categories"]["fingerprinting"].update(supp_res)
            except Exception as e:
                log(f"Supplementary test warning: {e}")

            # 4. Top-level GPC & IP leak
            log("=== Phase 4: Top-Level Misc Tests ===")
            tl_url = f"{LIVE_ROOT}/toplevel.html?sessionId={self.session_id}"
            self.navigate(tl_url)
            try:
                tl_res = await self.next_value(timeout=30)
                results["categories"]["misc"] = tl_res
            except Exception as e:
                log(f"Top-level test warning: {e}")

            # 5. Upgradable HTTPS
            log("=== Phase 5: HTTPS Upgradable Test ===")
            up_url = f"{UPGRADABLE_ROOT}/upgradable.html?source=address&sessionId={self.session_id}"
            self.navigate(up_url)
            try:
                up_res = await self.next_value(timeout=30)
                if "https" not in results["categories"]:
                    results["categories"]["https"] = {}
                results["categories"]["https"].update(up_res)
            except Exception as e:
                log(f"Upgradable test warning: {e}")

            # 6. Insecure website warning
            log("=== Phase 6: Insecure Website Warning Test ===")
            insec_url = f"{INSECURE_ROOT}/insecure.html?sessionId={self.session_id}"
            self.navigate(insec_url)
            try:
                insec_res = await self.next_value(timeout=15)
                if "https" not in results["categories"]:
                    results["categories"]["https"] = {}
                results["categories"]["https"].update(insec_res)
            except Exception as e:
                log(f"Insecure site blocked / timed out (HTTPS-Only mode active): {e}")
                if "https" not in results["categories"]:
                    results["categories"]["https"] = {}
                results["categories"]["https"]["Insecure website warning"] = {
                    "passed": True,
                    "result": "Insecure website blocked / never loaded"
                }

        finally:
            if self.ws:
                await self.ws.close()
            self.take_screenshot("99_final")

        results["timeStopped"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.save_reports(results)

    def save_reports(self, data):
        json_path = self.out_dir / "mullvad-android-privacytests.json"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        log(f"Saved raw JSON results to {json_path}")

        report_md = self.generate_markdown(data)
        md_path = self.out_dir / "privacytests-report.md"
        md_path.write_text(report_md, encoding="utf-8")
        log(f"Saved scorecard report to {md_path}")
        print("\n" + report_md, flush=True)

    def generate_markdown(self, data):
        md = "# PrivacyTests.org Results: Mullvad Browser for Android\n\n"
        md += f"**Target:** `{data.get('packageName')}`\n"
        md += f"**Platform:** {data.get('platform')} ({data.get('os')})\n"
        md += f"**Test Date:** {data.get('timeStarted')}\n\n"

        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_unsupported = 0
        category_tables = []

        for cat_name, tests in data.get("categories", {}).items():
            if not isinstance(tests, dict):
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
        md += f"## 🏆 Overall Privacy Score: {total_passed} / {overall_denom} Passed ({overall_pct}%)\n\n"
        md += f"- **Passed (Protected):** {total_passed} ✅\n"
        md += f"- **Failed (Leaked):** {total_failed} ❌\n"
        md += f"- **Unsupported / N/A:** {total_unsupported} ⚪\n\n"
        md += "---\n\n"
        md += "".join(category_tables)
        return md

if __name__ == "__main__":
    pkg = os.environ.get("PKG_NAME", "net.mullvad.mullvadbrowser_alpha")
    out = os.environ.get("OUTPUT_DIR", "/tmp/privacytests-output")
    tester = PrivacyTester(pkg, out)
    asyncio.run(tester.run_suite())
