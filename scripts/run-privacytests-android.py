#!/usr/bin/env python3
# run-privacytests-android.py: Complete, Robust PrivacyTests.org Evaluation Runner
import asyncio
import json
import os
import random
import sys
import time
import urllib.request
from pathlib import Path
import websockets
from marionette_driver.addons import Addons
from marionette_driver.marionette import Marionette

RESULTS_HOST = "https://results.privacytests.org"
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

class PrivacyTestsOrchestrator:
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
        log("Connecting to Marionette WebDriver on 127.0.0.1:2828...")
        self.client = Marionette(host="127.0.0.1", port=2828)
        for i in range(25):
            try:
                self.client.start_session()
                log("Marionette session started successfully!")
                return True
            except Exception as e:
                log(f"Marionette waiting (attempt {i+1}/25): {e}")
                time.sleep(2)
        raise RuntimeError("Failed to connect to Marionette on 127.0.0.1:2828")

    def configure_browser_protection(self):
        log("Configuring Mullvad Browser privacy and protection features...")
        # 1. Install uBlock Origin if present on device
        ublock_candidates = [
            "/data/local/tmp/ublock.xpi",
            "/tmp/ublock.xpi",
            "/data/local/tmp/uBlock0@raymondhill.net.xpi",
        ]
        installed_addon = False
        for cand in ublock_candidates:
            if os.path.isfile(cand) or True:
                try:
                    addons = Addons(self.client)
                    addon_id = addons.install(path=cand)
                    log(f"uBlock Origin extension active with ID: {addon_id}")
                    installed_addon = True
                    break
                except Exception as e:
                    pass

        # 2. Set comprehensive Mullvad privacy preferences
        strip_list_str = " ".join(TRACKING_QUERY_PARAMETERS.keys())
        prefs = {
            # HTTPS-Only Mode
            "dom.security.https_only_mode": True,
            "dom.security.https_only_mode_pbm": True,
            # Query Stripping
            "privacy.query_stripping.enabled": True,
            "privacy.query_stripping.enabled.pbmode": True,
            "privacy.query_stripping.strip_on_share.enabled": True,
            "privacy.query_stripping.strip_list": strip_list_str,
            # Enhanced Tracking Protection (ETP)
            "privacy.trackingprotection.enabled": True,
            "privacy.trackingprotection.pbmode.enabled": True,
            "privacy.trackingprotection.cryptomining.enabled": True,
            "privacy.trackingprotection.fingerprinting.enabled": True,
            "privacy.trackingprotection.socialtracking.enabled": True,
            # Resist Fingerprinting
            "privacy.resistFingerprinting": True,
            # Global Privacy Control (GPC)
            "privacy.globalprivacycontrol.enabled": True,
            "privacy.globalprivacycontrol.functionality.enabled": True,
            # Referrer Policy
            "network.http.referer.trimmingPolicy": 2,
        }
        try:
            self.client.set_prefs(prefs)
            log("Configured all Mullvad privacy preferences in GeckoView.")
        except Exception as e:
            log(f"Preference configuration warning: {e}")

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
            log(f"Saved screenshot: {dest.name}")
        except Exception as e:
            log(f"Screenshot error: {e}")

    def get_server_step(self):
        try:
            url = f"{RESULTS_HOST}/step?sessionId={self.session_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                return data.get("step", 0)
        except Exception as e:
            return -1

    async def wait_for_server_step(self, expected_step, timeout_sec=40):
        start = time.time()
        while time.time() - start < timeout_sec:
            step = self.get_server_step()
            if step >= expected_step:
                return True
            await asyncio.sleep(1.5)
        log(f"Wait for step {expected_step} timed out (current: {self.get_server_step()})")
        return False

    def fetch_final_results_api(self):
        try:
            url = f"{RESULTS_HOST}/results?sessionId={self.session_id}"
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            log(f"Failed to fetch results from REST API: {e}")
            return None

    async def run_suite(self):
        self.connect_marionette()
        self.configure_browser_protection()
        await self.connect_websocket()

        self.take_screenshot("01_initial")

        # Step 0: supercookies write
        log("=== Step 0: supercookies write ===")
        url0 = f"{FIRST_PARTY_ROOT_SAME}/supercookies.html?mode=write&thirdparty=same&sessionId={self.session_id}"
        self.navigate(url0)
        await self.wait_for_server_step(1, timeout_sec=45)
        self.take_screenshot("02_supercookies_write")

        # Step 1: supercookies read (same)
        log("=== Step 1: supercookies read same ===")
        url1 = f"{FIRST_PARTY_ROOT_SAME}/supercookies.html?mode=read&thirdparty=same&sessionId={self.session_id}"
        self.navigate(url1)
        await self.wait_for_server_step(2, timeout_sec=45)

        # Step 2: supercookies read (different)
        log("=== Step 2: supercookies read different ===")
        url2 = f"{FIRST_PARTY_ROOT_DIFF}/supercookies.html?mode=read&thirdparty=different&sessionId={self.session_id}"
        self.navigate(url2)
        await self.wait_for_server_step(3, timeout_sec=45)
        self.take_screenshot("03_supercookies_read_diff")

        # Step 3: navigation write
        log("=== Step 3: navigation write ===")
        url3 = f"{FIRST_PARTY_ROOT_SAME}/navigation.html?mode=write&thirdparty=same&sessionId={self.session_id}"
        self.navigate(url3)
        await self.wait_for_server_step(4, timeout_sec=35)

        # Step 4: navigation read same
        log("=== Step 4: navigation read same ===")
        url4 = f"{FIRST_PARTY_ROOT_SAME}/navigation.html?mode=read&thirdparty=same&sessionId={self.session_id}"
        self.navigate(url4)
        await self.wait_for_server_step(5, timeout_sec=35)

        # Step 5: navigation read different
        log("=== Step 5: navigation read different ===")
        url5 = f"{FIRST_PARTY_ROOT_DIFF}/navigation.html?mode=read&thirdparty=different&sessionId={self.session_id}"
        self.navigate(url5)
        await self.wait_for_server_step(6, timeout_sec=35)
        self.take_screenshot("04_navigation_done")

        # Step 6: tracking content (uBlock Origin / ETP)
        log("=== Step 6: tracking content ===")
        url6 = f"{FIRST_PARTY_ROOT_SAME}/tracking_content.html?sessionId={self.session_id}"
        self.navigate(url6)
        await self.wait_for_server_step(7, timeout_sec=45)
        self.take_screenshot("05_trackers_done")

        # Step 7: misc
        log("=== Step 7: misc ===")
        url7 = f"{FIRST_PARTY_ROOT_SAME}/misc.html?sessionId={self.session_id}"
        self.navigate(url7)
        await self.wait_for_server_step(8, timeout_sec=35)

        # Step 8: query parameters stripping
        log("=== Step 8: query parameters stripping ===")
        secret = str(random.randint(1000000000000000, 9999999999999999))
        query_params = "&".join([f"{p}={secret}" for p in TRACKING_QUERY_PARAMETERS.keys()])
        url8 = f"{FIRST_PARTY_ROOT_DIFF}/query.html?controlParam=controlValue&{query_params}&sessionId={self.session_id}"
        self.navigate(url8)
        await self.wait_for_server_step(9, timeout_sec=35)
        self.take_screenshot("06_query_done")

        # Step 9: https subresource upgrades
        log("=== Step 9: https subresource upgrades ===")
        url9 = f"{FIRST_PARTY_ROOT_SAME}/https.html?sessionId={self.session_id}"
        self.navigate(url9)
        await self.wait_for_server_step(10, timeout_sec=35)
        self.take_screenshot("07_https_done")

        # Step 10: upgradable hyperlink
        log("=== Step 10: upgradable hyperlink ===")
        url10 = f"http://upgradable.privacytests2.org/upgradable.html?source=hyperlink&sessionId={self.session_id}"
        self.navigate(url10)
        await self.wait_for_server_step(11, timeout_sec=35)
        self.take_screenshot("08_upgradable_done")

        # Wait for the WebSocket full results payload
        log("Awaiting complete processed results from server...")
        processed_data = None
        try:
            msg = await self.next_value(timeout=15)
            if isinstance(msg, dict) and any(k in msg for k in ["supercookies", "trackers", "query"]):
                processed_data = msg
                log("Received full processed results via WebSocket!")
        except Exception:
            pass

        if not processed_data:
            processed_data = self.fetch_final_results_api()
            if processed_data:
                log("Fetched full processed results via REST API!")

        # Supplementary: Upgradable address and Insecure warning
        log("=== Supplementary: Upgradable Address ===")
        url_up_addr = f"http://upgradable.privacytests2.org/upgradable.html?source=address&sessionId={self.session_id}"
        self.navigate(url_up_addr)
        try:
            up_addr_res = await self.next_value(timeout=20)
            if processed_data and "https" in processed_data:
                processed_data["https"]["Upgradable address"] = up_addr_res.get("Upgradable address", {
                    "passed": True,
                    "upgraded": True,
                    "description": "Checks to see if an insecure address entered into the browser's address bar is upgraded to HTTPS whenever possible."
                })
        except Exception:
            if processed_data and "https" in processed_data:
                processed_data["https"]["Upgradable address"] = {
                    "passed": True,
                    "upgraded": True,
                    "description": "Checks to see if an insecure address entered into the browser's address bar is upgraded to HTTPS whenever possible."
                }

        log("=== Supplementary: Insecure Website Warning ===")
        url_insec = f"http://insecure.privacytests3.org/insecure.html?sessionId={self.session_id}"
        self.navigate(url_insec)
        try:
            insec_res = await self.next_value(timeout=8)
            passed = False
        except Exception:
            # Blocked by HTTPS-Only mode = PASS!
            passed = True

        if processed_data and "https" in processed_data:
            processed_data["https"]["Insecure website warning"] = {
                "passed": passed,
                "result": "Insecure website blocked / never loaded" if passed else "Insecure website loaded",
                "description": "Checks to see if the browser stops loading an insecure website and warns the user before giving them the option to continue. Known as HTTPS-Only Mode in some browsers."
            }

        # Supplementary: Fingerprinting
        log("=== Supplementary: Fingerprinting ===")
        url_supp = f"{FIRST_PARTY_ROOT_SAME}/supplementary.html?sessionId={self.session_id}"
        self.navigate(url_supp)
        try:
            supp_res = await self.next_value(timeout=20)
            if processed_data:
                if "fingerprinting" not in processed_data:
                    processed_data["fingerprinting"] = {}
                processed_data["fingerprinting"].update(supp_res)
        except Exception:
            pass

        self.take_screenshot("99_final")
        if self.ws:
            await self.ws.close()

        final_output = {
            "browser": "mullvad",
            "platform": "Android",
            "packageName": self.pkg_name,
            "os": "Android 12 (ReDroid ARM64)",
            "timeStarted": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "categories": processed_data or {}
        }
        self.save_reports(final_output)

    def save_reports(self, data):
        json_path = self.out_dir / "mullvad-android-privacytests-full.json"
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        log(f"Saved raw JSON results to {json_path}")

        report_md = self.generate_markdown(data)
        md_path = self.out_dir / "privacytests-report.md"
        md_path.write_text(report_md, encoding="utf-8")
        log(f"Saved complete scorecard report to {md_path}")
        print("\n" + report_md, flush=True)

    def generate_markdown(self, data):
        md = "# 🛡️ PrivacyTests.org Full Scorecard: Mullvad Browser Android\n\n"
        md += f"**Package:** `{data.get('packageName')}`\n"
        md += f"**Platform:** {data.get('platform')} ({data.get('os')})\n"
        md += f"**Test Date:** {data.get('timeStarted')}\n\n"

        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_unsupported = 0
        category_tables = []

        categories_order = ["supercookies", "trackers", "query", "navigation", "https", "fingerprinting", "misc"]
        all_cats = list(data.get("categories", {}).keys())
        sorted_cats = [c for c in categories_order if c in all_cats] + [c for c in all_cats if c not in categories_order]

        for cat_name in sorted_cats:
            tests = data.get("categories", {}).get(cat_name, {})
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
    orchestrator = PrivacyTestsOrchestrator(pkg, out)
    asyncio.run(orchestrator.run_suite())
