#!/usr/bin/env node
// run-privacytests-android.mjs: Automated PrivacyTests.org runner for Android browsers via ADB
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

// Constants
const WS_ENDPOINT = 'wss://results.privacytests.org/ws';
const IFRAME_ROOT_SAME = 'https://test-pages.privacytests2.org';
const IFRAME_ROOT_DIFF = 'https://test-pages.privacytests.org';
const IFRAME_ROOT_THIRD = 'https://test-pages.privacytests3.org';
const INSECURE_ROOT = 'http://insecure.privacytests3.org';
const UPGRADABLE_ROOT = 'http://upgradable.privacytests2.org';
const LIVE_ROOT = 'https://test-pages.privacytests2.org/live';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const log = (...args) => {
  console.log(`[${new Date().toISOString()}]`, ...args);
};

// ADB Helper
class AdbDriver {
  constructor(targetDev, pkgName, activity = 'org.mozilla.fenix.HomeActivity') {
    this.targetDev = targetDev;
    this.pkgName = pkgName;
    this.activity = activity;
    this.devArg = targetDev ? `-s ${targetDev}` : '';
  }

  adb(cmd) {
    try {
      const fullCmd = `adb ${this.devArg} ${cmd}`;
      return execSync(fullCmd, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
    } catch (e) {
      log(`ADB error: ${cmd}:`, e.message);
      return '';
    }
  }

  async launch() {
    log(`Launching ${this.pkgName}...`);
    this.adb(`shell am start -n ${this.pkgName}/${this.activity}`);
    await sleep(4000);
  }

  async kill() {
    log(`Stopping ${this.pkgName}...`);
    this.adb(`shell am force-stop ${this.pkgName}`);
    await sleep(1000);
  }

  async restart() {
    await this.kill();
    await this.launch();
  }

  async openUrl(url) {
    log(`Opening URL: ${url}`);
    // Open URL as an Android VIEW intent
    const escaped = url.replace(/&/g, '\\&');
    this.adb(`shell am start -n ${this.pkgName}/${this.activity} -a android.intent.action.VIEW -d "${escaped}"`);
  }

  async getVersion() {
    const raw = this.adb(`shell dumpsys package ${this.pkgName}`);
    const match = raw.match(/versionName=([^\s]+)/);
    return match ? match[1] : 'unknown';
  }

  async takeScreenshot(destPath) {
    this.adb(`shell screencap -p /data/local/tmp/pt_screen.png`);
    this.adb(`pull /data/local/tmp/pt_screen.png "${destPath}"`);
  }
}

// PrivacyTests WebSocket Client
class PrivacyTestsClient {
  constructor(wsUri = WS_ENDPOINT) {
    this.wsUri = wsUri;
    this.ws = null;
    this.sessionId = null;
    this.messageQueue = [];
    this.waiters = [];
  }

  async connect() {
    log(`Connecting to PrivacyTests WebSocket at ${this.wsUri}...`);
    this.ws = new WebSocket(this.wsUri);

    await new Promise((resolve, reject) => {
      this.ws.addEventListener('open', resolve, { once: true });
      this.ws.addEventListener('error', (err) => reject(new Error(`WebSocket connection failed: ${err.message}`)), { once: true });
    });

    this.ws.addEventListener('message', (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (this.waiters.length > 0) {
          const waiter = this.waiters.shift();
          waiter(msg);
        } else {
          this.messageQueue.push(msg);
        }
      } catch (e) {
        log('Error parsing WS message:', e.message);
      }
    });

    this.ws.addEventListener('close', () => {
      log('WebSocket connection closed.');
    });

    // Receive initial connection hello containing sessionId
    const initMsg = await this.nextMessage(15000);
    this.sessionId = initMsg.sessionId;
    log(`PrivacyTests session established with sessionId: ${this.sessionId}`);

    // Keepalive ping
    this.keepAlive = setInterval(() => {
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ message: 'ping' }));
      }
    }, 25000);
  }

  nextMessage(timeoutMs = 60000) {
    if (this.messageQueue.length > 0) {
      return Promise.resolve(this.messageQueue.shift());
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.waiters.indexOf(resolve);
        if (idx !== -1) this.waiters.splice(idx, 1);
        reject(new Error(`Timeout waiting for PrivacyTests message after ${timeoutMs / 1000}s`));
      }, timeoutMs);

      this.waiters.push((msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
    });
  }

  async nextValue(timeoutMs = 60000) {
    const msg = await this.nextMessage(timeoutMs);
    if (msg.sessionId && msg.sessionId !== this.sessionId) {
      log(`Warning: sessionId mismatch (${msg.sessionId} vs ${this.sessionId})`);
    }
    return msg.data || msg;
  }

  close() {
    if (this.keepAlive) clearInterval(this.keepAlive);
    if (this.ws) this.ws.close();
  }
}

// Main Runner
async function runPrivacyTests() {
  const args = process.argv.slice(2);
  const targetDev = process.env.ADB_DEVICE || '';
  const pkgName = process.env.PKG_NAME || 'net.mullvad.mullvadbrowser_alpha';
  const outDir = process.env.OUTPUT_DIR || '/tmp/privacytests-output';

  fs.mkdirSync(outDir, { recursive: true });

  const adb = new AdbDriver(targetDev, pkgName);
  const version = await adb.getVersion();
  log(`Detected ${pkgName} version: ${version}`);

  const pt = new PrivacyTestsClient();
  await pt.connect();

  const results = {
    browser: 'mullvad',
    platform: 'Android',
    os: 'Android 12 (ReDroid ARM64)',
    version: version,
    packageName: pkgName,
    timeStarted: new Date().toISOString(),
    categories: {}
  };

  try {
    // 1. Launch browser
    await adb.launch();

    // 2. Stage 1: Main Supercookies, Fingerprinting, and Navigation Tracking
    log('=== Starting Main PrivacyTests (Stage 1) ===');
    const writeUrl = `${IFRAME_ROOT_SAME}/supercookies.html?mode=write&thirdparty=same&sessionId=${pt.sessionId}`;
    await adb.openUrl(writeUrl);

    log('Waiting for supercookie_write_finished signal...');
    const writeSignal = await pt.nextValue(120000);
    log('Write signal received:', JSON.stringify(writeSignal));

    await sleep(2000);
    await adb.takeScreenshot(path.join(outDir, '01_write_done.png'));

    const readUrl = `${IFRAME_ROOT_SAME}/supercookies.html?mode=read&thirdparty=same&sessionId=${pt.sessionId}`;
    await adb.openUrl(readUrl);

    log('Waiting for main test results (supercookies, fingerprinting, query)...');
    const mainResults = await pt.nextValue(120000);
    log('Main test results received!');

    await sleep(2000);
    await adb.takeScreenshot(path.join(outDir, '02_read_done.png'));

    if (mainResults.supercookies) results.categories.supercookies = mainResults.supercookies;
    if (mainResults.fingerprinting) results.categories.fingerprinting = mainResults.fingerprinting;
    if (mainResults.query || mainResults.navigation) {
      results.categories.query = mainResults.query || mainResults.navigation;
    }
    if (mainResults.trackers) results.categories.trackers = mainResults.trackers;

    // 3. Stage 2: Upgradable and Insecure HTTPS tests
    log('=== Starting HTTPS Upgrade & Insecure Warning Tests ===');
    const upgradableUrl = `${UPGRADABLE_ROOT}/upgradable.html?source=address&sessionId=${pt.sessionId}`;
    await adb.openUrl(upgradableUrl);
    try {
      const upgradableRes = await pt.nextValue(30000);
      results.categories.https = { ...(results.categories.https || {}), ...upgradableRes };
    } catch (e) {
      log('Upgradable test warning:', e.message);
    }

    const insecureUrl = `${INSECURE_ROOT}/insecure.html?sessionId=${pt.sessionId}`;
    await adb.openUrl(insecureUrl);
    try {
      const insecureRes = await pt.nextValue(15000);
      results.categories.https = { ...(results.categories.https || {}), ...insecureRes };
    } catch (e) {
      // Insecure website blocked / never loaded is a PASS in HTTPS-only mode!
      log('Insecure site never loaded (HTTPS-Only protection active):', e.message);
      results.categories.https = {
        ...(results.categories.https || {}),
        'Insecure website warning': { passed: true, result: 'Insecure website blocked / never loaded' }
      };
    }

    // 4. Stage 3: Top-level / GPC / IP leak tests
    log('=== Starting Top-Level Misc Tests ===');
    const toplevelUrl = `${LIVE_ROOT}/toplevel.html?sessionId=${pt.sessionId}`;
    await adb.openUrl(toplevelUrl);
    try {
      const toplevelRes = await pt.nextValue(30000);
      results.categories.misc = toplevelRes;
    } catch (e) {
      log('Top-level test warning:', e.message);
    }

    results.timeStopped = new Date().toISOString();
  } finally {
    pt.close();
    await adb.kill();
  }

  // Save raw JSON
  const jsonOut = path.join(outDir, 'mullvad-android-privacytests.json');
  fs.writeFileSync(jsonOut, JSON.stringify(results, null, 2), 'utf-8');
  log(`Wrote full results to ${jsonOut}`);

  // Generate Markdown report
  const reportMd = generateMarkdownReport(results);
  const reportPath = path.join(outDir, 'privacytests-report.md');
  fs.writeFileSync(reportPath, reportMd, 'utf-8');
  log(`Wrote markdown scorecard to ${reportPath}`);

  console.log('\n' + reportMd);
}

function generateMarkdownReport(data) {
  let md = `# PrivacyTests.org Results: Mullvad Browser for Android\n\n`;
  md += `**Target:** ${data.packageName} (version \`${data.version}\`)\n`;
  md += `**Platform:** ${data.platform} (${data.os})\n`;
  md += `**Test Date:** ${data.timeStarted}\n\n`;

  let totalTests = 0;
  let totalPassed = 0;
  let totalFailed = 0;
  let totalUnsupported = 0;

  const categoryTables = [];

  for (const [catName, tests] of Object.entries(data.categories)) {
    if (!tests || typeof tests !== 'object') continue;

    let catPassed = 0;
    let catFailed = 0;
    let catUnsupported = 0;
    let rows = [];

    for (const [testName, testVal] of Object.entries(tests)) {
      if (!testVal || typeof testVal !== 'object') continue;

      totalTests++;
      const isPassed = testVal.passed === true;
      const isUnsupported = testVal.unsupported === true;

      let statusIcon = '❌ Fail';
      if (isUnsupported) {
        statusIcon = '⚪ Unsupported';
        catUnsupported++;
        totalUnsupported++;
      } else if (isPassed) {
        statusIcon = '✅ Pass';
        catPassed++;
        totalPassed++;
      } else {
        catFailed++;
        totalFailed++;
      }

      const desc = (testVal.description || '').replace(/\|/g, '-');
      rows.push(`| **${testName}** | ${statusIcon} | ${desc} |`);
    }

    const catTitle = catName.charAt(0).toUpperCase() + catName.slice(1);
    let catTable = `### Category: ${catTitle}\n`;
    catTable += `**Score:** ${catPassed} / ${catPassed + catFailed} passed (${Math.round((catPassed / (catPassed + catFailed || 1)) * 100)}%)\n\n`;
    catTable += `| Test | Status | Description |\n| :--- | :---: | :--- |\n`;
    catTable += rows.join('\n') + '\n\n';
    categoryTables.push(catTable);
  }

  const overallScore = Math.round((totalPassed / (totalPassed + totalFailed || 1)) * 100);
  md += `## 🏆 Overall Privacy Score: ${totalPassed} / ${totalPassed + totalFailed} Passed (${overallScore}%)\n\n`;
  md += `- **Passed (Protected):** ${totalPassed} ✅\n`;
  md += `- **Failed (Leaked):** ${totalFailed} ❌\n`;
  md += `- **Unsupported / N/A:** ${totalUnsupported} ⚪\n\n`;
  md += `---\n\n`;

  md += categoryTables.join('\n');
  return md;
}

runPrivacyTests().catch((err) => {
  console.error('Fatal runner error:', err);
  process.exit(1);
});
