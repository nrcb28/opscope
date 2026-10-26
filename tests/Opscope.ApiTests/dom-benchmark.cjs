'use strict';
// Optional synthetic benchmark: no provider calls, real identities, or timing pass/fail threshold.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn, execFileSync } = require('node:child_process');
const root = path.resolve(__dirname, '../..');
const output = path.join(__dirname, 'test-results', 'dom-benchmark.json');
let server, browser;
async function main() {
  server = spawn(process.env.DOTNET_BIN || 'dotnet', ['run', '--no-build', '--project', 'tests/Opscope.ApiTests', '--', '--serve'], { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  const bootstrap = await new Promise((resolve, reject) => {
    let captured = '';
    const timer = setTimeout(() => reject(new Error('Synthetic fixture host did not start.')), 30000);
    server.stdout.on('data', data => { captured += data; const found = captured.match(/http:\/\/127\.0\.0\.1:\d+\/#token=[A-F0-9]+/); if (found) { clearTimeout(timer); resolve(found[0]); } });
    server.once('error', error => { clearTimeout(timer); reject(error); });
    server.once('exit', code => { clearTimeout(timer); reject(new Error('Synthetic fixture host exited: ' + code)); });
  });
  const url = new URL(bootstrap), token = new URLSearchParams(url.hash.slice(1)).get('token');
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || (fs.existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined), headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const fixture = await (await context.request.get(url.origin + '/api/snapshot', { headers: { 'X-Opscope-Token': token } })).json();
  fixture.processes = Array.from({ length: 1000 }, (_, index) => ({ id: 10000 + index, name: 'synthetic-process-' + String(index).padStart(4, '0'), user: '[redacted-user]', workingSetBytes: (index + 1) * 1048576, workingSetMb: index + 1, cpuTime: '00:' + String(index % 60).padStart(2, '0') + ':20', commandLine: 'synthetic fixture', accessLimited: false }));
  fixture.findings = Array.from({ length: 500 }, (_, index) => ({ severity: index % 3, code: 'SYNTHETIC_' + index, title: 'Synthetic finding ' + index, detail: 'Generated test evidence only.', recommendation: 'Review the synthetic observation.' }));
  const page = await context.newPage(), errors = [];
  page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/snapshot*', route => route.fulfill({ json: fixture }));
  await page.route('**/api/events', route => route.fulfill({ contentType: 'text/event-stream', body: ': heartbeat\n\n' }));
  await page.goto(bootstrap);
  await page.getByRole('heading', { name: 'Host evidence', exact: true }).waitFor();
  const samples = await page.evaluate(() => {
    const results = { processes: [], sorting: [], findings: [], maxTableRows: 0, maxFindingCards: 0 };
    function measure(action) {
      const start = performance.now(); action();
      document.getElementById('view').getBoundingClientRect(); // Include synchronous style/layout.
      return performance.now() - start;
    }
    for (let iteration = 0; iteration < 23; iteration++) {
      const processDuration = measure(() => document.querySelector('[data-view="processes"]').click());
      const sortDuration = measure(() => { const sort = document.getElementById('process-sort'); sort.value = ['cpuSort', 'nameSort', 'memorySort'][iteration % 3]; sort.dispatchEvent(new Event('change', { bubbles: true })); });
      results.maxTableRows = Math.max(results.maxTableRows, ...[...document.querySelectorAll('#view table tbody')].map(body => body.rows.length));
      const findingDuration = measure(() => document.querySelector('[data-view="findings"]').click());
      results.maxFindingCards = Math.max(results.maxFindingCards, document.querySelectorAll('#view .finding').length);
      if (iteration >= 3) { results.processes.push(processDuration); results.sorting.push(sortDuration); results.findings.push(findingDuration); }
    }
    return results;
  });
  assert.equal(errors.length, 0, 'Synthetic benchmark must not hide runtime errors');
  assert.ok(samples.maxTableRows > 0 && samples.maxTableRows <= 100, 'Process pagination must keep mounted table rows bounded');
  assert.ok(samples.maxFindingCards > 0 && samples.maxFindingCards <= 100, 'Finding pagination must keep mounted finding cards bounded');
  function stats(values) { const sorted = [...values].sort((a, b) => a - b); return { iterations: values.length, medianMs: sorted[Math.floor(sorted.length / 2)], p95Ms: sorted[Math.ceil(sorted.length * .95) - 1], maximumMs: sorted.at(-1) }; }
  const report = {
    schemaVersion: 1, measuredAtUtc: new Date().toISOString(), baselineCommit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    worktreeHasImplementationChanges: true, environment: { platform: process.platform, architecture: process.arch, logicalProcessors: os.cpus().length, node: process.version, chromium: browser.version(), viewport: { width: 1440, height: 1000 } },
    fixture: { processes: 1000, findings: 500, source: 'synthetic interception', providerRequests: 0 },
    method: 'Three warmups, then twenty synchronous DOM and layout timings per operation. No universal timing threshold; compare on the same environment.',
    processNavigation: stats(samples.processes), processSorting: stats(samples.sorting), findingNavigation: stats(samples.findings), maxMountedTableRows: samples.maxTableRows, maxMountedFindingCards: samples.maxFindingCards
  };
  fs.mkdirSync(path.dirname(output), { recursive: true }); fs.writeFileSync(output, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
}
main().catch(error => { console.error(String(error).replace(/#token=\S+/g, '#token=[redacted]')); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  if (server && server.exitCode === null) { server.kill('SIGINT'); await Promise.race([new Promise(resolve => server.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 3000))]); if (server.exitCode === null) server.kill('SIGTERM'); }
});
