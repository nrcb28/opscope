/* Run after: dotnet build tests/Opscope.ApiTests; npm ci --prefix tests/Opscope.ApiTests.
   Uses fixture evidence only inside the test host. No token or evidence is printed. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const results = path.join(__dirname, 'test-results');
let server, browser, activePage, assertions = 0;
function check(value, message) { assert.ok(value, message); assertions++; console.log('PASS ' + message); }
async function startServer() {
  server = spawn(process.env.DOTNET_BIN || 'dotnet', ['run', '--no-build', '--project', 'tests/Opscope.ApiTests', '--', '--serve'], { cwd: root, env: process.env, stdio: ['ignore', 'pipe', 'pipe'] });
  return new Promise((resolve, reject) => {
    let output = '', errors = '';
    const timer = setTimeout(() => reject(new Error('Local fixture host did not become ready.')), 30000);
    server.stdout.on('data', data => { output += data.toString(); const match = output.match(/http:\/\/127\.0\.0\.1:\d+\/#token=[A-F0-9]+/); if (match) { clearTimeout(timer); resolve(match[0]); } });
    server.stderr.on('data', data => { errors += data.toString(); });
    server.once('error', reject);
    server.once('exit', code => { clearTimeout(timer); reject(new Error(`Local fixture host exited (${code}). ${errors.replace(/#token=\S+/g, '#token=[redacted]')}`)); });
  });
}
async function exerciseSavedEvidence(page, context, origin, token) {
  let analysisCalls = 0, collectionCalls = 0;
  const requests = request => {
    if (request.method() === 'POST' && request.url() === origin + '/api/analyze') analysisCalls++;
    if (request.method() === 'POST' && request.url() === origin + '/api/collect') collectionCalls++;
  };
  page.on('request', requests);
  const headers = { 'X-Opscope-Token': token };
  const saved = await (await context.request.get(origin + '/api/snapshot?full=true', { headers })).json();
  saved.host.hostname = 'saved-workbench-private-host'; saved.host.currentUser = 'saved-workbench-private-user';
  saved.collectedAtUtc = '2026-10-25T12:00:00+00:00'; saved.host.bootTimeUtc = '2026-10-25T10:00:00+00:00';
  saved.cpuUsedPercent = 96; saved.memory.usedPercent = 97;
  saved.processes = [{ id: 73, name: 'ioc-saved-worker', user: 'saved-workbench-private-user', workingSetBytes: 2097152, workingSetMb: 2, cpuTime: '00:01:00', commandLine: 'worker --password=saved-workbench-command-secret', accessLimited: false }];
  saved.services = [{ name: 'saved-worker.service', state: 'failed/failed', source: 'saved-fixture' }];
  saved.findings = [{ severity: 1, code: 'SAVED_XSS', title: '<img src=x onerror="window.__savedXss=1">', detail: 'saved-workbench-private-host password=saved-workbench-detail-secret', recommendation: 'Review saved evidence.' }];
  const snapshotFile = value => ({ name: 'saved.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(value)) });
  async function analyze(action, operation) {
    const pending = page.waitForResponse(response => response.url() === origin + '/api/analyze' && response.request().method() === 'POST' && response.request().postDataJSON().operation === operation);
    await action();
    const response = await pending;
    assert.equal(response.status(), 200, 'Saved analysis request completes successfully');
    return response.json();
  }
  async function saveDownload(selector, filename) {
    const pending = page.waitForEvent('download'); await page.locator(selector).click();
    const download = await pending, target = path.join(results, filename);
    fs.mkdirSync(results, { recursive: true }); await download.saveAs(target); return fs.readFileSync(target);
  }
  await page.locator('[data-view="overview"]').click();
  await page.locator('#full').check(); await page.getByText('api-private-host', { exact: true }).waitFor();
  await page.locator('[data-view="analysis"]').click();
  check(await page.locator('#source-context').textContent().then(text => text.includes('Saved snapshot') && text.includes('Always redacted')) && await page.locator('#full').isDisabled() && await page.locator('.full-toggle').isHidden(), 'Saved workspace states its separate always-redacted source and hides the live identifier preference');
  check(await page.locator('#collect').isHidden() && await page.locator('.search-wrap').isHidden(), 'Live collection and live search controls are hidden while inspecting saved evidence');
  await page.locator('#analysis-upload').setInputFiles({ name: 'too-large.json', mimeType: 'application/json', buffer: Buffer.alloc(2 * 1024 * 1024 + 1, ' ') });
  await page.locator('#analysis-error').waitFor();
  check(analysisCalls === 0 && await page.locator('#analysis-run').count() === 0, 'Oversized saved snapshot is rejected before a request or analysis state is created');
  await page.locator('#analysis-upload').setInputFiles({ name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from('{broken') });
  await page.locator('#analysis-error').waitFor();
  check(analysisCalls === 0, 'Malformed snapshot JSON is rejected locally before analysis submission');
  const inspected = await analyze(() => page.locator('#analysis-upload').setInputFiles(snapshotFile(saved)), 'inspect');
  await page.getByRole('heading', { name: 'Saved snapshot evidence', exact: true }).waitFor();
  check(inspected.cpuUsedPercent === 96 && inspected.host.hostname === '[redacted-host]' && await page.locator('.saved-summary').innerText().then(text => text.includes('96%')), 'Saved inspection presents the uploaded metrics and shared redaction rather than live host values');
  const inspectedText = await page.locator('#analysis-result').textContent();
  check(!inspectedText.includes('saved-workbench-private') && !inspectedText.includes('saved-workbench-command-secret') && !inspectedText.includes('saved-workbench-detail-secret'), 'Saved inspection removes host, user, command-line and finding secrets from rendered evidence');
  check(await page.locator('#analysis-result img').count() === 0 && await page.evaluate(() => window.__savedXss === undefined) && inspectedText.includes('<img'), 'Uploaded finding markup is rendered as text without creating executable image content');
  const inspectedDownload = JSON.parse(await saveDownload('#analysis-download', 'saved-inspect.json'));
  check(inspectedDownload.host.hostname === '[redacted-host]' && inspectedDownload.cpuUsedPercent === 96, 'Inspection download contains the selected saved snapshot and remains redacted');
  await page.locator('#analysis-operation').selectOption('triage');
  await page.locator('#analysis-scenario').selectOption('high-cpu');
  const triage = await analyze(() => page.locator('#analysis-run').click(), 'triage');
  await page.locator('#analysis-result .triage-steps li').first().waitFor();
  check(triage.kind === 'triage' && triage.data.scenario === 'high-cpu' && await page.locator('#analysis-result .triage-steps li').count() === triage.data.steps.length, 'Guided triage renders the shared analyzer steps for the selected saved scenario');
  await page.locator('#analysis-scenario').selectOption('port-exposed');
  check(await page.locator('#analysis-download').isDisabled() && await page.locator('#analysis-result').innerText().then(text => text.includes('Inputs changed')), 'Changing a triage scenario invalidates its old result and download');
  await page.locator('#analysis-operation').selectOption('ioc');
  const beforeLargeIndicator = analysisCalls;
  await page.locator('#analysis-ioc-text').fill('é'.repeat(65537));
  check(await page.locator('#analysis-run').isDisabled() && analysisCalls === beforeLargeIndicator, 'Indicator drafts use the UTF-8 byte limit rather than only a character count');
  await page.locator('#analysis-ioc-upload').setInputFiles({ name: 'too-large.csv', mimeType: 'text/csv', buffer: Buffer.alloc(128 * 1024 + 1, 'x') });
  await page.locator('#analysis-error').waitFor();
  check(analysisCalls === beforeLargeIndicator, 'Oversized indicator files are rejected before reaching the analyzer');
  const csv = 'type,value,label\nprocess,ioc-saved-worker,saved fixture\n';
  await page.locator('#analysis-ioc-text').fill(csv);
  await page.locator('#analysis-ioc-text').focus();
  await page.waitForTimeout(5500); // The fixture emits a live SSE sample every five seconds.
  check(await page.locator('#analysis-ioc-text').evaluate((node, text) => node === document.activeElement && node.value === text, csv) && await page.locator('#source-context').textContent().then(text => text.includes('Saved snapshot')), 'Live SSE updates preserve saved indicator drafts, focus and source context');
  const csvResult = await analyze(() => page.locator('#analysis-run').click(), 'ioc');
  await page.locator('#analysis-result td').filter({ hasText: 'ioc-saved-worker' }).first().waitFor();
  check(csvResult.kind === 'ioc' && csvResult.data.matches.length === 1, 'CSV indicator matching uses the uploaded process evidence without scanning the live host');
  const stix = JSON.stringify({ type: 'bundle', id: 'bundle--e095dd48-f564-4db1-a0d6-cb852d4107a3', objects: [{ type: 'indicator', spec_version: '2.1', id: 'indicator--d4ada3df-19d6-4b8a-ade8-324c29fa2f68', pattern_type: 'stix', pattern: "[process:name = 'ioc-saved-worker']", valid_from: '2026-10-25T00:00:00Z' }] });
  await page.locator('#analysis-ioc-upload').setInputFiles({ name: 'indicators.stix', mimeType: 'application/json', buffer: Buffer.from(stix) });
  await page.waitForFunction(() => document.getElementById('analysis-ioc-text')?.value.includes('bundle--e095dd48'));
  check(await page.locator('#analysis-ioc-format').inputValue() === 'stix', 'STIX file selection restores the actual format and draft text');
  const stixResult = await analyze(() => page.locator('#analysis-run').click(), 'ioc');
  await page.locator('#analysis-result td').filter({ hasText: 'ioc-saved-worker' }).first().waitFor();
  check(stixResult.data.matches.length === 1 && JSON.parse(await saveDownload('#analysis-download', 'saved-ioc.json')).kind === 'ioc', 'STIX matches and result download preserve the saved-analysis contract');
  await page.locator('#analysis-operation').selectOption('timeline');
  const before = structuredClone(saved); before.collectedAtUtc = '2026-10-25T11:00:00+00:00'; before.cpuUsedPercent = 8; before.services[0].state = 'active/running';
  await analyze(() => page.locator('#analysis-baseline-upload').setInputFiles({ name: 'before.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(before)) }), 'inspect');
  await page.waitForFunction(() => !document.getElementById('analysis-run')?.disabled);
  const timeline = await analyze(() => page.locator('#analysis-run').click(), 'timeline');
  await page.locator('#analysis-result td').filter({ hasText: 'drift' }).first().waitFor();
  check(timeline.kind === 'timeline' && timeline.data.events.some(event => event.kind === 'drift') && timeline.data.events.some(event => event.kind === 'boot'), 'Saved timeline merges the chosen snapshot, baseline differences and observed boot evidence');
  await page.locator('#analysis-export-format').selectOption('pdf');
  const pdf = await saveDownload('#analysis-export', 'saved-report.pdf');
  check(pdf.subarray(0, 5).toString() === '%PDF-' && !pdf.includes(Buffer.from('saved-workbench-private-host')), 'Saved PDF export uses the uploaded snapshot with shared redaction');
  const live = await (await context.request.get(origin + '/api/snapshot?full=true', { headers })).json();
  const retained = await (await context.request.get(origin + '/api/history', { headers })).json();
  check(live.host.hostname === 'api-private-host' && live.cpuUsedPercent === 17.5 && retained.every(row => row.cpuUsedPercent === 17.5) && collectionCalls === 0, 'Saved analyses leave the live collector and retained live history unchanged');
  await page.locator('#analysis-operation').selectOption('ioc');
  await page.locator('#analysis-ioc-text').fill(csv);
  await page.locator('[data-view="overview"]').click();
  await page.locator('[data-view="analysis"]').click();
  check(await page.locator('#analysis-ioc-text').inputValue() === csv && await page.locator('.saved-summary').innerText().then(text => text.includes('96%')), 'Navigation preserves saved drafts and selected evidence independently of the live source');
  await page.locator('#language').selectOption('es');
  check(await page.locator('#source-context').textContent().then(text => text.includes('Snapshot guardado')) && await page.locator('#analysis-ioc-text').inputValue() === csv, 'Spanish labels preserve the selected saved source and draft');
  await page.locator('#language').selectOption('en');
  await page.evaluate(fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8'));
  const originalTheme = await page.locator('html').getAttribute('data-theme');
  for (const theme of ['light', 'dark']) {
    if (await page.locator('html').getAttribute('data-theme') !== theme) await page.locator('#theme').click();
    await page.waitForTimeout(220);
    const violations = await page.evaluate(async () => (await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } })).violations);
    fs.writeFileSync(path.join(results, 'saved-accessibility-' + theme + '.json'), JSON.stringify(violations, null, 2));
    check(violations.length === 0, 'Saved workspace passes automated WCAG A/AA checks in the ' + theme + ' theme');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Saved workspace forms fit the mobile viewport without horizontal page overflow');
  await page.screenshot({ path: path.join(results, 'saved-workspace-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  if (await page.locator('html').getAttribute('data-theme') !== originalTheme) await page.locator('#theme').click();
  const stored = await page.evaluate(() => JSON.stringify([localStorage, sessionStorage]));
  check(!stored.includes('saved-workbench-private') && !stored.includes('ioc-saved-worker') && !stored.includes('saved-workbench-command-secret'), 'Saved snapshots and indicator drafts never enter browser storage');
  await page.getByRole('button', { name: 'Clear saved evidence', exact: true }).click();
  check(await page.locator('.saved-summary').count() === 0 && await page.locator('#analysis-download').count() === 0 && !await page.locator('#view').textContent().then(text => text.includes('ioc-saved-worker')), 'Clear saved evidence removes its snapshot, drafts and downloadable results');
  await page.locator('[data-view="overview"]').click();
  await page.locator('#full').uncheck(); await page.getByText('[redacted-host]', { exact: true }).waitFor();
  check(await page.locator('#source-context').textContent().then(text => text.includes('Live host')) && await page.locator('#collect').isVisible() && await page.locator('#full').isEnabled() && await page.locator('.full-toggle').isVisible(), 'Returning to live evidence restores the live source controls without importing saved state');
  page.off('request', requests);
}

async function main() {
  const bootstrap = await startServer(), origin = new URL(bootstrap).origin, token = new URLSearchParams(new URL(bootstrap).hash.slice(1)).get('token');
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || (fs.existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined), headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage(), errors = [], external = []; activePage = page;
  page.on('pageerror', error => errors.push(error.message));
  page.on('request', request => { if (!request.url().startsWith(origin + '/') && !request.url().startsWith('blob:')) external.push(request.url()); });
  await page.goto(bootstrap);
  await page.getByRole('heading', { name: 'Host evidence', exact: true }).waitFor();
  check(page.url() === origin + '/', 'Bootstrap fragment is consumed before any evidence requests');
  check(!await page.locator('body').innerText().then(text => text.includes('api-private-host')), 'Default evidence view redacts host identifiers');
  check(await page.locator('.safety').innerText().then(text => text.includes('READ ONLY')), 'Read-only banner remains visible');
  await page.keyboard.press('Control+k');
  check(await page.locator('#search').evaluate(node => node === document.activeElement), 'Ctrl+K focuses the global evidence search');
  await page.locator('#search').fill('worker');
  check(await page.locator('#search-results button').count() > 0, 'Global search finds processes, ports, and services from real snapshot records');
  await page.locator('#search-results button').first().click();
  await page.keyboard.press('Escape');
  await page.locator('[data-view="processes"]').click();
  await page.getByRole('heading', { name: 'Listening ports', exact: true }).waitFor();
  check(await page.locator('table').count() === 2, 'Processes and listening ports render as accessible tables');
  await page.locator('[data-view="services"]').click();
  check(await page.locator('td').allTextContents().then(values => values.includes('[redacted-service]')), 'Services show collected service evidence');
  await page.locator('[data-view="findings"]').click();
  await page.locator('#severity-filter').selectOption('critical');
  check(await page.locator('#view').innerText().then(text => text.includes('No findings')), 'Severity filter uses the collected finding severity');
  await page.locator('#severity-filter').selectOption('warning');
  check(await page.getByRole('heading', { name: 'Test evidence', exact: true }).count() === 1, 'Finding evidence and recommendations render after filtering');
  await page.locator('[data-view="overview"]').click();
  await page.locator('#full').check();
  await page.getByText('api-private-host', { exact: true }).waitFor();
  check(await page.locator('#privacy').innerText().then(text => text.includes('Full identifiers visible')), 'Full evidence requires an explicit visible toggle');
  await page.locator('#full').uncheck();
  await page.getByText('[redacted-host]', { exact: true }).waitFor();
  let releaseFullRequest;
  let markContinued;
  const requestContinued = new Promise(resolve => { markContinued = resolve; });
  await page.route('**/api/snapshot?full=true', async route => { await new Promise(resolve => { releaseFullRequest = resolve; }); await route.continue(); markContinued(); });
  await page.locator('#full').check();
  await page.waitForFunction(() => document.getElementById('full').checked);
  for (let count = 0; !releaseFullRequest && count < 50; count++) await new Promise(resolve => setTimeout(resolve, 10));
  check(typeof releaseFullRequest === 'function', 'Full-view response can be delayed for the privacy regression check');
  await page.locator('#full').uncheck();
  releaseFullRequest();
  await requestContinued;
  await page.unroute('**/api/snapshot?full=true');
  await page.waitForTimeout(300);
  check(!await page.locator('body').innerText().then(text => text.includes('api-private-host')), 'A stale full-view response cannot reveal identifiers after redaction is restored');
  await page.locator('#language').selectOption('es');
  check(await page.getByRole('heading', { name: 'Resumen', exact: true }).count() === 1, 'Spanish navigation and evidence labels are available');
  const theme = await page.locator('html').getAttribute('data-theme');
  await page.locator('#theme').click();
  check(await page.locator('html').getAttribute('data-theme') !== theme, 'Light and dark themes switch without network resources');
  await page.locator('#language').selectOption('en');
  await page.locator('[data-view="drift"]').click();
  await page.locator('#baseline-upload').setInputFiles({ name: 'invalid-baseline.json', mimeType: 'application/json', buffer: Buffer.from('{"host":{},"collectedAtUtc":"bad","findings":[]}') });
  await page.getByRole('status').filter({ hasText: 'The uploaded snapshot is invalid' }).waitFor();
  check(await page.locator('.split-evidence').count() === 0, 'Structurally invalid uploaded JSON is rejected by the shared parser before entering UI state');
  const baseline = await (await context.request.get(origin + '/api/snapshot', { headers: { 'X-Opscope-Token': token } })).json();
  baseline.cpuUsedPercent = 90;
  await page.locator('#baseline-upload').setInputFiles({ name: 'baseline.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(baseline)) });
  await page.getByRole('button', { name: 'Compare with current', exact: true }).click();
  await page.getByRole('heading', { name: 'Significant changes detected', exact: true }).waitFor();
  check(await page.locator('.split-evidence section').count() === 2, 'Uploaded baseline and current evidence appear side by side');
  check(await page.locator('#view').innerText().then(text => text.includes('cpuUsedPercent') && text.includes('-72.5')), 'Drift uses the shared diff engine metric values');
  await page.locator('[data-view="fleet"]').click();
  const fleetFirst = structuredClone(baseline), fleetSecond = structuredClone(baseline);
  fleetFirst.host.hostname = 'browser-fleet-private-a'; fleetFirst.cpuUsedPercent = 10;
  fleetSecond.host.hostname = 'browser-fleet-private-b'; fleetSecond.cpuUsedPercent = 95;
  await page.locator('#fleet-upload').setInputFiles([
    { name: 'oversized.json', mimeType: 'application/json', buffer: Buffer.alloc(2 * 1024 * 1024, ' ') },
    { name: 'peer.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(fleetFirst)) }
  ]);
  check(await page.getByRole('button', { name: 'Compare fleet', exact: true }).isDisabled(), 'Fleet upload enforces its total local file-size bound before comparison');
  await page.locator('#fleet-upload').setInputFiles([
    { name: 'first.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(fleetFirst)) },
    { name: 'second.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(fleetSecond)) }
  ]);
  await page.getByText('2 snapshots selected', { exact: true }).waitFor();
  await page.getByRole('button', { name: 'Compare fleet', exact: true }).click();
  await page.getByRole('heading', { name: 'Observed outliers and peer differences', exact: true }).waitFor();
  check(await page.locator('#view').innerText().then(text => text.includes('52.5%') && text.includes('FLEET_CPU_OUTLIER')), 'Fleet multi-upload shows the actual two-host median and CPU outlier finding');
  check(await page.locator('td').allTextContents().then(values => values.includes('[redacted-host-1]') && values.includes('[redacted-host-2]')), 'Fleet comparison keeps distinct anonymous host rows');
  check(!await page.locator('#view').innerText().then(text => text.includes('browser-fleet-private')), 'Fleet view always redacts uploaded host identities');
  check(await page.locator('#view').innerText().then(text => text.includes('never sent to a cloud service or saved in history')), 'Fleet view states its local-only stateless processing');
  await page.locator('[data-view="history"]').click();
  await page.locator('svg[role="img"]').waitFor({ timeout: 15000 });
  check(await page.locator('svg[role="img"]').count() === 1, 'Retained samples produce an accessible trend chart');
  check(await page.locator('#view').innerText().then(text => text.includes('service-observation') && text.includes('observation time')), 'Timeline distinguishes actual failed-service observations from inferred change times');
  await page.getByRole('button', { name: 'View redacted sample', exact: true }).first().click();
  await page.getByRole('heading', { name: 'Retained redacted evidence', exact: true }).waitFor();
  check(!await page.locator('pre').innerText().then(text => text.includes('api-private-host')), 'Historical evidence remains redacted after full-view use');
  await page.locator('[data-view="cloud"]').click();
  check(await page.getByRole('button', { name: /azure-scope-1\/inventory$/ }).count() === 1 && await page.getByRole('button', { name: /aws-scope-20\/health$/ }).count() === 1, 'Configured anonymous Azure and AWS scope aliases render as query actions');
  async function invokeFixtureCloud(action, expectedCount) {
    let response;
    for (let attempt = 0; attempt < 4; attempt++) {
      const received = page.waitForResponse(result => result.url() === origin + '/api/cloud/' + action);
      await page.getByRole('button').filter({ hasText: action }).click();
      response = await received;
      if (response.status() !== 429) break;
      // The fixture's periodic collector shares the production two-second action cooldown.
      await page.waitForTimeout(2100);
    }
    assert.equal(response.status(), 200, 'Scoped fixture cloud query succeeds after the action cooldown');
    assert.equal((await response.json()).data.resourceCount, expectedCount);
    await page.waitForFunction(expected => {
      try { return JSON.parse(document.querySelector('#view pre')?.textContent || '{}').data?.resourceCount === expected; }
      catch { return false; }
    }, expectedCount);
  }
  await invokeFixtureCloud('azure-scope-1/inventory', 3);
  check(JSON.parse(await page.locator('#view pre').innerText()).data.resourceCount === 3, 'Azure scoped action invokes its exact allowlisted fixture callback');
  await invokeFixtureCloud('aws-scope-20/health', 5);
  check(JSON.parse(await page.locator('#view pre').innerText()).data.resourceCount === 5, 'AWS scoped action invokes its exact allowlisted fixture callback');
  let releaseCloudFailure, markCloudStarted;
  const cloudStarted = new Promise(resolve => { markCloudStarted = resolve; });
  await page.route('**/api/cloud/aws-scope-20/health', async route => {
    await new Promise(resolve => { releaseCloudFailure = resolve; markCloudStarted(); });
    await route.fulfill({ status: 502, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/aws/health', collectedAtUtc: new Date().toISOString(), findings: [], data: null, warnings: ['Fixture cloud coverage unavailable.'], operationSucceeded: false }) });
  });
  const cloudFailure = page.waitForResponse(response => response.url() === origin + '/api/cloud/aws-scope-20/health');
  await page.getByRole('button').filter({ hasText: 'aws-scope-20/health' }).click();
  await cloudStarted; await page.locator('#cloud-status').waitFor();
  const loadingCloudSource = await page.locator('#source-context').textContent().then(text => text.includes('aws-scope-20/health')) && await page.locator('#cloud-status').innerText().then(text => text.includes('Running configured cloud query')) && await page.locator('#view button').evaluateAll(buttons => buttons.every(button => button.disabled));
  releaseCloudFailure(); assert.equal((await cloudFailure).status(), 502); await page.locator('#cloud-error').waitFor();
  check(loadingCloudSource, 'Pending cloud query names its selected scope and disables competing query controls');
  check(JSON.parse(await page.locator('#view pre').innerText()).operationSucceeded === false && !await page.locator('#view pre').innerText().then(text => text.includes('resourceCount')), 'An unsuccessful next cloud query replaces the earlier result with its actual failure and coverage report');
  await page.unroute('**/api/cloud/aws-scope-20/health');
  await page.locator('[data-view="policy"]').click();
  check(await page.locator('#policy-editor').count() === 1 && await page.locator('#view').innerText().then(text => text.includes('never applies policy')), 'Policy editor clearly limits its behavior to preview and download');
  await page.locator('#policy-editor').fill('version: 2\n');
  await page.getByRole('button', { name: 'Validate & preview', exact: true }).click();
  await page.locator('#policy-result .notice').waitFor();
  check(await page.locator('#policy-download').isDisabled(), 'Invalid policy YAML shows validation errors and cannot be downloaded as validated');
  const policyDraft = 'version: 1\nthresholds:\n  cpuWarningPercent: 10\n  cpuCriticalPercent: 15\n';
  await page.locator('#policy-editor').fill(policyDraft);
  await page.getByRole('button', { name: 'Validate & preview', exact: true }).click();
  await page.getByRole('heading', { name: 'Policy validated', exact: true }).waitFor();
  check(await page.locator('#policy-result').innerText().then(text => text.includes('POLICY_CPU') && text.includes('CRITICAL')), 'Policy preview evaluates strict YAML thresholds against current collected evidence');
  const policyDownloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download validated YAML', exact: true }).click();
  const policyDownload = await policyDownloadEvent;
  fs.mkdirSync(results, { recursive: true });
  const policyPath = path.join(results, 'opscope.yml');
  await policyDownload.saveAs(policyPath);
  check(fs.readFileSync(policyPath, 'utf8') === policyDraft, 'Validated policy downloads the exact draft without applying host configuration');
  await page.locator('#policy-editor').fill(policyDraft + '# edited\n');
  check(await page.locator('#policy-download').isDisabled() && await page.locator('#policy-result').innerText().then(text => text.includes('Draft changed')), 'Editing a validated policy invalidates stale findings and download state');
  await page.locator('#policy-editor').focus();
  await page.waitForTimeout(5200);
  check(await page.locator('#policy-editor').evaluate(node => node === document.activeElement && node.value.endsWith('# edited\n')), 'Live evidence updates preserve an active policy draft and keyboard focus');
  await exerciseSavedEvidence(page, context, origin, token);
  await page.locator('[data-view="reports"]').click();
  const bundleEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download redacted bundle', exact: true }).click();
  const bundleDownload = await bundleEvent;
  const bundlePath = path.join(results, bundleDownload.suggestedFilename());
  await bundleDownload.saveAs(bundlePath);
  check(fs.readFileSync(bundlePath).subarray(0, 2).toString() === 'PK', 'Bundle button downloads the verified custody ZIP as its primary artifact');
  const checksumEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download bundle checksum', exact: true }).click();
  const checksumDownload = await checksumEvent;
  const checksumPath = path.join(results, checksumDownload.suggestedFilename());
  await checksumDownload.saveAs(checksumPath);
  check(fs.readFileSync(checksumPath, 'utf8').trim() === createHash('sha256').update(fs.readFileSync(bundlePath)).digest('hex'), 'Separate checksum download matches the ZIP without relying on automatic multiple downloads');
  const downloadEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download PDF', exact: true }).click();
  const downloaded = await downloadEvent;
  fs.mkdirSync(results, { recursive: true });
  const pdf = path.join(results, downloaded.suggestedFilename());
  await downloaded.saveAs(pdf);
  check(fs.readFileSync(pdf).subarray(0, 5).toString() === '%PDF-', 'Report export downloads an actual PDF document');
  const jsonEvent = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Download redacted JSON', exact: true }).click();
  const jsonDownload = await jsonEvent, jsonPath = path.join(results, jsonDownload.suggestedFilename());
  await jsonDownload.saveAs(jsonPath);
  check(!fs.readFileSync(jsonPath, 'utf8').includes('api-private-host'), 'Downloaded snapshot always uses shared redaction');
  await page.locator('[data-view="settings"]').click();
  check(await page.locator('#view').innerText().then(text => text.includes('127.0.0.1') && text.includes('telemetry')), 'Settings expose the actual read-only listener and telemetry configuration');
  const storage = await page.evaluate(() => ({ local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage) }));
  check(!storage.local.includes(token) && !storage.session.includes(token) && !storage.local.includes('api-private-host'), 'Browser storage contains no token or snapshot evidence');
  await page.locator('[data-view="overview"]').click();
  await page.screenshot({ path: path.join(results, 'overview-desktop.png'), fullPage: true });
  await page.evaluate(fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8'));
  const accessibility = await page.evaluate(async () => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } }));
  fs.writeFileSync(path.join(results, 'accessibility.json'), JSON.stringify(accessibility.violations, null, 2));
  check(accessibility.violations.length === 0, 'Overview passes automated WCAG A/AA accessibility checks');
  await page.locator('#theme').click();
  await page.waitForTimeout(200); // Let the existing button background transition finish before contrast sampling.
  const darkAccessibility = await page.evaluate(async () => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } }));
  fs.writeFileSync(path.join(results, 'accessibility-dark.json'), JSON.stringify(darkAccessibility.violations, null, 2));
  check(darkAccessibility.violations.length === 0, 'Dark theme also passes automated WCAG A/AA accessibility checks');
  await page.screenshot({ path: path.join(results, 'overview-dark.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Mobile overview fits the viewport without horizontal page scrolling');
  await page.screenshot({ path: path.join(results, 'overview-mobile.png'), fullPage: true });
  check(errors.length === 0, 'Browser reports no JavaScript runtime errors');
  check(external.length === 0, 'All UI resources and evidence requests remain on the authenticated local origin');
  console.log(`PASS: ${assertions} browser and accessibility assertions.`);
}
main().catch(async error => { if (activePage) { try { fs.mkdirSync(results, { recursive: true }); await activePage.screenshot({ path: path.join(results, 'last-failure.png'), fullPage: true }); } catch {} } console.error(String(error).replace(/#token=\S+/g, '#token=[redacted]')); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  if (server && server.exitCode === null) { server.kill('SIGINT'); await Promise.race([new Promise(resolve => server.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 5000))]); if (server.exitCode === null) server.kill('SIGTERM'); }
});
