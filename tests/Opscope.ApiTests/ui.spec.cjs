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
let server, browser, assertions = 0;
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
async function main() {
  const bootstrap = await startServer(), origin = new URL(bootstrap).origin, token = new URLSearchParams(new URL(bootstrap).hash.slice(1)).get('token');
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || (fs.existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined), headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage(), errors = [], external = [];
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
main().catch(error => { console.error(String(error).replace(/#token=\S+/g, '#token=[redacted]')); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  if (server && server.exitCode === null) { server.kill('SIGINT'); await Promise.race([new Promise(resolve => server.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 5000))]); if (server.exitCode === null) server.kill('SIGTERM'); }
});
