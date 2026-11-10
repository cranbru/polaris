/* Isolated presentation regression harness. Native responses here are test
 * doubles only. Production always requires the pywebview API. Screenshots of
 * progress replay recorded events from the restricted live smoke check.
 * Usage: node tests/desktop_ui_check.cjs <playwright-module-path> <qa-folder>
 */
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require(process.argv[2]);
const qa = process.argv[3];
const bootstrap = JSON.parse(fs.readFileSync(path.join(qa, 'bootstrap.json'), 'utf8'));
const live = JSON.parse(fs.readFileSync(path.join(qa, 'live-run.json'), 'utf8'));

(async () => {
  const browser = await chromium.launch({ channel: 'msedge', headless: true });
  const page = await browser.newPage({viewport:{width:1440,height:920}});
  const errors = [];
  page.on('pageerror', error => errors.push(error.message));
  async function screenshot(name) {
    await page.locator('#toast').evaluate(el => { el.hidden = true; });
    await page.screenshot({path:path.join(qa,name),animations:'disabled'});
  }
  await page.addInitScript(data => {
    window.__qaCalls = [];
    window.pywebview = { api: {
      bootstrap: async () => structuredClone(data),
      save_configuration: async (...args) => { window.__qaCalls.push(['save',...args]); return {ok:true,credential:{configured:false,persistent:false}}; },
      start_acquisition: async (...args) => { window.__qaCalls.push(['start',...args]); return {ok:true}; },
      test_connection: async () => ({ok:false,error:'Enter a model identifier and API key first.'}),
      request_close: async () => true,
      cancel_acquisition: async () => ({ok:true,message:'Cancellation requested'}),
    }};
  }, bootstrap);
  await page.goto('file://' + path.join(process.cwd(), 'desktop/resources/index.html').replaceAll('\\','/'));
  await page.locator('#setup-view').waitFor({state:'visible'});
  assert.equal(await page.locator('#quick-card').getAttribute('aria-checked'), 'true');
  assert.equal(Number(await page.locator('#quick-count').innerText()), bootstrap.presets.quick.length);
  await page.waitForFunction(() => document.querySelector('#background-video').classList.contains('playing'));
  await page.locator('#background-video').evaluate(video => {
    let previous = video.currentTime;
    window.__qaVideoLoops = 0;
    video.addEventListener('timeupdate', () => {
      if (previous > video.currentTime + 1) window.__qaVideoLoops++;
      previous = video.currentTime;
    });
    video.currentTime = video.duration - .5;
  });
  await page.waitForFunction(() => window.__qaVideoLoops > 0);
  assert.ok(await page.locator('#background-video').evaluate(video => video.loop && video.muted && !video.paused));
  await screenshot('setup.png');
  await page.locator('#full-card').click();
  assert.equal(Number(await page.locator('#full-count').innerText()), bootstrap.collectors.length - 1);
  await page.locator('#more-options').click();
  assert.equal(await page.locator('[data-module="sensitive_files"] input').isChecked(), false);
  await page.locator('#disable-optional').click();
  assert.equal(await page.locator('#collector-list input:checked').count(), 1);
  await page.locator('#collector-list [data-module="system_info"] input').click();
  assert.equal(await page.locator('#collector-list input:checked').count(), 1);
  await page.locator('#ai-tab').click();
  await page.locator('#ai-provider').selectOption('openai');
  await page.locator('#ai-model').fill('entered-model');
  await page.locator('#api-key').fill('test-only-draft');
  await page.locator('#ai-provider').selectOption('gemini');
  await page.locator('#ai-provider').selectOption('openai');
  assert.equal(await page.locator('#ai-model').inputValue(), 'entered-model');
  assert.equal(await page.locator('#api-key').inputValue(), 'test-only-draft');
  assert.equal(await page.locator('#api-key').getAttribute('type'), 'password');
  await page.locator('#api-key').fill('');
  await page.locator('#ai-model').fill('');
  await page.locator('#test-connection').click();
  await page.locator('#connection-status.failed').waitFor();
  await screenshot('ai-settings.png');
  await page.locator('#collectors-tab').click();
  assert.equal(await page.locator('#collector-list input:checked').count(), 1);
  await page.locator('#enable-all').click();
  assert.equal(await page.locator('#collector-list input:checked').count(), bootstrap.collectors.length);
  assert.equal(await page.locator('[data-module="sensitive_files"] input').isChecked(), true);
  await screenshot('collectors.png');
  await page.locator('#disable-optional').click();
  await page.locator('#back-to-setup').click();
  assert.match(await page.locator('#profile-summary').innerText(), /Customized/);
  await page.locator('#review-acquisition').click();
  assert.match(await page.locator('#acquisition-summary').innerText(), /Collectors enabled\s+1/);
  await page.locator('#confirm-start').click();
  assert.equal(await page.locator('#processing-details').isVisible(), false);
  assert.equal(await page.locator('#toggle-processing-details').getAttribute('aria-expanded'), 'false');
  assert.equal(await page.locator('#cancel-acquisition').isVisible(), true);
  assert.deepEqual((await page.evaluate(() => window.__qaCalls.find(c=>c[0]==='start')))[1].modules, ['system_info']);
  const unknown = live.events.find(e=>e.state==='INDETERMINATE' && e.stage==='collecting');
  await page.evaluate(e => window.Polaris.receive({type:'progress',data:e}), unknown);
  await page.waitForFunction(() => document.querySelector('#progress-percentage').textContent === '—');
  assert.match(await page.locator('#progress-track').getAttribute('class'), /indeterminate/);
  const measured = live.events.find(e=>e.percentage>50 && e.percentage<95);
  await page.evaluate(e => window.Polaris.receive({type:'progress',data:e}), measured);
  await page.waitForFunction(() => !document.querySelector('#progress-track').classList.contains('indeterminate'));
  assert.equal(await page.locator('#processing-details').isVisible(), false);
  await screenshot('processing.png');
  for (const viewport of [{width:900,height:680},{width:1920,height:1080},{width:1100,height:720}]) {
    await page.setViewportSize(viewport);
    const bounds = await page.locator('#processing-panel').boundingBox();
    assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= viewport.width + 1);
    assert.ok(bounds.y >= 0 && bounds.y + bounds.height < viewport.height);
    await page.locator('#toggle-processing-details').click();
    assert.equal(await page.locator('#toggle-processing-details').getAttribute('aria-expanded'), 'true');
    const liveBounds = await page.locator('.live-layout').boundingBox();
    const expandedBounds = await page.locator('#processing-panel').boundingBox();
    assert.ok(liveBounds.y + liveBounds.height <= expandedBounds.y, 'Progress must not overlap the case controls');
    await screenshot(`processing-expanded-${viewport.width}.png`);
    await page.locator('#toggle-processing-details').focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.locator('#processing-details').isVisible(), false);
    await page.evaluate(() => maskArtwork());
    const masked = await page.evaluate(() => {
      const video = document.querySelector('#background-video');
      const scale=Math.max(innerWidth/video.videoWidth,innerHeight/video.videoHeight);
      const sampleTop=(innerHeight-video.videoHeight*scale)/2+video.videoHeight*scale*.73;
      return document.querySelector('#artwork-mask').getBoundingClientRect().top <= sampleTop;
    });
    assert.ok(masked, 'Baked-in progress panel must be entirely masked');
    await screenshot(`processing-${viewport.width}.png`);
  }
  await page.setViewportSize({width:1440,height:920});
  await page.evaluate(data => {
    window.Polaris.receive({type:'progress',data:data.events.at(-1)});
    window.Polaris.receive({type:'result',data:data.result});
  }, live);
  await page.locator('#result-panel').waitFor({state:'visible'});
  assert.equal(await page.locator('#toggle-processing-details').getAttribute('aria-expanded'), 'false');
  assert.equal(await page.locator('#processed-modules').isVisible(), true);
  assert.equal(await page.locator('#elapsed-time').isVisible(), true);
  assert.equal(await page.locator('#open-report').isVisible(), true);
  assert.equal(await page.locator('#open-folder').isVisible(), true);
  assert.equal(await page.locator('#operation-details').isVisible(), false);
  assert.equal(await page.locator('#result-details').isVisible(), false);
  assert.equal(await page.locator('#run-details').isVisible(), false);
  assert.equal(await page.locator('#cancel-acquisition').isVisible(), false);
  assert.equal(await page.locator('#progress-percentage').innerText(), '100%');
  await screenshot('completed.png');
  for (const viewport of [{width:900,height:680},{width:1920,height:1080},{width:1100,height:720}]) {
    await page.setViewportSize(viewport);
    const buttons = await page.locator('.result-buttons').boundingBox();
    const panel = await page.locator('#processing-panel').boundingBox();
    assert.ok(buttons.y + buttons.height <= panel.y, 'Output actions must stay visible above progress');
    await screenshot(`completed-${viewport.width}.png`);
  }
  await page.setViewportSize({width:1440,height:920});
  await page.locator('#toggle-processing-details').click();
  assert.equal(await page.locator('#result-description').isVisible(), true);
  assert.equal(await page.locator('#activity-log').isVisible(), true);
  await screenshot('completed-diagnostics.png');
  await page.locator('#toggle-processing-details').click();
  await page.evaluate(data => {
    window.Polaris.receive({type:'progress',data:{...data.events.at(-1),state:'FAILED',workflow_completed:true}});
    window.Polaris.receive({type:'result',data:{...data.result,state:'FAILED',workflow_completed:true,completion_reason:'collection_gaps',warnings:['One collector was partial']}});
  }, live);
  assert.equal(await page.locator('#progress-percentage').innerText(), '100%');
  assert.equal(await page.locator('#progress-track').getAttribute('aria-valuenow'), '100');
  assert.equal(await page.locator('#result-description').isVisible(), false);
  assert.equal(await page.locator('#open-report').isVisible(), true);
  await screenshot('collection-gaps.png');
  for (const state of ['FAILED','CANCELLED']) {
    await page.evaluate(({event,result,state}) => {
      window.Polaris.receive({type:'progress',data:{...event,state,workflow_completed:false,percentage:63,error:'QA interruption fixture'}});
      window.Polaris.receive({type:'result',data:{...result,state,workflow_completed:false,error:'QA interruption fixture'}});
    },{event:live.events.at(-1),result:live.result,state});
    assert.equal(await page.locator('#progress-percentage').innerText(), '63%');
    assert.equal(await page.locator('#result-title').innerText(), state === 'CANCELLED' ? 'Acquisition cancelled' : 'Acquisition stopped');
    assert.equal(await page.locator('#result-panel').isVisible(), true);
    assert.equal(await page.locator('#result-details').isVisible(), false);
    await screenshot(state.toLowerCase()+'.png');
  }
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.waitForFunction(() => document.querySelector('#background-video').paused);
  assert.ok(!await page.locator('#background-video').evaluate(el => el.classList.contains('playing')));
  await page.locator('#new-investigation').click();
  await page.locator('#review-acquisition').click();
  await page.locator('#confirm-start').click();
  assert.equal(await page.locator('#processing-details').isVisible(), false, 'Every new acquisition starts collapsed');
  await page.evaluate(data => window.Polaris.receive({type:'result',data:data.result}), live);
  await page.locator('#new-investigation').click();
  await screenshot('reduced-motion.png');
  await page.emulateMedia({reducedMotion:'no-preference'});
  await page.locator('#background-video').evaluate(video => {video.src='missing-video.mp4';video.load();});
  await page.waitForFunction(() => !document.querySelector('#background-video').classList.contains('playing'));
  assert.ok(await page.locator('#background-image').evaluate(img=>img.complete && img.naturalWidth>0));
  await screenshot('static-fallback.png');
  assert.deepEqual(errors, []);
  console.log('Desktop UI checks passed: profiles, collector toggles, drafts, summary, progress, results, resizing, reduced motion and video fallback.');
  await browser.close();
})().catch(error => { console.error(error); process.exit(1); });
