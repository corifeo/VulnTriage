#!/usr/bin/env node
// Regenerates docs/screenshots/ from the built-in sample data and the demo export.
//
//   npm i -g playwright && npx playwright install chromium   (once)
//   node scripts/screenshots.cjs
//
// Serves the repository on a free local port, drives the real page with
// Playwright and writes PNGs (plus demo.gif when ffmpeg is on PATH).

const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { chromium } = require('playwright');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, 'docs', 'screenshots');
const TYPES = { '.html': 'text/html', '.js': 'text/javascript', '.json': 'application/json', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png' };

function serve() {
  const server = http.createServer((req, res) => {
    const rel = decodeURIComponent(new URL(req.url, 'http://x').pathname).replace(/^\/+/, '') || 'index.html';
    const file = path.join(ROOT, rel);
    if (!file.startsWith(ROOT) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)));
}

// Click an option card by its title. `nth` picks among cards with the same title
// (Mission & well-being has "Minimal" twice).
async function pick(page, title, nth = 0) {
  const cards = page.locator('main button').filter({ has: page.locator(`span:text-is("${title}")`) });
  await cards.nth(nth).click();
}

async function triage(page, answers, rationale) {
  const [e, a, t, mission, wellbeing] = answers;
  await pick(page, e);
  await pick(page, a);
  await pick(page, t);
  await pick(page, mission, 0);
  await pick(page, wellbeing, wellbeing === 'Minimal' ? 1 : 0);
  if (rationale) await page.locator('textarea').fill(rationale);
  await page.getByRole('button', { name: /^Move to / }).click();
  await page.waitForTimeout(350);
}

// A fresh browser opens on the demo export. `samples: true` blocks that first load,
// so the page starts on the built-in samples (as it does when opened from disk).
async function fresh(browser, opts = {}, { samples = false } = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 2, ...opts });
  const page = await ctx.newPage();
  // Fonts come from the system when present; don't wait on Google Fonts.
  await page.route(/fonts\.(googleapis|gstatic)\.com/, r => r.abort());
  // Each context starts with empty storage, so this is a first visit.
  let served = !samples;
  await page.route(/triage-queue-demo\.json/, r => { if (served) return r.continue(); served = true; return r.abort(); });
  await page.goto(base);
  await page.waitForTimeout(samples ? 400 : 1200);
  return { ctx, page };
}

let base;

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const server = await serve();
  base = `http://127.0.0.1:${server.address().port}/`;
  const browser = await chromium.launch();
  const shot = (page, name, opts = {}) => page.screenshot({ path: path.join(OUT, name), ...opts });

  // 1. Triage: evidence pre-filled, context answered, outcome resolved.
  {
    const { ctx, page } = await fresh(browser);
    await page.getByRole('button', { name: 'Pre-fill from evidence' }).click();
    await pick(page, 'Essential');
    await pick(page, 'Material');
    await page.locator('textarea').fill('Customer-facing sites on 12 WordPress hosts with core auto-updates off. WAF rule in place; patch tonight.');
    await page.locator('textarea').blur();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(500);
    await shot(page, 'overview.png');
    const decide = page.locator('section').filter({ has: page.locator('h3:text-is("Move to bucket")') });
    await decide.screenshot({ path: path.join(OUT, 'move-to-bucket.png') });
    await ctx.close();
  }

  // 2. Bucket board after a short session.
  {
    const { ctx, page } = await fresh(browser, { viewport: { width: 1720, height: 680 } });
    const plan = [
      [['Active', 'No', 'Total', 'Essential', 'Material'], 'Customer-facing WordPress sites.'],
      [['Active', 'No', 'Partial', 'Essential', 'Material'], 'Remote access for all staff runs through it.'],
      [['Active', 'No', 'Partial', 'Support', 'Minimal'], 'Branch firewalls; MFA already enforced on SSLVPN.'],
      [['Active', 'Yes', 'Total', 'Support', 'Material'], 'Two legacy Java services still on 2.14.'],
      [['None', 'No', 'Total', 'Essential', 'Material'], 'Key manager holds production certificates.'],
      [['None', 'No', 'Partial', 'Minimal', 'Minimal'], 'Only on two lab hosts.'],
      [['None', 'No', 'Total', 'Support', 'Material'], 'Monitoring only; not internet-facing.'],
      [['None', 'No', 'Partial', 'Minimal', 'Minimal'], 'Not deployed.'],
    ];
    for (const [answers, why] of plan) await triage(page, answers, why);
    await page.getByRole('button', { name: 'Buckets' }).click();
    await page.waitForTimeout(400);
    await shot(page, 'buckets.png');
    await ctx.close();
  }

  // 3. Flow builder.
  {
    const { ctx, page } = await fresh(browser);
    await page.getByRole('button', { name: 'Configure', exact: true }).click();
    await page.waitForTimeout(400);
    await shot(page, 'configure-flow.png');
    await shot(page, 'configure-flow-full.png', { fullPage: true });
    await ctx.close();
  }

  // 4. Import the VulnFlow demo export, then triage the real Log4Shell record.
  {
    const { ctx, page } = await fresh(browser, {}, { samples: true });
    await page.getByRole('button', { name: 'Import', exact: true }).click();
    await page.waitForTimeout(250);
    await page.getByRole('button', { name: 'Load demo export' }).click();
    await page.waitForTimeout(500);
    const dialog = page.getByRole('dialog', { name: 'Import vulnerabilities' });
    await dialog.screenshot({ path: path.join(OUT, 'import.png') });
    await dialog.locator('button', { hasText: 'Replace the sample CVEs' }).click();
    await dialog.locator('button').last().click();
    await page.waitForTimeout(400);
    await page.locator('aside button').filter({ hasText: 'CVE-2021-44228' }).first().click();
    await page.waitForTimeout(300);
    await page.getByRole('button', { name: 'Pre-fill from evidence' }).click();
    await page.waitForTimeout(400);
    await shot(page, 'log4shell.png');
    await ctx.close();
  }

  // 5. Phone width.
  {
    const { ctx, page } = await fresh(browser, { viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
    await page.getByRole('button', { name: 'Pre-fill from evidence' }).click();
    await page.waitForTimeout(300);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.waitForTimeout(200);
    await shot(page, 'mobile.png');
    await ctx.close();
  }

  // 6. Animated walkthrough: one CVE from evidence to bucket.
  try {
    execFileSync('ffmpeg', ['-version'], { stdio: 'ignore' });
    const tmp = fs.mkdtempSync(path.join(require('os').tmpdir(), 'vt-gif-'));
    const { ctx, page } = await fresh(browser, { deviceScaleFactor: 1 });
    let n = 0;
    const frame = async (hold = 1) => { for (let i = 0; i < hold; i++) await page.screenshot({ path: path.join(tmp, `f${String(n++).padStart(3, '0')}.png`) }); };
    await frame(4);
    await page.getByRole('button', { name: 'Pre-fill from evidence' }).click();
    await page.waitForTimeout(500); await frame(4);
    await page.mouse.wheel(0, 700); await page.waitForTimeout(500); await frame(3);
    await pick(page, 'Essential'); await page.waitForTimeout(300); await frame(2);
    await pick(page, 'Material'); await page.waitForTimeout(500); await frame(3);
    await page.mouse.wheel(0, 700); await page.waitForTimeout(600); await frame(4);
    await page.locator('textarea').fill('Internet-facing on 14 gateways; fix available.'); await frame(3);
    await page.getByRole('button', { name: /^Move to / }).click();
    await page.waitForTimeout(300);
    await page.mouse.wheel(0, -3000); await page.waitForTimeout(600); await frame(5);
    await ctx.close();
    execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-framerate', '2', '-i', path.join(tmp, 'f%03d.png'),
      '-vf', 'scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96[p];[b][p]paletteuse=dither=bayer:bayer_scale=4',
      path.join(OUT, 'demo.gif')]);
    fs.rmSync(tmp, { recursive: true, force: true });
  } catch (err) {
    console.warn('demo.gif skipped:', err.message.split('\n')[0]);
  }

  await browser.close();
  server.close();
  console.log('Screenshots written to', path.relative(process.cwd(), OUT));
})().catch(err => { console.error(err); process.exit(1); });
