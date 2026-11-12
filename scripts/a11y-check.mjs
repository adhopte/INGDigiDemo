// End-to-end walk-through of all four flows in MOCK_MODE (simulated wallet) with an axe-core WCAG 2.x A/AA scan of every page.
// Usage: start the app (MOCK_MODE=true npm run dev), then: BASE_URL=http://localhost:3000 npm run a11y
// Needs Playwright (preinstalled in the cloud sandbox; locally: npm i -D playwright && npx playwright install chromium).
import { createRequire } from 'node:module';
import { readFileSync, mkdirSync } from 'node:fs';
const require = createRequire(import.meta.url);
const { chromium } = require('playwright');
const axeSource = readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8');

const BASE = process.env.BASE_URL ?? 'http://localhost:3000';
const SHOTS = process.env.SHOTS_DIR;
if (SHOTS) mkdirSync(SHOTS, { recursive: true });
const viewports = process.env.MOBILE_ONLY ? { mobile: { width: 390, height: 844 } } : { desktop: { width: 1280, height: 900 }, mobile: { width: 390, height: 844 } };

let failures = 0;
const log = (...a) => console.log(...a);

async function axe(page, label) {
  await page.evaluate(axeSource);
  const res = await page.evaluate(() => window.axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] } }));
  if (res.violations.length) {
    failures += res.violations.length;
    for (const v of res.violations) log(`  ✗ [${label}] ${v.id} (${v.impact}) ×${v.nodes.length}: ${v.help}\n      ${v.nodes.slice(0, 2).map((n) => n.target.join(' ')).join(' | ')}`);
  } else log(`  ✓ ${label}`);
  // no horizontal scroll (reflow, WCAG 1.4.10)
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  if (overflow > 1) { failures++; log(`  ✗ [${label}] horizontal overflow ${overflow}px`); }
}
const shot = async (page, vp, name) => { if (SHOTS) await page.screenshot({ path: `${SHOTS}/${vp}-${name}.png`, fullPage: true }); };

async function run(vpName, size) {
  log(`\n=== ${vpName} ${size.width}x${size.height} ===`);
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: size, bypassCSP: true, locale: 'en', deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  const go = async (path) => { await page.goto(BASE + path); };
  const step = async (name) => { await axe(page, `${vpName}:${name}`); await shot(page, vpName, name); };

  await go('/'); await step('dashboard');
  await go('/demo-issuer'); await step('issuer-console');

  // ---- Bank
  await go('/bank/'); await step('bank-home');
  await page.getByRole('link', { name: /Open an account/ }).first().click();
  await page.waitForURL(/\/bank\/verify\/[0-9a-f-]+$/); await step('bank-verify');
  await page.getByRole('link', { name: 'Open the simulated wallet' }).click(); await step('bank-wallet-empty');
  await page.getByRole('button', { name: 'Add demo PID' }).click();
  await page.getByRole('button', { name: 'Approve and share' }).click();
  await page.waitForURL(/\/bank\/kyc$/); await step('bank-kyc');
  await page.getByRole('link', { name: 'Continue to my account' }).click(); await step('bank-account');
  await page.getByRole('button', { name: 'Get account attestation' }).click(); await step('bank-offer-account');
  await page.getByRole('button', { name: 'Receive in simulated wallet' }).click();
  await page.waitForURL(/\/bank\/account$/);
  if (!(await page.getByText('stored in the simulated wallet').count())) { failures++; log('  ✗ flash missing after redeem'); }
  await page.getByRole('button', { name: 'Get payment attestation' }).click(); await step('bank-offer-payment');
  await page.getByRole('button', { name: 'Receive in simulated wallet' }).click();

  // ---- eShop (same browser session: wallet now holds the payment attestation issued by the bank)
  await go('/eshop/'); await step('eshop-home');
  await page.getByRole('button', { name: /Add to cart/ }).first().click();
  await page.getByRole('button', { name: /Add to cart/ }).nth(2).click();
  await go('/eshop/cart'); await step('eshop-cart');
  await page.getByRole('link', { name: 'Pay with EU Wallet' }).click();
  await page.waitForURL(/\/eshop\/verify\/[0-9a-f-]+$/); await step('eshop-verify');
  await page.getByRole('link', { name: 'Open the simulated wallet' }).click(); await step('eshop-wallet');
  await page.getByRole('button', { name: 'Approve and share' }).click();
  await page.waitForURL(/\/eshop\/order$/); await step('eshop-order');
  const order = await page.locator('main').innerText();
  if (!/ES-\d{4}-\d+/.test(order) || !/XX00 •••• •••• \d{4}/.test(order)) { failures++; log('  ✗ order confirmation incomplete'); }

  // ---- University (two requests in a row unless MULTI_CREDENTIAL=true)
  await go('/university/'); await step('uni-home');
  await page.getByRole('link', { name: 'Start enrolment' }).first().click();
  await page.waitForURL(/\/university\/(documents|verify\/.+)$/);
  if (/\/documents$/.test(page.url())) {
    await step('uni-documents');
    await page.getByRole('link', { name: 'Present PID', exact: true }).click();
    await page.getByRole('link', { name: 'Open the simulated wallet' }).click();
    await page.getByRole('button', { name: 'Approve and share' }).click();
    await page.waitForURL(/\/university\/documents$/);
    await page.getByRole('link', { name: 'Present birth certificate' }).click();
    await page.getByRole('link', { name: 'Open the simulated wallet' }).click(); await step('uni-wallet-bc');
    await page.getByRole('button', { name: 'Add demo birth certificate' }).click();
    await page.getByRole('button', { name: 'Approve and share' }).click();
    await page.waitForURL(/\/university\/documents$/);
  } else {
    await page.getByRole('link', { name: 'Open the simulated wallet' }).click();
    await page.getByRole('button', { name: 'Add demo birth certificate' }).click();
    await page.getByRole('button', { name: 'Approve and share' }).click();
    await page.waitForURL(/\/university\/documents$/);
  }
  await step('uni-documents-done');
  await page.getByRole('link', { name: 'Continue to enrolment' }).click(); await step('uni-enrol');
  await page.getByRole('button', { name: 'Complete enrolment' }).click(); await step('uni-enrol-errors');
  await page.getByLabel(/Programme/).selectOption('cs');
  await page.getByLabel(/E-mail address/).fill('student@example.org');
  await page.getByLabel(/I confirm/).check();
  await page.getByRole('button', { name: 'Complete enrolment' }).click();
  await page.waitForURL(/\/university\/confirmation$/); await step('uni-confirmation');

  // ---- Electricity
  await go('/electricity/'); await step('el-home');
  await page.getByRole('link', { name: /Sign in with EU Wallet/ }).first().click();
  await page.getByRole('link', { name: 'Open the simulated wallet' }).click();
  await page.getByRole('button', { name: 'Approve and share' }).click();
  await page.waitForURL(/\/electricity\/account$/); await step('el-account');

  await go('/wallet'); await step('wallet');
  await browser.close();
}

// Every language on key pages (phone viewport): axe + no raw translation keys leaking into the UI + <html lang> set.
async function languages() {
  log('\n=== all languages (mobile) ===');
  const browser = await chromium.launch();
  for (const lang of ['en', 'fr', 'es', 'nl', 'de', 'da', 'mt', 'sv']) {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, bypassCSP: true });
    const page = await ctx.newPage();
    for (const path of ['/', '/bank/', '/eshop/', '/eshop/cart', '/university/', '/electricity/', '/demo-issuer']) {
      await page.goto(`${BASE}${path}?lang=${lang}`);
      const htmlLang = await page.getAttribute('html', 'lang');
      const text = await page.locator('body').innerText();
      const leaked = text.match(/\b(?:bank|eshop|uni|el|dash|verify|offer|mockw|claim|att|rp|shop|prog|nav|btn|form|footer|mock|issuer)\.[a-z_0-9]+(?:\.[a-z_0-9]+)*\b/g);
      if (htmlLang !== lang) { failures++; log(`  ✗ [${lang}${path}] html lang=${htmlLang}`); }
      if (leaked) { failures++; log(`  ✗ [${lang}${path}] untranslated keys: ${[...new Set(leaked)].join(', ')}`); }
      await axe(page, `${lang}:${path}`);
    }
    await ctx.close();
  }
  await browser.close();
}

for (const [n, s] of Object.entries(viewports)) await run(n, s);
await languages();
log(failures ? `\n${failures} problem(s)` : '\nAll flows completed, no WCAG A/AA violations found by axe.');
process.exit(failures ? 1 : 0);
