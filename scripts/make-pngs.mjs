// Renders the SVG logos to PNG (wallets show logo_uri; many do not render SVG). Needs Playwright.  node scripts/make-pngs.mjs
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
const { chromium } = createRequire(import.meta.url)('playwright');
const dir = new URL('../public/img/', import.meta.url).pathname;
const jobs = [['rp-bank', 256, 256], ['rp-eshop', 256, 256], ['rp-university', 256, 256], ['rp-electricity', 256, 256], ['in-groupe-logo', 640, 308]];
const b = await chromium.launch();
for (const [name, w, h] of jobs) {
  const p = await b.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
  await p.setContent(`<body style="margin:0;background:transparent"><img style="width:${w}px;height:${h}px" src="data:image/svg+xml;base64,${readFileSync(`${dir}${name}.svg`).toString('base64')}"></body>`);
  await p.screenshot({ path: `${dir}${name}.png`, omitBackground: true });
  await p.close();
}
await b.close();
console.log('ok');
