// Drive a real Chromium through the decoy web portal, the way a person would.
// usage: node browse.js '<json steps>' <user agent> [locale]
// steps: ["goto /path", "fill username x", "fill password y", "click submit", "wait 3"]
const { chromium } = require(process.env.PLAYWRIGHT_DIR || '/opt/node22/lib/node_modules/playwright');
(async () => {
  const steps = JSON.parse(process.argv[2]);
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM || '/opt/pw-browsers/chromium' });
  const ctx = await browser.newContext({ userAgent: process.argv[3], locale: process.argv[4] || 'en-US' });
  const page = await ctx.newPage();
  const base = process.env.WEB || 'http://127.0.0.1:8080';
  for (const step of steps) {
    const [op, ...rest] = step.split(' ');
    try {
      if (op === 'goto') await page.goto(base + rest[0], { waitUntil: 'load', timeout: 15000 });
      else if (op === 'fill') await page.fill(`input[name=${rest[0]}]`, rest.slice(1).join(' '));
      else if (op === 'click') await Promise.all([page.waitForLoadState('load'), page.click('button[type=submit], input[type=submit]')]);
      else if (op === 'reload') await page.reload({ waitUntil: 'load' });
      else if (op === 'wait') await page.waitForTimeout(parseFloat(rest[0]) * 1000);
    } catch (e) { console.error('step failed:', step, e.message.split('\n')[0]); }
  }
  await browser.close();
})();
