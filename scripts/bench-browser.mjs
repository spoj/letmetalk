// Runs a bench page in headless Chrome. `serve` keeps the page serving until it is killed. `dial` waits until the page
// reports done or failed, then writes its JSON lines to a file.
// Usage: node scripts/bench-browser.mjs serve <url>
//        node scripts/bench-browser.mjs dial <url> <file>
import { writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT ?? '/home/spoj/.local/lib/node_modules/@playwright/cli/node_modules/playwright');
const [role, url, file] = process.argv.slice(2);
const finished = () => /^(done|failed)/.test(document.getElementById('status').textContent);

const browser = await chromium.launch({ headless: true, executablePath: process.env.CHROME ?? '/opt/google/chrome/chrome' });
const page = await browser.newPage();
page.on('pageerror', (e) => console.error(`page error: ${e.message}`));
await page.goto(url);
if (role === 'serve') {
  process.on('SIGTERM', async () => {
    await browser.close();
    process.exit(0);
  });
  await page.waitForFunction(() => document.getElementById('out').textContent.includes('"role":"serve"'), null, { timeout: 120_000 });
  console.log('ready');
  await new Promise(() => {});
} else {
  await page.waitForFunction(finished, null, { timeout: 900_000 });
  const status = await page.textContent('#status');
  writeFileSync(file, await page.textContent('#out'));
  await browser.close();
  if (status !== 'done') {
    console.error(status);
    process.exitCode = 1;
  }
}
