import { Camoufox } from 'camoufox-js';
import { readFileSync } from 'node:fs';

function env(name: string): string {
  const raw = readFileSync('.env.local', 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#') || !t.includes('=')) continue;
    const i = t.indexOf('=');
    if (t.slice(0, i).trim() === name) return t.slice(i + 1).trim();
  }
  return '';
}

const base = env('OPENAI_BASE_URL').replace(/\/+$/, '');
const key = env('OPENAI_KEY');
const model = env('MODEL_NAME');

const browser = await Camoufox({ headless: true, humanize: false });
try {
  const page = await browser.newPage();
  await page.goto('https://app.tavily.com/api/auth/login', { waitUntil: 'domcontentloaded', timeout: 90000 });
  await page.waitForURL(/auth\.tavily\.com/i, { timeout: 90000 });
  if (/\/u\/login\/identifier/i.test(page.url())) {
    const direct = page.locator('a[href*="/u/signup/identifier"]').first();
    if ((await direct.count()) > 0) await direct.click();
  }
  await page.waitForURL(/\/u\/signup\/identifier/i, { timeout: 90000 });
  await page.waitForSelector('img[alt="captcha"]', { timeout: 30000 });

  const src = await page.$eval('img[alt="captcha"]', (el: any) => String(el.src || ''));
  const png = Buffer.from(await page.locator('img[alt="captcha"]').first().screenshot({ type: 'png' }));
  const pngDataUrl = `data:image/png;base64,${png.toString('base64')}`;

  const cases: Array<{ name: string; image_url: string }> = [
    { name: 'svg_src', image_url: src },
    { name: 'png_screenshot', image_url: pngDataUrl },
  ];

  for (const c of cases) {
    const payload = {
      model,
      temperature: 0,
      input: [
        {
          role: 'user',
          content: [
            { type: 'input_text', text: 'Read captcha text exactly. Return only letters/digits.' },
            { type: 'input_image', image_url: c.image_url },
          ],
        },
      ],
    };
    const r = await fetch(`${base}/responses`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const txt = await r.text();
    let out = '';
    try {
      const j = JSON.parse(txt);
      out = String(j?.output?.[0]?.content?.[0]?.text || j?.output_text || '');
    } catch {}
    const clean = out.replace(/[^A-Za-z0-9]/g, '').trim();
    console.log(`${c.name} HTTP=${r.status} raw=${JSON.stringify(out)} clean=${clean} len=${clean.length}`);
    await new Promise((res) => setTimeout(res, 3000));
  }
} finally {
  await browser.close();
}
