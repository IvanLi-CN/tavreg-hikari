import { Camoufox } from 'camoufox-js';
import { readFileSync } from 'node:fs';
import { Resvg } from '@resvg/resvg-js';

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

function toResvgPng(svgDataUrl: string): Buffer | null {
  const m = svgDataUrl.match(/^data:image\/svg\+xml;base64,(.+)$/i);
  if (!m || !m[1]) return null;
  const svg = Buffer.from(m[1], 'base64');
  const resvg = new Resvg(svg, {
    fitTo: { mode: 'width', value: 900 },
    background: 'white',
  });
  const rendered = resvg.render();
  return Buffer.from(rendered.asPng());
}

async function ask(imageDataUrl: string, label: string): Promise<void> {
  const payload = {
    model,
    temperature: 0,
    input: [
      {
        role: 'user',
        content: [
          { type: 'input_text', text: 'OCR captcha text exactly. Output only letters/digits.' },
          { type: 'input_image', image_url: imageDataUrl },
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
  console.log(`${label} HTTP=${r.status} raw=${JSON.stringify(out)} clean=${clean} len=${clean.length}`);
}

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

  const svgSrc = await page.$eval('img[alt="captcha"]', (el: any) => String(el.src || ''));
  const shot = Buffer.from(await page.locator('img[alt="captcha"]').first().screenshot({ type: 'png' }));
  const shotData = `data:image/png;base64,${shot.toString('base64')}`;

  await ask(shotData, 'png_screenshot');

  const resvgPng = toResvgPng(svgSrc);
  if (resvgPng) {
    const resvgData = `data:image/png;base64,${resvgPng.toString('base64')}`;
    await ask(resvgData, 'png_resvg_900w');
  } else {
    console.log('png_resvg_900w not available');
  }
} finally {
  await browser.close();
}
