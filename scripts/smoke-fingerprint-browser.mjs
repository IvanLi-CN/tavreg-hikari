import { chromium } from "playwright-core";

const executablePath = (process.argv[2] || process.env.CHROME_EXECUTABLE_PATH || "").trim();
if (!executablePath) {
  console.error("Missing executable path. Pass it as argv[2] or CHROME_EXECUTABLE_PATH.");
  process.exit(1);
}

const launchArgs = [];
if (process.platform === "linux" && process.env.FINGERPRINT_BROWSER_SMOKE_NO_SANDBOX !== "false") {
  launchArgs.push("--no-sandbox");
}

const browser = await chromium.launch({
  executablePath,
  headless: true,
  args: launchArgs,
});

try {
  const page = await browser.newPage();
  await page.goto("data:text/html,<title>ok</title><h1>ok</h1>");
  const title = await page.title();
  if (title !== "ok") {
    throw new Error(`Unexpected title: ${title}`);
  }
  console.log(JSON.stringify({ ok: true, executablePath, title }));
} finally {
  await browser.close();
}
