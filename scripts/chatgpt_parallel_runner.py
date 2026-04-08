#!/usr/bin/env python3
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import websocket

BASE_URL = "http://127.0.0.1:4317"
REPO_ROOT = Path("/Users/ivan/.codex/worktrees/2949/tavreg-hikari")
RUN_ROOT = REPO_ROOT / "output" / "web-runs" / f"chatgpt-parallel-{int(time.time())}"
RUN_ROOT.mkdir(parents=True, exist_ok=True)
STARTUP_STAGGER_SECONDS = 10
STARTUP_READY_TIMEOUT_SECONDS = 12
CDP_CONNECT_TIMEOUT_MS = 120000
USE_NATIVE_CDP = False
DEFAULT_PREFERRED_PATTERNS = [
    "🇸🇬新加坡01 | 电信联通推荐",
    "🇦🇪迪拜 | 高速专线-hy2",
    "🇯🇵日本东京01 | 移动联通推荐",
    "🇯🇵日本东京 | 移动联通推荐-hy2",
    "🇺🇸美国圣何塞01 | 三网推荐",
    "🇦🇺澳大利亚 | 高速专线-hy2",
    "🇨🇭瑞士苏黎世 | 高速专线-hy2",
    "🇺🇸",
    "🇯🇵",
]


def load_preferred_patterns():
    raw_json = os.environ.get("CHATGPT_PARALLEL_PATTERNS_JSON", "").strip()
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, list):
                values = [str(item).strip() for item in parsed if str(item).strip()]
                if values:
                    return values
        except Exception:
            pass
    raw = os.environ.get("CHATGPT_PARALLEL_PATTERNS", "").strip()
    if not raw:
        return DEFAULT_PREFERRED_PATTERNS
    for sep in ("\n", ";;", "||"):
        if sep in raw:
            values = [item.strip() for item in raw.split(sep) if item.strip()]
            if values:
                return values
    return [raw]


def api_get(path: str):
    with urllib.request.urlopen(f"{BASE_URL}{path}", timeout=30) as response:
        return json.load(response)


def pick_free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def select_nodes(limit: int):
    payload = api_get("/api/proxies")
    nodes = payload.get("nodes") or []
    preferred_patterns = load_preferred_patterns()
    non_hk = [node for node in nodes if "香港" not in str(node.get("nodeName", ""))]
    picked = []
    seen = set()
    for pattern in preferred_patterns:
      for node in non_hk:
        name = str(node.get("nodeName", ""))
        if pattern not in name or name in seen:
          continue
        picked.append(name)
        seen.add(name)
        break
      if len(picked) >= limit:
        break
    for node in non_hk:
      name = str(node.get("nodeName", ""))
      if name in seen:
        continue
      picked.append(name)
      seen.add(name)
      if len(picked) >= limit:
        break
    return payload["settings"], picked[:limit]


def get_draft():
    payload = api_get("/api/chatgpt/draft")
    return payload["draft"]


def debug_port_for(output_dir: Path):
    command = f"pgrep -af '{output_dir}/chrome-profile' || true"
    out = subprocess.check_output(["zsh", "-lc", command], text=True)
    match = re.search(r"--remote-debugging-port=(\d+)", out)
    return int(match.group(1)) if match else None


def cdp_eval(ws_url: str, expr: str):
    ws = websocket.create_connection(ws_url, timeout=5)
    try:
        for index, (method, params) in enumerate(
            [
                ("Runtime.enable", {}),
                ("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True}),
            ],
            start=1,
        ):
            ws.send(json.dumps({"id": index, "method": method, "params": params}))
            while True:
                message = json.loads(ws.recv())
                if message.get("id") != index:
                    continue
                if index == 2:
                    return message.get("result", {}).get("result", {}).get("value")
                break
    finally:
        ws.close()


def click_consent(ws_url: str):
    return cdp_eval(
        ws_url,
        r"""(() => {
          const norm = (s) => String(s || '').replace(/\s+/g, ' ').trim().toLowerCase();
          const ok = ['continue', 'allow', 'accept', 'authorize'];
          const nodes = [...document.querySelectorAll('button, a, [role="button"], input[type="submit"]')];
          for (const el of nodes) {
            const text = norm(el.innerText || el.textContent || el.value || el.getAttribute('aria-label') || '');
            if (!ok.some((name) => text === name || text.startsWith(name + ' '))) continue;
            el.click();
            return { clicked: true, text, href: location.href };
          }
          const form = document.querySelector('form');
          if (form && typeof form.requestSubmit === 'function') {
            form.requestSubmit();
            return { clicked: true, text: 'form.requestSubmit()', href: location.href };
          }
          return {
            clicked: false,
            href: location.href,
            body: norm(document.body && document.body.innerText).slice(0, 400),
          };
        })()""",
    )


def pages_for(port: int):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5) as response:
        return json.load(response)


def spawn_worker(slot: int, settings: dict, node_name: str):
    draft = get_draft()
    output_dir = RUN_ROOT / f"slot-{slot}"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "draft.json").write_text(json.dumps(draft, ensure_ascii=False, indent=2), encoding="utf-8")
    api_port = pick_free_port()
    mixed_port = pick_free_port()
    env = os.environ.copy()
    env.update(
        {
            "RUN_MODE": "headed",
            "CHROME_NATIVE_AUTOMATION": "true" if USE_NATIVE_CDP else "false",
            "CHROME_ACTIVATE_ON_LAUNCH": "false",
            "CHROME_NATIVE_CDP_CONNECT_TIMEOUT_MS": str(CDP_CONNECT_TIMEOUT_MS),
            "CHATGPT_JOB_EMAIL": draft["email"],
            "CHATGPT_JOB_PASSWORD": draft["password"],
            "CHATGPT_JOB_NICKNAME": draft["nickname"],
            "CHATGPT_JOB_BIRTH_DATE": draft["birthDate"],
            "CHATGPT_JOB_MAILBOX_ID": draft["mailboxId"],
            "CHATGPT_JOB_OUTPUT_DIR": str(output_dir),
            "MIHOMO_SUBSCRIPTION_URL": settings["subscriptionUrl"],
            "MIHOMO_GROUP_NAME": settings["groupName"],
            "MIHOMO_ROUTE_GROUP_NAME": settings["routeGroupName"],
            "MIHOMO_API_PORT": str(api_port),
            "MIHOMO_MIXED_PORT": str(mixed_port),
            "PROXY_CHECK_URL": settings["checkUrl"],
            "PROXY_CHECK_TIMEOUT_MS": str(settings["timeoutMs"]),
            "PROXY_LATENCY_MAX_MS": str(settings["maxLatencyMs"]),
            "OUTPUT_ROOT_DIR": str(output_dir),
            "CHROME_PROFILE_DIR": str(output_dir / "chrome-profile"),
            "INSPECT_CHROME_PROFILE_DIR": str(output_dir / "chrome-inspect-profile"),
            "KEEP_BROWSER_OPEN_ON_FAILURE": "false",
            "KEEP_BROWSER_OPEN_MS": "0",
        }
    )
    log_path = output_dir / "runner.log"
    log_handle = log_path.open("w", encoding="utf-8")
    child = subprocess.Popen(
        ["bun", "run", "src/server/chatgpt-worker.ts", "--proxy-node", node_name],
        cwd=REPO_ROOT,
        env=env,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return {
        "slot": slot,
        "node": node_name,
        "draft": draft,
        "output_dir": output_dir,
        "child": child,
        "log_handle": log_handle,
        "port": None,
        "seen_pages": set(),
        "consent_clicks": 0,
        "done": False,
    }


def wait_for_worker_start(worker, timeout_seconds: int):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
      if worker["child"].poll() is not None:
        return False
      if worker["port"] is None:
        worker["port"] = debug_port_for(worker["output_dir"])
        if worker["port"]:
          print(
              json.dumps(
                  {"event": "debug_port", "slot": worker["slot"], "port": worker["port"], "phase": "startup"},
                  ensure_ascii=False,
              ),
              flush=True,
          )
          return True
      time.sleep(2)
    return False


def summarize_worker(worker):
    result_path = worker["output_dir"] / "result.json"
    error_path = worker["output_dir"] / "error.json"
    if result_path.exists():
        data = json.loads(result_path.read_text())
        creds = data.get("credentials") or {}
        return {
            "slot": worker["slot"],
            "node": worker["node"],
            "status": "success",
            "email": data.get("email"),
            "account_id": creds.get("account_id"),
            "has_refresh_token": bool(creds.get("refresh_token")),
            "output_dir": str(worker["output_dir"]),
        }
    error = json.loads(error_path.read_text()) if error_path.exists() else {"error": f"exit_{worker['child'].poll()}"}
    return {
        "slot": worker["slot"],
        "node": worker["node"],
        "status": "failed",
        "error": error.get("error"),
        "failureStage": error.get("failureStage"),
        "output_dir": str(worker["output_dir"]),
    }


def main():
    settings, nodes = select_nodes(3)
    if len(nodes) < 3:
        raise SystemExit("not enough non-HK proxy nodes to run three parallel workers")
    print(json.dumps({"runRoot": str(RUN_ROOT), "nodes": nodes}, ensure_ascii=False, indent=2), flush=True)
    workers = []
    for index, node_name in enumerate(nodes):
      worker = spawn_worker(index + 1, settings, node_name)
      workers.append(worker)
      print(json.dumps({"event": "spawned", "slot": worker["slot"], "node": node_name}, ensure_ascii=False), flush=True)
      started = wait_for_worker_start(worker, STARTUP_READY_TIMEOUT_SECONDS) if USE_NATIVE_CDP else worker["child"].poll() is None
      print(
          json.dumps(
              {"event": "startup_ready", "slot": worker["slot"], "node": node_name, "started": started},
              ensure_ascii=False,
          ),
          flush=True,
      )
      if index < len(nodes) - 1:
        time.sleep(STARTUP_STAGGER_SECONDS)
    timeout_at = time.time() + 20 * 60
    try:
        while time.time() < timeout_at:
            all_done = True
            for worker in workers:
                if worker["done"]:
                    continue
                if worker["child"].poll() is not None:
                    worker["done"] = True
                    print(json.dumps({"event": "finished", **summarize_worker(worker)}, ensure_ascii=False), flush=True)
                    continue
                all_done = False
                if worker["port"] is None:
                    worker["port"] = debug_port_for(worker["output_dir"])
                    if worker["port"]:
                        print(json.dumps({"event": "debug_port", "slot": worker["slot"], "port": worker["port"]}, ensure_ascii=False), flush=True)
                if not worker["port"]:
                    continue
                try:
                    pages = pages_for(worker["port"])
                except Exception:
                    continue
                if not pages:
                    continue
                page = pages[0]
                title = page.get("title", "")
                url = page.get("url", "")
                signature = (title, url)
                if signature not in worker["seen_pages"]:
                    worker["seen_pages"].add(signature)
                    print(json.dumps({"event": "page", "slot": worker["slot"], "title": title, "url": url}, ensure_ascii=False), flush=True)
                ws = page.get("webSocketDebuggerUrl")
                if ws and ("/consent" in url or "Sign in to Codex with ChatGPT" in title):
                    result = click_consent(ws)
                    worker["consent_clicks"] += 1
                    print(json.dumps({"event": "consent", "slot": worker["slot"], "count": worker["consent_clicks"], "result": result}, ensure_ascii=False), flush=True)
                if ws and ("/auth/callback" in url or "localhost:1455/auth/callback" in url):
                    print(json.dumps({"event": "callback", "slot": worker["slot"], "url": url}, ensure_ascii=False), flush=True)
            if all_done:
                break
            time.sleep(2)
    finally:
        for worker in workers:
            if worker["child"].poll() is None:
                worker["child"].terminate()
        for worker in workers:
            try:
                worker["child"].wait(timeout=10)
            except Exception:
                worker["child"].kill()
            worker["log_handle"].close()
    print(json.dumps({"event": "summary", "results": [summarize_worker(worker) for worker in workers]}, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
