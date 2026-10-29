"""Real-browser verification of demo.html (Playwright chromium)."""
import json
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

URL = "http://127.0.0.1:8933/demo.html"
SHOT = Path(__file__).parent / "screenshots"
SHOT.mkdir(exist_ok=True)
errors, console = [], []

with sync_playwright() as pw:
    b = pw.chromium.launch(args=["--no-proxy-server"])
    page = b.new_page(viewport={"width": 1500, "height": 1150})
    page.on("console", lambda m: console.append(f"{m.type}: {m.text}"))
    page.on("pageerror", lambda e: errors.append(str(e)))

    page.goto(URL, wait_until="load", timeout=30000)
    page.wait_for_timeout(1200)
    tail = page.locator(".sub").inner_text()
    print("[1] loaded:", page.title())
    print("    status line:", tail.splitlines()[-1].strip() if tail else "?")
    page.screenshot(path=str(SHOT / "01_loaded.png"), full_page=True)

    # --- PoW chain ---
    page.click("#btn-pow")
    page.wait_for_function("document.querySelector('#p-state').innerText.includes('求解成功')"
                           " || document.querySelector('#p-state').innerText.includes('失败')"
                           " || document.querySelector('#p-state').innerText.includes('被拒绝')",
                           timeout=120000)
    state = page.locator("#p-state").inner_text()
    nonce = page.locator("#p-nonce").inner_text()
    took = page.locator("#p-time").inner_text()
    print(f"[2] pow state={state.strip()} nonce={nonce} time={took}")
    page.screenshot(path=str(SHOT / "02_pow.png"), full_page=True)

    # --- whitelist probe ---
    page.click("#btn-wl")
    page.wait_for_function("document.querySelector('#p-log').innerText.includes('/api/v0/chat/completion')",
                           timeout=120000)
    page.wait_for_timeout(800)
    log = page.locator("#p-log").inner_text()
    allow = log.count("允许")
    deny = log.count("拒绝")
    print(f"[3] whitelist probe: {allow} allow / {deny} deny")
    page.screenshot(path=str(SHOT / "03_whitelist.png"), full_page=True)

    # --- login reachability (bogus account, proves the endpoint answers) ---
    page.fill("#l-email", "browser-probe@invalid.example")
    page.fill("#l-pass", "not-a-real-password")
    page.click("#btn-login")
    page.wait_for_function("document.querySelector('#l-log').innerText.includes('✗') || document.querySelector('#l-log').innerText.includes('登录成功')", timeout=60000)
    print("[4] login probe:", page.locator("#l-log").inner_text().replace(chr(10),' | ')[:200])
    page.screenshot(path=str(SHOT / "04_login.png"), full_page=True)

    # --- chat with no token: must show the 40002 wall ---
    page.fill("#c-token", "")
    page.click("#btn-chat")
    page.wait_for_function("document.querySelector('#c-log').innerText.includes('✗') || document.querySelector('#c-log').innerText.includes('✓')", timeout=60000)
    print("[5] chat(no token):", page.locator("#c-log").inner_text().replace(chr(10),' | ')[:200])
    page.screenshot(path=str(SHOT / "05_chat_notoken.png"), full_page=True)

    b.close()

print(f"\nconsole messages: {len(console)}")
for c in console[:8]:
    print("   ", c[:120])
print(f"page errors: {len(errors)}")
for e in errors[:5]:
    print("   ", e[:200])
sys.exit(1 if errors else 0)
