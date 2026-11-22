import os
from playwright.sync_api import sync_playwright

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")


def run_bot(url: str):
    """Log in as admin, visit `url`, then close. Lets XSS fire."""
    print(f"[bot] visiting {url}", flush=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        try:
            page = browser.new_page()
            # 1. Log in as admin
            page.goto(f"{BASE_URL}/login", timeout=15000)
            page.fill('input[name="username"]', ADMIN_USER)
            page.fill('input[name="password"]', ADMIN_PASS)
            page.click('button[type="submit"]')
            page.wait_for_url(f"{BASE_URL}/", timeout=15000)

            # 2. Visit the reported URL (this is where XSS fires)
            page.goto(url, timeout=15000)
            page.wait_for_timeout(5000)  # give the payload time to exfiltrate
        except Exception as e:
            print(f"[bot] error: {e}", flush=True)
        finally:
            browser.close()
            print("[bot] done", flush=True)