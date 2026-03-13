#!/usr/bin/env python3
"""
Browser E2E tests for companion.py

Tests the actual browser behavior including JavaScript execution, console errors,
and the full authentication flow (CLI register -> browser credentials -> 200).

Requires playwright: run via 'make test-browser'
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


def _make_env(tmp_home):
    env = os.environ.copy()
    env["HOME"] = tmp_home
    return env


def _run(script, args, *, env, timeout=10):
    return subprocess.run(
        ["python3", script] + args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=timeout,
        env=env,
    )


def _parse_credentials(stdout):
    id_match = re.search(r"Client ID:\s+(\S+)", stdout)
    secret_match = re.search(r"Client Secret:\s+(\S+)", stdout)
    assert id_match, f"Could not find Client ID in output:\n{stdout}"
    assert secret_match, f"Could not find Client Secret in output:\n{stdout}"
    return id_match.group(1), secret_match.group(1)


def test_page_load_and_console(page, url, version_name):
    """Test that page loads without console errors and UI elements work."""
    print(f"\n  🌐 Page load & console ({version_name})...")

    console_messages = []
    errors = []

    def handle_console(msg):
        console_messages.append(f"[{msg.type}] {msg.text}")
        # 401s are expected: the page polls APIs before credentials are entered
        if msg.type in ["error", "warning"] and "401" not in msg.text:
            errors.append(f"[{msg.type}] {msg.text}")

    def handle_page_error(error):
        error_msg = f"[PAGE ERROR] {error}"
        console_messages.append(error_msg)
        errors.append(error_msg)

    page.on("console", handle_console)
    page.on("pageerror", handle_page_error)

    try:
        response = page.goto(url, wait_until="networkidle", timeout=10000)
        print(f"     ✅ Page loaded with status {response.status}")
    except Exception as e:
        print(f"     ❌ Failed to load page: {e}")
        return False

    time.sleep(2)

    try:
        for label in ["Upload", "Files", "Preview", "Settings"]:
            btn = page.locator(f'button:has-text("{label}")')
            assert btn.is_visible(), f"{label} button not found"
        print("     ✅ All tab buttons visible (including Settings)")

        assert page.locator("#apiKey").count() == 0, "#apiKey input should not exist"
        assert page.locator("#padApiKey").count() == 0, "#padApiKey input should not exist"
        print("     ✅ Old API key inputs removed")

        page.locator('button:has-text("Files")').click()
        time.sleep(0.5)
        assert page.locator("#filesTab").is_visible(), "Files tab should be visible after click"
        print("     ✅ Tab switching works")

        page.locator('button:has-text("Settings")').click()
        time.sleep(0.5)
        assert page.locator("#settingsTab").is_visible(), "Settings tab should be visible after click"
        print("     ✅ Settings tab works")

    except Exception as e:
        print(f"     ❌ Element test failed: {e}")
        errors.append(f"Element test failed: {e}")

    if errors:
        print("\n     ❌ Console errors/warnings found:")
        for error in errors:
            print(f"       {error}")
    else:
        print("     ✅ No console errors")

    if console_messages:
        print("\n     📋 All console messages:")
        for msg in console_messages:
            print(f"       {msg}")

    return len(errors) == 0


def test_auth_flow(page, script, url, env):
    """Register via CLI, enter credentials in browser, verify 401 -> 200."""
    print("\n  🔐 Auth flow (CLI register -> browser credentials)...")

    # Register a regular user via CLI
    result = _run(script, ["register", "--server", "testserver", "--name", "browser-user"], env=env)
    assert result.returncode == 0, f"register failed:\n{result.stdout}\n{result.stderr}"
    client_id, client_secret = _parse_credentials(result.stdout)
    print(f"     ✅ Registered user: {client_id}")

    # Navigate fresh (no stored credentials)
    page.goto(url, wait_until="networkidle", timeout=10000)

    # Verify /api/files returns 401 without credentials
    api_status = page.evaluate("""async () => {
        const resp = await fetch('/api/files');
        return resp.status;
    }""")
    assert api_status == 401, f"Expected 401 without credentials, got {api_status}"
    print(f"     ✅ /api/files -> {api_status} without credentials")

    # Go to Settings tab and enter credentials
    page.locator('button:has-text("Settings")').click()
    time.sleep(0.5)
    assert page.locator("#settingsTab").is_visible(), "Settings tab not visible"

    page.fill("#settingsClientId", client_id)
    page.fill("#settingsClientSecret", client_secret)
    page.click("#saveCredsBtn")
    time.sleep(0.5)
    print("     ✅ Credentials saved in Settings")

    # Verify /api/files now returns 200
    api_result = page.evaluate("""async () => {
        const auth = JSON.parse(localStorage.getItem('companion_auth') || '{}');
        const resp = await fetch('/api/files', {
            headers: { 'Authorization': 'Bearer ' + auth.clientId + ':' + auth.clientSecret }
        });
        return { status: resp.status, ok: resp.ok };
    }""")
    assert api_result["status"] == 200, f"Expected 200 with credentials, got {api_result['status']}"
    print(f"     ✅ /api/files -> {api_result['status']} with credentials")

    # Verify Files tab works through the UI (no auth error shown)
    page.locator('button:has-text("Files")').click()
    time.sleep(1)
    files_tab = page.locator("#filesTab")
    assert files_tab.is_visible(), "Files tab not visible"
    files_text = files_tab.inner_text()
    assert "No credentials" not in files_text, f"Files tab still shows auth error: {files_text}"
    print("     ✅ Files tab loaded without auth errors")

    return True


def run_tests_for_version(name, script, port):
    """Run all browser tests for a given version (DEV or BUILT)."""
    print(f"\n{'=' * 60}")
    print(f"Testing {name} version ({script})")
    print("=" * 60)

    tmp_home = tempfile.mkdtemp()
    env = _make_env(tmp_home)
    base_url = f"http://localhost:{port}"

    # Set up admin config before starting server
    result = _run(script, ["server-setup", "--server", "testserver", "--url", base_url], env=env)
    assert result.returncode == 0, f"server-setup failed:\n{result.stdout}\n{result.stderr}"

    config = json.loads((Path(tmp_home) / ".config" / "companion" / "config.json").read_text())
    admin_id = config["servers"]["testserver"]["client-id"]
    print(f"  Admin client: {admin_id}")

    # Start server
    server = subprocess.Popen(
        ["python3", script, "server", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    time.sleep(2)

    results = {}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # Test 1: page load and console
            page1 = browser.new_page()
            results["page_load"] = test_page_load_and_console(page1, base_url, name)
            page1.close()

            # Test 2: auth flow
            page2 = browser.new_page()
            try:
                results["auth_flow"] = test_auth_flow(page2, script, base_url, env)
            except Exception as e:
                print(f"     ❌ Auth flow failed: {e}")
                results["auth_flow"] = False
            page2.close()

            browser.close()
    finally:
        server.terminate()
        server.wait()
        shutil.rmtree(tmp_home, ignore_errors=True)

    return results


def main():
    """Run all browser E2E tests against both dev and built versions."""
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)

    print("🧪 Starting browser E2E tests...")

    all_results = {}
    versions = [("DEV", "src/companion.py", 8090), ("BUILT", "companion.py", 8091)]

    for name, script, port in versions:
        all_results[name] = run_tests_for_version(name, script, port)

    # Summary
    print(f"\n{'=' * 60}")
    print("BROWSER TEST SUMMARY")
    print("=" * 60)
    all_passed = True
    for version, results in all_results.items():
        for test_name, passed in results.items():
            status = "✅ PASS" if passed else "❌ FAIL"
            print(f"  {version} / {test_name}: {status}")
            if not passed:
                all_passed = False

    if all_passed:
        print("\n🎉 All browser tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some browser tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
