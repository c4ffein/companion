#!/usr/bin/env python3
"""
Browser E2E tests for companion.py
Tests the actual browser behavior including JavaScript execution and console errors

Requires playwright: run via 'make test-browser'
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright


def test_page_load_and_console(url, version_name):
    """Test that page loads without console errors"""
    print(f"\n🌐 Testing {version_name} at {url}...")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Collect console messages and page errors
        console_messages = []
        errors = []

        def handle_console(msg):
            console_messages.append(f"[{msg.type}] {msg.text}")
            if msg.type in ["error", "warning"]:
                errors.append(f"[{msg.type}] {msg.text}")

        def handle_page_error(error):
            error_msg = f"[PAGE ERROR] {error}"
            console_messages.append(error_msg)
            errors.append(error_msg)

        page.on("console", handle_console)
        page.on("pageerror", handle_page_error)

        # Navigate to page
        try:
            response = page.goto(url, wait_until="networkidle", timeout=10000)
            print(f"✅ Page loaded with status {response.status}")
        except Exception as e:
            print(f"❌ Failed to load page: {e}")
            browser.close()
            return False

        # Wait a bit for JavaScript to execute
        time.sleep(2)

        # Check if we can find the main elements
        try:
            # Check for tab buttons (including Settings)
            for label in ["Upload", "Files", "Preview", "Settings"]:
                btn = page.locator(f'button:has-text("{label}")')
                assert btn.is_visible(), f"{label} button not found"
            print("✅ All tab buttons visible (including Settings)")

            # Verify old API key inputs are gone
            assert page.locator("#apiKey").count() == 0, "#apiKey input should not exist"
            assert page.locator("#padApiKey").count() == 0, "#padApiKey input should not exist"
            print("✅ Old API key inputs removed")

            # Test tab switching
            page.locator('button:has-text("Files")').click()
            time.sleep(0.5)
            assert page.locator("#filesTab").is_visible(), "Files tab should be visible after click"
            print("✅ Tab switching works")

            # Test Settings tab
            page.locator('button:has-text("Settings")').click()
            time.sleep(0.5)
            assert page.locator("#settingsTab").is_visible(), "Settings tab should be visible after click"
            print("✅ Settings tab works")

        except Exception as e:
            print(f"❌ Element test failed: {e}")
            errors.append(f"Element test failed: {e}")

        # Report console errors
        if errors:
            print("\n❌ Console errors/warnings found:")
            for error in errors:
                print(f"  {error}")
        else:
            print("✅ No console errors")

        # ALWAYS print all console messages for debugging
        if console_messages:
            print("\n📋 All console messages:")
            for msg in console_messages:
                print(f"  {msg}")

        browser.close()
        return len(errors) == 0


def main():
    """Run browser tests against both dev and built versions"""
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)

    print("🧪 Starting browser E2E tests...")

    # Use temp HOME to avoid config issues
    temp_home = tempfile.mkdtemp()
    env = {**os.environ, "HOME": temp_home}

    results = {}
    versions = [("DEV", "src/companion.py", 8090), ("BUILT", "companion.py", 8091)]

    for name, script, port in versions:
        print(f"\n{'=' * 60}")
        print(f"Testing {name} version ({script})")
        print("=" * 60)

        server = subprocess.Popen(
            ["python3", script, "server", "--port", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        time.sleep(2)

        try:
            results[name] = test_page_load_and_console(f"http://localhost:{port}", f"{name} version")
        finally:
            server.terminate()
            server.wait()

    shutil.rmtree(temp_home, ignore_errors=True)

    # Summary
    print(f"\n{'=' * 60}")
    print("BROWSER TEST SUMMARY")
    print("=" * 60)
    for name, passed in results.items():
        print(f"{name} version:  {'✅ PASS' if passed else '❌ FAIL'}")

    if all(results.values()):
        print("\n🎉 All browser tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some browser tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
