#!/usr/bin/env python3
"""
Browser E2E tests for companion.py
Tests the actual browser behavior including JavaScript execution and console errors
"""

import subprocess
import sys
import time
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
            # Check for tab buttons
            upload_button = page.locator('button:has-text("Upload")')
            files_button = page.locator('button:has-text("Files")')
            preview_button = page.locator('button:has-text("Preview")')

            assert upload_button.is_visible(), "Upload button not found"
            assert files_button.is_visible(), "Files button not found"
            assert preview_button.is_visible(), "Preview button not found"
            print("✅ All tab buttons visible")

            # Test tab switching
            files_button.click()
            time.sleep(0.5)
            files_tab = page.locator("#filesTab")
            assert files_tab.is_visible(), "Files tab should be visible after click"
            print("✅ Tab switching works")

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
    # Change to project root directory (parent of tests/)
    import os
    from pathlib import Path

    project_root = Path(__file__).parent.parent
    os.chdir(project_root)

    print("🧪 Starting browser E2E tests...")

    # Start server for dev version
    print("\n" + "=" * 60)
    print("Testing DEV version (src/companion.py)")
    print("=" * 60)

    server_dev = subprocess.Popen(
        [
            "python3",
            "src/companion.py",
            "server",
            "--api-key",
            "test123",
            "--port",
            "8090",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(2)  # Wait for server to start

    try:
        dev_passed = test_page_load_and_console("http://localhost:8090", "DEV version")
    finally:
        server_dev.terminate()
        server_dev.wait()

    # Start server for built version
    print("\n" + "=" * 60)
    print("Testing BUILT version (companion.py)")
    print("=" * 60)

    server_built = subprocess.Popen(
        ["python3", "companion.py", "server", "--api-key", "test123", "--port", "8091"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    time.sleep(2)  # Wait for server to start

    try:
        built_passed = test_page_load_and_console(
            "http://localhost:8091", "BUILT version"
        )
    finally:
        server_built.terminate()
        server_built.wait()

    # Summary
    print("\n" + "=" * 60)
    print("BROWSER TEST SUMMARY")
    print("=" * 60)
    print(f"DEV version:   {'✅ PASS' if dev_passed else '❌ FAIL'}")
    print(f"BUILT version: {'✅ PASS' if built_passed else '❌ FAIL'}")

    if dev_passed and built_passed:
        print("\n🎉 All browser tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some browser tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
