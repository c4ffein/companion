#!/usr/bin/env python3
"""
Build tool for Companion - Inlines PDF.js CDN assets into companion.py

This tool fetches PDF.js from CDN and inlines it into the Python source
to maintain the zero-dependency single-file distribution model.
"""

import re
import urllib.request
from pathlib import Path


def fetch_url(url: str, cache_path: str) -> str:
    """Fetch content from URL or load from cache"""
    cache_file = Path(cache_path)

    # Check if cached version exists
    if cache_file.exists():
        print(f"📦 Loading from cache: {cache_path}")
        with open(cache_file, "r", encoding="utf-8") as f:
            content = f.read()
        print(f"✅ Loaded {len(content):,} bytes from cache")
        return content

    # Fetch from CDN
    print(f"📥 Fetching {url}...")
    with urllib.request.urlopen(url) as response:
        content = response.read().decode("utf-8")
    print(f"✅ Fetched {len(content):,} bytes")

    # Cache for future use
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cache_file, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"💾 Cached to {cache_path}")

    return content


def build_companion():
    """Build companion.py with inlined PDF.js"""
    print("🔨 Building Companion with inlined PDF.js...\n")

    # Read source file from src/
    print("📖 Reading src/companion.py...")
    with open("src/companion.py", "r", encoding="utf-8") as f:
        source = f.read()

    # Fetch PDF.js files (or load from cache)
    pdf_js_url = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.min.mjs"
    pdf_worker_url = (
        "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.worker.min.mjs"
    )

    pdf_js_content = fetch_url(pdf_js_url, "js_deps/pdf.min.mjs")
    pdf_worker_content = fetch_url(pdf_worker_url, "js_deps/pdf.worker.min.mjs")

    # Embed PDF.js files as Python string constants
    print("\n🔄 Embedding PDF.js files as Python constants...")

    import json

    # Escape the content for Python string literals
    pdf_js_escaped = json.dumps(pdf_js_content)
    pdf_worker_escaped = json.dumps(pdf_worker_content)

    # Add embedded PDF.js constants at the top of the file, after imports
    embedded_deps = f"""
# Embedded PDF.js files for offline use (added by build.py)
_PDFJS_LIB = {pdf_js_escaped}
_PDFJS_WORKER = {pdf_worker_escaped}
"""

    # Insert after the imports section (after "from typing import Dict, Tuple")
    source = source.replace(
        "from typing import Dict, Tuple\n",
        f"from typing import Dict, Tuple\n{embedded_deps}\n",
    )

    # Remove the PDF.js script tag from head (it will be imported in the module script instead)
    source = re.sub(
        r'    <!-- PDF\.js CDN - will be inlined in build -->\n    <script src="https://cdnjs\.cloudflare\.com/ajax/libs/pdf\.js/[^"]+/pdf\.min\.mjs" type="module"></script>\n',
        "",
        source,
    )

    # Replace CDN URLs with local /deps/ URLs (in the import statement)
    source = source.replace(
        "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.min.mjs",
        "/deps/pdf.min.mjs",
    )
    source = source.replace(
        "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.worker.min.mjs",
        "/deps/pdf.worker.min.mjs",
    )

    # Add /deps/ routes to the HTTP handler
    # Find the do_GET method and add routes there
    deps_handler = """        # Serve embedded PDF.js dependencies (built version only)
        if self.path == "/deps/pdf.min.mjs":
            if "_PDFJS_LIB" in globals():
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                content_bytes = _PDFJS_LIB.encode("utf-8")
                self.send_header("Content-Length", str(len(content_bytes)))
                self.send_header("Cache-Control", "public, max-age=31536000")  # Cache for 1 year
                self.end_headers()
                self.wfile.write(content_bytes)
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
            return

        if self.path == "/deps/pdf.worker.min.mjs":
            if "_PDFJS_WORKER" in globals():
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                content_bytes = _PDFJS_WORKER.encode("utf-8")
                self.send_header("Content-Length", str(len(content_bytes)))
                self.send_header("Cache-Control", "public, max-age=31536000")  # Cache for 1 year
                self.end_headers()
                self.wfile.write(content_bytes)
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
            return

"""

    # Insert deps routes at the beginning of do_GET method (after the docstring if any)
    # Look for "def do_GET(self):" and insert after it
    source = source.replace(
        '    def do_GET(self):\n        """Handle GET requests"""\n',
        f'    def do_GET(self):\n        """Handle GET requests"""\n{deps_handler}',
    )

    # Update docstring to mark as built version
    print("\n📝 Adding built version marker to docstring...")
    source = source.replace(
        '#!/usr/bin/env python3\n"""',
        '#!/usr/bin/env python3\n"""\n⚠️  BUILT VERSION - This file was automatically generated by build.py\n    Source: src/companion.py\n    This version includes inlined PDF.js (~1.4MB) for offline use.\n    For development, use src/companion.py which loads PDF.js from CDN.\n\nLICENSE NOTICE:\n    - Companion code: MIT License, Copyright (c) 2025 c4ffein\n    - Embedded PDF.js library: Apache License 2.0, Copyright Mozilla Foundation\n    - See js_deps/LICENSE for full PDF.js license details\n    - Both licenses allow commercial and non-commercial use\n\n',
        1,  # Only replace the first occurrence
    )

    # Write output file to root
    output_file = "companion.py"
    print(f"\n💾 Writing {output_file} to root...")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(source)

    output_size = len(source)
    original_size = len(open("src/companion.py", "r").read())

    print(f"✅ Build complete! Output: {output_file}")
    print(f"📦 Original size: {original_size:,} bytes")
    print(f"📦 Built size: {output_size:,} bytes")
    print(
        f"📦 Added: {output_size - original_size:,} bytes ({((output_size / original_size - 1) * 100):.1f}% increase)"
    )
    print("\n🎉 You can now distribute companion.py as a single file!")
    print("   The built version is at the root for easy access.")


if __name__ == "__main__":
    build_companion()
