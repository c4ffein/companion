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
    pdf_worker_url = "https://cdnjs.cloudflare.com/ajax/libs/pdf.js/5.4.149/pdf.worker.min.mjs"

    pdf_js_content = fetch_url(pdf_js_url, "js_deps/pdf.min.mjs")
    pdf_worker_content = fetch_url(pdf_worker_url, "js_deps/pdf.worker.min.mjs")

    # Embed PDF.js files as base64-encoded Python string constants
    print("\n🔄 Embedding PDF.js files as base64 constants...")

    import base64

    # Encode content as base64
    pdf_js_b64 = base64.b64encode(pdf_js_content.encode("utf-8")).decode("ascii")
    pdf_worker_b64 = base64.b64encode(pdf_worker_content.encode("utf-8")).decode("ascii")

    # Add embedded PDF.js constants at the top of the file, after imports
    embedded_deps = f"""
# Embedded PDF.js files for offline use (added by build.py)
# Base64-encoded to avoid escaping issues
_PDFJS_LIB = "{pdf_js_b64}";
_PDFJS_WORKER = "{pdf_worker_b64}";
"""

    # Insert after the imports section (after "from typing import ...")
    typing_import = "from typing import Dict, Optional, Tuple\n"
    if typing_import not in source:
        print("❌ ERROR: Could not find typing import line in source.")
        print(f"   Expected: {typing_import.strip()}")
        print("   The source file may have been modified. Please update build.py.")
        exit(1)
    source = source.replace(typing_import, f"{typing_import}{embedded_deps}\n")

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
                import base64
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                # Decode base64 to get original content
                content_bytes = base64.b64decode(_PDFJS_LIB.rstrip(';').strip('"'))
                self.send_header("Content-Length", str(len(content_bytes)))
                self.send_header("Cache-Control", "public, max-age=31536000")  # Cache for 1 year
                self.end_headers()
                self.wfile.write(content_bytes)
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
            return

        if self.path == "/deps/pdf.worker.min.mjs":
            if "_PDFJS_WORKER" in globals():
                import base64
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/javascript; charset=utf-8")
                # Decode base64 to get original content
                content_bytes = base64.b64decode(_PDFJS_WORKER.rstrip(';').strip('"'))
                self.send_header("Content-Length", str(len(content_bytes)))
                self.send_header("Cache-Control", "public, max-age=31536000")  # Cache for 1 year
                self.end_headers()
                self.wfile.write(content_bytes)
            else:
                self.send_error(HTTPStatus.NOT_FOUND)
            return

"""

    # Insert deps routes at the beginning of do_GET method (after the docstring if any)
    do_get_marker = '    def do_GET(self):\n        """Handle GET requests"""\n'
    if do_get_marker not in source:
        print("❌ ERROR: Could not find do_GET method in source.")
        print("   The source file may have been modified. Please update build.py.")
        exit(1)
    source = source.replace(do_get_marker, f"{do_get_marker}{deps_handler}")

    # Update docstring to mark as built version
    print("\n📝 Adding built version marker to docstring...")
    shebang_marker = '#!/usr/bin/env python3\n"""'
    if shebang_marker not in source:
        print("❌ ERROR: Could not find shebang/docstring marker in source.")
        print("   The source file may have been modified. Please update build.py.")
        exit(1)
    source = source.replace(
        shebang_marker,
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
