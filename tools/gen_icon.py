#!/usr/bin/env python3
"""Regenerate the Companion icon (SVG + PNG) from a single Python definition.

The icon's geometry and colors live as the ICON dict below — the single source
of truth. Running this script regenerates the SVG and a 180×180 anti-aliased
grayscale PNG (8× supersampled) and patches both `src/companion.py` (the
`_ICON_SVG` and `_APPLE_TOUCH_ICON_PNG` constants, plus the route path) and
`src/index.html` (the `<link rel="apple-touch-icon">` href) in place.

The PNG URL uses a 6-char SHA-256 prefix of the PNG bytes as a cache-busting
suffix — `apple-touch-icon.<hash>.png`. URL changes IFF the bytes change.

Usage:
    python3 tools/gen_icon.py            # regenerate and patch in place
    python3 tools/gen_icon.py --check    # exit 1 if patched contents differ
                                         # (used by `make check` and CI)

Pure-stdlib: struct + zlib + hashlib + base64. No external image library.
"""

import argparse
import base64
import hashlib
import re
import struct
import sys
import textwrap
import zlib
from pathlib import Path

# ---------- icon definition (single source of truth) ----------

ICON = {
    "viewbox": (0, 0, 512, 512),
    "output_size": 180,
    "supersample": 8,
    "shapes": [
        {"type": "rect", "x": 0, "y": 0, "w": 512, "h": 512, "fill": "#000000"},
        {"type": "rrect", "x": 176, "y": 90, "w": 160, "h": 333, "rx": 28, "fill": "#FFFFFF"},
    ],
}

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPANION_PY = REPO_ROOT / "src" / "companion.py"
INDEX_HTML = REPO_ROOT / "src" / "index.html"

# Matches `/apple-touch-icon.<any-alphanumeric>.png` — used to update the route
# in src/companion.py and the <link> href in src/index.html.
ROUTE_RE = re.compile(r"/apple-touch-icon\.[A-Za-z0-9]+\.png")


# ---------- color helpers ----------


def hex_to_rgb(c):
    c = c.lstrip("#")
    return int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)


def rgb_to_luma(r, g, b):
    # ITU-R BT.601 luma — close enough to perceived brightness for an icon
    return (299 * r + 587 * g + 114 * b) // 1000


# ---------- SVG generation ----------


def svg_bytes(icon):
    vb = " ".join(str(n) for n in icon["viewbox"])
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{vb}">']
    for s in icon["shapes"]:
        if s["type"] == "rect":
            out.append(f'<rect x="{s["x"]}" y="{s["y"]}" width="{s["w"]}" height="{s["h"]}" fill="{s["fill"]}"/>')
        elif s["type"] == "rrect":
            out.append(
                f'<rect x="{s["x"]}" y="{s["y"]}" width="{s["w"]}" height="{s["h"]}" '
                f'rx="{s["rx"]}" fill="{s["fill"]}"/>'
            )
        else:
            raise ValueError(f"unknown shape type: {s['type']}")
    out.append("</svg>")
    return "".join(out).encode("ascii")


# ---------- PNG generation (8× supersampled grayscale) ----------


def _luma_at(icon, vx, vy, lumas):
    """Resolve the (cached) luma at viewBox coords (vx, vy). lumas: shape_idx → int."""
    luma = 0
    for i, s in enumerate(icon["shapes"]):
        x0, y0 = s["x"], s["y"]
        x1, y1 = x0 + s["w"], y0 + s["h"]
        if not (x0 <= vx < x1 and y0 <= vy < y1):
            continue
        if s["type"] == "rect":
            luma = lumas[i]
        elif s["type"] == "rrect":
            r = s["rx"]
            if x0 + r <= vx < x1 - r or y0 + r <= vy < y1 - r:
                luma = lumas[i]
            else:
                cx = x0 + r if vx < x0 + r else x1 - 1 - r
                cy = y0 + r if vy < y0 + r else y1 - 1 - r
                if (vx - cx) * (vx - cx) + (vy - cy) * (vy - cy) <= r * r:
                    luma = lumas[i]
    return luma


def png_bytes(icon):
    W = H = icon["output_size"]
    ss = icon["supersample"]
    vb_x0, vb_y0, vb_w, vb_h = icon["viewbox"]
    hi_W, hi_H = W * ss, H * ss
    sx, sy = vb_w / hi_W, vb_h / hi_H

    # Precompute each shape's luma once (avoids per-sample hex parsing).
    lumas = [rgb_to_luma(*hex_to_rgb(s["fill"])) for s in icon["shapes"]]

    # Accumulate luma sums per output pixel across the 8×8 hi-res samples.
    sums = [0] * (W * H)
    for hy in range(hi_H):
        vy = vb_y0 + (hy + 0.5) * sy
        row_off = (hy // ss) * W
        for hx in range(hi_W):
            vx = vb_x0 + (hx + 0.5) * sx
            sums[row_off + (hx // ss)] += _luma_at(icon, vx, vy, lumas)

    ss2 = ss * ss
    pixels = bytes(s // ss2 for s in sums)
    # PNG row = filter byte (0 = None) + W luma bytes.
    raw = b"".join(b"\x00" + pixels[y * W : (y + 1) * W] for y in range(H))

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", W, H, 8, 0, 0, 0, 0)  # 8-bit grayscale
    idat = zlib.compress(raw, 9)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


# ---------- formatting for source-file embedding ----------


def fmt_icon_svg_block(svg):
    """Render the _ICON_SVG = (...) block — one byte-string literal per SVG element.

    Matches ruff's quote-style rule (prefer double quotes; fall back to single
    quotes when the segment contains a literal double quote — which it does for
    every SVG element with attributes). This keeps the source idempotent under
    `make format`.
    """

    def wrap(p):
        if '"' not in p:
            return f'    b"{p}"'
        if "'" not in p:
            return f"    b'{p}'"
        raise ValueError("SVG segment contains both single and double quotes; no clean wrapping")

    s = svg.decode("ascii")
    parts = s.replace("><", ">\x00<").split("\x00")
    body = "\n".join(wrap(p) for p in parts)
    return f"_ICON_SVG = (\n{body}\n)"


def fmt_png_block(png):
    """Render the _APPLE_TOUCH_ICON_PNG = base64.b64decode(...) block."""
    b = base64.b64encode(png).decode("ascii")
    body = "\n".join(f'    b"{line}"' for line in textwrap.wrap(b, 84))
    return f"_APPLE_TOUCH_ICON_PNG = base64.b64decode(\n{body}\n)"


def png_url_path(png):
    return f"/apple-touch-icon.{hashlib.sha256(png).hexdigest()[:6]}.png"


# ---------- patch / check ----------


_SVG_BLOCK_RE = re.compile(r"_ICON_SVG = \([\s\S]*?\n\)")
_PNG_BLOCK_RE = re.compile(r"_APPLE_TOUCH_ICON_PNG = base64\.b64decode\([\s\S]*?\n\)")


def regenerate(svg, png):
    """Patch the source files. Returns the new URL path."""
    path = png_url_path(png)
    svg_block = fmt_icon_svg_block(svg)
    png_block = fmt_png_block(png)
    # Lambda replacements bypass re.sub's backreference parsing.
    comp = COMPANION_PY.read_text()
    comp = _SVG_BLOCK_RE.sub(lambda _: svg_block, comp, count=1)
    comp = _PNG_BLOCK_RE.sub(lambda _: png_block, comp, count=1)
    comp = ROUTE_RE.sub(path, comp)
    COMPANION_PY.write_text(comp)

    html = INDEX_HTML.read_text()
    html = ROUTE_RE.sub(path, html)
    INDEX_HTML.write_text(html)
    return path


def check(svg, png):
    """Return True if src files already contain the regenerated assets."""
    path = png_url_path(png)
    comp = COMPANION_PY.read_text()
    html = INDEX_HTML.read_text()

    problems = []
    if fmt_icon_svg_block(svg) not in comp:
        problems.append("_ICON_SVG is out of sync")
    if fmt_png_block(png) not in comp:
        problems.append("_APPLE_TOUCH_ICON_PNG is out of sync")
    if path not in comp:
        problems.append(f"route path {path} missing from src/companion.py")
    if path not in html:
        problems.append(f"<link> href {path} missing from src/index.html")
    return problems


# ---------- CLI ----------


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--check", action="store_true", help="Exit 1 if src/ is out of sync with the icon definition.")
    args = p.parse_args()

    svg = svg_bytes(ICON)
    png = png_bytes(ICON)

    if args.check:
        problems = check(svg, png)
        if not problems:
            print("✓ icon assets in src/ match tools/gen_icon.py")
            return 0
        for msg in problems:
            print(f"✗ {msg}")
        print("\nRun: python3 tools/gen_icon.py")
        return 1

    path = regenerate(svg, png)
    print("✓ regenerated icon")
    print(f"  SVG:  {len(svg)} bytes")
    print(f"  PNG:  {len(png)} bytes ({ICON['output_size']}x{ICON['output_size']}, {ICON['supersample']}× supersampled)")
    print(f"  URL:  {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
