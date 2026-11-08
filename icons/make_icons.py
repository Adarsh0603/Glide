"""Draws Glide's icons (same art as ICON in glide.py). Dev-only: needs Pillow.
Usage:  python icons/make_icons.py
"""
import os

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
BG = (11, 13, 16, 255)                 # #0b0d10
C1, C2 = (91, 140, 255), (138, 107, 255)  # #5b8cff -> #8a6bff
# cursor arrow in a 192x192 box
ARROW = [(64, 42), (64, 142), (90, 118), (108, 154), (128, 145), (110, 110), (146, 110)]
SS = 4  # supersampling for smooth edges


def gradient(n):
    """Diagonal gradient, top-left C1 to bottom-right C2."""
    small = Image.new("RGBA", (64, 64))
    px = small.load()
    for y in range(64):
        for x in range(64):
            t = (x + y) / 126
            px[x, y] = tuple(round(a + (b - a) * t) for a, b in zip(C1, C2)) + (255,)
    return small.resize((n, n), Image.BILINEAR)


def draw(size, rounded=True, scale=1.0):
    n = size * SS
    k = n / 192
    img = Image.new("RGBA", (n, n), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    if rounded:
        d.rounded_rectangle((0, 0, n - 1, n - 1), radius=round(44 * k), fill=BG)
    else:
        d.rectangle((0, 0, n, n), fill=BG)
    cx, cy = (64 + 146) / 2, (42 + 154) / 2   # centre of the arrow's bounding box
    pts = [((x - cx) * scale * k + n / 2, (y - cy) * scale * k + n / 2) for x, y in ARROW]
    mask = Image.new("L", (n, n), 0)
    m = ImageDraw.Draw(mask)
    w = round(6 * scale * k)                   # the SVG's 6px round-joined stroke
    m.polygon(pts, fill=255)
    m.line(pts + [pts[0]], fill=255, width=w)
    for x, y in pts:
        m.ellipse((x - w / 2, y - w / 2, x + w / 2, y + w / 2), fill=255)
    img.paste(gradient(n), (0, 0), mask)
    return img.resize((size, size), Image.LANCZOS)


def main():
    out = lambda name: os.path.join(HERE, name)
    draw(192).save(out("icon-192.png"))
    draw(512).save(out("icon-512.png"))
    # maskable / iOS: full-bleed square, the launcher or iOS rounds the corners itself
    draw(512, rounded=False, scale=0.8).save(out("icon-maskable-512.png"))
    draw(180, rounded=False).save(out("apple-touch-icon.png"))
    draw(256).save(out("glide.ico"), sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("icons written to", HERE)


if __name__ == "__main__":
    main()
