"""Generate the README's SVGs (banner and update flow, dark and light) with text outlined to paths.

GitHub serves README images through <img>, which cannot load web fonts, so every glyph is drawn as
a path from the RznSans TTF files. Not part of the Gate; run it by hand after changing a picture:

    python3 scripts/readme-assets.py <RznSans fonts dir> docs/images/readme

Needs fontTools (`pip install fonttools`).
"""
import os
import random
import sys

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

if len(sys.argv) != 3:
    sys.exit("usage: readme-assets.py <RznSans fonts dir> <out dir>")
FONTS, OUT = sys.argv[1], sys.argv[2]
_cache = {}


def font(w):
    if w not in _cache:
        _cache[w] = TTFont(os.path.join(FONTS, f"RznSans-{w}.ttf"))
    return _cache[w]


def text(s, x, y, size, weight="Regular", fill="#fff", tracking=0.0, anchor="start", opacity=1):
    f = font(weight)
    upm = f["head"].unitsPerEm
    cmap, gs, hmtx = f.getBestCmap(), f.getGlyphSet(), f["hmtx"]
    sc = size / upm
    names = [cmap.get(ord(c), ".notdef") for c in s]
    adv = [hmtx[n][0] + tracking * upm for n in names]
    width = sum(adv) * sc
    if anchor == "middle":
        x -= width / 2
    elif anchor == "end":
        x -= width
    d, cx = [], 0
    for n, a in zip(names, adv):
        pen = SVGPathPen(gs)
        gs[n].draw(TransformPen(pen, (sc, 0, 0, -sc, x + cx * sc, y)))
        d.append(pen.getCommands())
        cx += a
    return f'<path fill="{fill}" fill-opacity="{opacity}" d="{" ".join(d)}"/>', width


THEMES = {
    "dark": dict(bg0="#0d0f14", bg1="#1b1e27", ink="#f3f4f7", sub="#a9afbd", dim="#6b7285",
                 moon0="#f4f1e8", moon1="#c9cdd8", glow="#9fb4ff", star="#ffffff", rust="#f0743e",
                 ok="#5cc98a", bad="#ef6b6b", ring="#ffffff", chip="#ffffff", chipo=0.06, chipb=0.14),
    "light": dict(bg0="#f7f8fb", bg1="#e6e9f1", ink="#14161c", sub="#4a5162", dim="#7a8194",
                  moon0="#2a2f3d", moon1="#4b5470", glow="#6d82d6", star="#3b4256", rust="#d4561f",
                  ok="#1f9254", bad="#c8372f", ring="#1b1f2a", chip="#14161c", chipo=0.04, chipb=0.12),
}


def moon(cx, cy, r, t, p):
    return f'''
  <defs>
    <radialGradient id="{p}halo" cx="{cx}" cy="{cy}" r="{r*2.6}" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="{t['glow']}" stop-opacity="0.32"/>
      <stop offset="0.45" stop-color="{t['glow']}" stop-opacity="0.08"/>
      <stop offset="1" stop-color="{t['glow']}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="{p}moon" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{t['moon0']}"/><stop offset="1" stop-color="{t['moon1']}"/>
    </linearGradient>
    <mask id="{p}cut"><rect x="{cx-r*2}" y="{cy-r*2}" width="{r*4}" height="{r*4}" fill="#fff"/>
      <circle cx="{cx+r*0.46}" cy="{cy-r*0.30}" r="{r*0.86}" fill="#000"/></mask>
  </defs>
  <circle cx="{cx}" cy="{cy}" r="{r*2.6}" fill="url(#{p}halo)"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="url(#{p}moon)" mask="url(#{p}cut)"/>'''


def parcel(x, y, s, t):
    """A small isometric box: the package that orbits the moon."""
    top = f"M{x} {y-s*0.5} L{x+s} {y} L{x} {y+s*0.5} L{x-s} {y} Z"
    left = f"M{x-s} {y} L{x} {y+s*0.5} L{x} {y+s*1.6} L{x-s} {y+s*1.1} Z"
    right = f"M{x+s} {y} L{x} {y+s*0.5} L{x} {y+s*1.6} L{x+s} {y+s*1.1} Z"
    tape = f"M{x-s*0.5} {y-s*0.25} L{x+s*0.5} {y+s*0.25}"
    return (f'<path d="{left}" fill="{t["rust"]}" fill-opacity="0.78"/>'
            f'<path d="{right}" fill="{t["rust"]}" fill-opacity="0.58"/>'
            f'<path d="{top}" fill="{t["rust"]}"/>'
            f'<path d="{tape}" stroke="{t["bg0"]}" stroke-opacity="0.55" stroke-width="2"/>')


def banner(theme):
    t = THEMES[theme]
    W, H = 1280, 420
    p = f"b{theme[0]}"
    rnd = random.Random(11)
    stars = []
    for _ in range(70):
        x, y = rnd.uniform(0, W), rnd.uniform(0, H)
        if 80 < x < 800 and 100 < y < 340:
            continue
        stars.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{rnd.uniform(0.6, 1.7):.2f}" '
                     f'fill="{t["star"]}" opacity="{rnd.uniform(0.12, 0.55):.2f}"/>')
    title, tw = text("lunepack", 96, 218, 112, "Bold", t["ink"], tracking=-0.02)
    tag, _ = text("Package, ship and update desktop apps, in pure Rust", 100, 274, 30, "Regular", t["sub"])
    chips, cx = [], 100
    for label in ["Windows · macOS · Linux", "Signed + delta updates", "Rollback built in"]:
        lp, lw = text(label, cx + 18, 338, 19, "Medium", t["ink"], opacity=0.85)
        chips.append(f'<rect x="{cx}" y="311" width="{lw+36:.1f}" height="38" rx="19" fill="{t["chip"]}" '
                     f'fill-opacity="{t["chipo"]}" stroke="{t["chip"]}" stroke-opacity="{t["chipb"]}"/>{lp}')
        cx += lw + 36 + 12
    dot = f'<circle cx="{96+tw+14:.1f}" cy="210" r="9" fill="{t["rust"]}"/>'
    rings = "".join(
        f'<ellipse cx="1010" cy="210" rx="{rx}" ry="{rx*0.30:.1f}" fill="none" stroke="{t["ring"]}" '
        f'stroke-opacity="{o}" transform="rotate(-14 1010 210)"/>'
        for rx, o in [(250, 0.07), (195, 0.10)])
    box = f'<g transform="rotate(-14 1010 210)">{parcel(1010+250*0.96, 210-72, 14, t)}</g>'
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="lunepack: package, ship and update desktop apps, in pure Rust">
  <defs><linearGradient id="{p}bg" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="{t['bg0']}"/><stop offset="1" stop-color="{t['bg1']}"/></linearGradient>
    <clipPath id="{p}clip"><rect width="{W}" height="{H}" rx="24"/></clipPath></defs>
  <g clip-path="url(#{p}clip)">
  <rect width="{W}" height="{H}" fill="url(#{p}bg)"/>
  {''.join(stars)}
  {rings}
  {moon(1010, 210, 108, t, p)}
  {box}
  {title}{dot}{tag}{''.join(chips)}
  </g>
</svg>'''


def flow(theme):
    t = THEMES[theme]
    W, H = 1280, 370
    acc = t["rust"]
    out = []
    groups = [("ON YOUR BUILD MACHINE", "lunepack CLI", 40, ["pack", "sign", "publish feed"]),
              ("IN YOUR APP", "lunepack crate · runtime · C library", 660, ["check", "download + stage", "apply + restart"])]
    bw, gap, by = 162, 17, 150
    for lab, sub, gx, steps in groups:
        out.append(f'<rect x="{gx}" y="40" width="580" height="280" rx="18" fill="{t["chip"]}" '
                   f'fill-opacity="{t["chipo"]}" stroke="{t["chip"]}" stroke-opacity="{t["chipb"]}"/>')
        out.append(text(lab, gx + 28, 80, 14, "Medium", acc, tracking=0.12)[0])
        out.append(text(sub, gx + 28, 108, 20, "Medium", t["sub"])[0])
        for i, s in enumerate(steps):
            bx = gx + 28 + i * (bw + gap)
            out.append(f'<rect x="{bx}" y="{by}" width="{bw}" height="64" rx="12" fill="{t["bg0"]}" '
                       f'stroke="{t["chip"]}" stroke-opacity="{t["chipb"]+0.06}"/>')
            size = 19 if len(s) <= 14 else 17
            out.append(text(s, bx + bw / 2, by + 38, size, "Medium", t["ink"], anchor="middle")[0])
            if i < len(steps) - 1:
                ax = bx + bw + 2
                out.append(f'<path d="M{ax} {by+32} h{gap-6} m-5 -5 l5 5 l-5 5" fill="none" stroke="{t["dim"]}" '
                           f'stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
    out.append(f'<path d="M622 182 h34" stroke="{acc}" stroke-width="2.5" stroke-dasharray="5 5"/>'
               f'<path d="M650 176 l7 6 l-7 6" fill="none" stroke="{acc}" stroke-width="2.5" stroke-linecap="round"/>')
    out.append(text("signed feed, manifests and packs on any static host, or file:", 640, 352, 15,
                    "Regular", t["dim"], anchor="middle")[0])
    # what the packager adds
    px = 40 + 28
    for label in ["Ed25519 signatures", "delta patches", "installers"]:
        lp, lw = text(label, px + 34, 279, 16, "Medium", t["sub"])
        out.append(f'<rect x="{px}" y="252" width="{lw+50:.1f}" height="38" rx="19" fill="{acc}" fill-opacity="0.10"/>'
                   f'<circle cx="{px+19}" cy="271" r="5" fill="{acc}"/>{lp}')
        px += lw + 50 + 12
    # the health handshake: what happens after "apply + restart"
    px = 660 + 28
    for col, label in [(t["ok"], "confirmed: the new version stays"), (t["bad"], "no confirm: rolled back")]:
        lp, lw = text(label, px + 34, 279, 16, "Medium", col)
        out.append(f'<rect x="{px}" y="252" width="{lw+50:.1f}" height="38" rx="19" fill="{col}" fill-opacity="0.12"/>'
                   f'<circle cx="{px+19}" cy="271" r="5" fill="{col}"/>{lp}')
        px += lw + 50 + 12
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" role="img" aria-label="lunepack flow: pack, sign and publish a feed on the build machine; check, download and stage, apply and restart in the app, which keeps the new version once it confirms it works and rolls back otherwise">
  {''.join(out)}
</svg>'''


os.makedirs(OUT, exist_ok=True)
for th in THEMES:
    with open(os.path.join(OUT, f"banner-{th}.svg"), "w") as f:
        f.write(banner(th))
    with open(os.path.join(OUT, f"flow-{th}.svg"), "w") as f:
        f.write(flow(th))
print("ok")
