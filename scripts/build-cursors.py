#!/usr/bin/env python3
"""Build the site's 8-bit cursors as SVG files.

Each cursor is drawn on a pixel grid: 'k' ink outline, 'w' stock fill,
's' shade along the right edge, '.' transparent. One grid pixel is 1.5 CSS pixels. Plain SVG with crisp edges:
browsers handle a single url() cursor reliably, unlike image-set().

Run from the repo root:  python3 scripts/build-cursors.py
"""
import math
from pathlib import Path

INK = (17, 20, 24, 255)      # --ink  #111418
STOCK = (238, 240, 236, 255)  # --paper #eef0ec
SHADE = (195, 201, 207, 255)  # --rule-soft #c3c9cf, the right-edge shade
COLORS = {'k': INK, 'w': STOCK, 's': SHADE}

CURSORS = {
    # The classic desktop pixel arrow: a 45-degree head and a straight tail
    # that steps down two rows per column. Tip at the top-left pixel.
    'arrow': [
        'k...........',
        'kk..........',
        'kwk.........',
        'kwsk........',
        'kwwsk.......',
        'kwwwsk......',
        'kwwwwsk.....',
        'kwwwwwsk....',
        'kwwwwwwsk...',
        'kwwwwwwwsk..',
        'kwwwwwwwwsk.',
        'kwwwwwwkkkkk',
        'kwwwkwwk....',
        'kwwkkwwk....',
        'kwk..kwsk...',
        'kk...kwsk...',
        'k.....kwsk..',
        '......kwsk..',
        '.......kk...',
    ],
    # Pointing hand for links and buttons, index fingertip at the top.
    'hand': [
        '....kk..........',
        '...kwsk.........',
        '...kwsk.........',
        '...kwsk.........',
        '...kwskkk.......',
        '...kwwkwskkk....',
        '...kwwkwwkwskkk.',
        '.kkkwwkwwkwwkwsk',
        'kwwkwwwwwwwwwwsk',
        'kwwwwwwwwwwwwwsk',
        '.kwwwwwwwwwwwwsk',
        '..kwwwwwwwwwwwsk',
        '..kwwwwwwwwwwsk.',
        '...kwwwwwwwwwsk.',
        '....kwwwwwwwsk..',
        '....kkkkkkkkkk..',
    ],
    # Text beam for reading text, with a stock halo so it shows on ink and
    # on ultramarine.
    'text': [
        'www.www',
        'wkkwkkw',
        'wwwkwww',
        '..wkw..',
        '..wkw..',
        '..wkw..',
        '..wkw..',
        '..wkw..',
        '..wkw..',
        '..wkw..',
        '..wkw..',
        '..wkw..',
        'wwwkwww',
        'wkkwkkw',
        'www.www',
    ],
}


# 1.5 CSS pixels per grid pixel: on a 2x (retina) screen every grid pixel is
# exactly 3 device pixels, so the cursor stays sharp at about 3/4 the size of
# a 2px-per-pixel drawing.
SCALE = 1.5


def svg(grid):
    gw, gh = len(grid[0]), len(grid)
    rects = []
    for y, row in enumerate(grid):
        x = 0
        while x < len(row):
            c, n = row[x], 1
            while x + n < len(row) and row[x + n] == c:
                n += 1
            if c in COLORS:
                r, g, b, _ = COLORS[c]
                rects.append(f'<rect x="{x}" y="{y}" width="{n}" height="1" fill="#{r:02x}{g:02x}{b:02x}"/>')
            x += n
    w, h = math.ceil(gw * SCALE), math.ceil(gh * SCALE)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" '
            f'viewBox="0 0 {w / SCALE:g} {h / SCALE:g}" shape-rendering="crispEdges">' + ''.join(rects) + '</svg>\n')

out = Path(__file__).resolve().parent.parent / 'public/assets/cursors'
out.mkdir(parents=True, exist_ok=True)
for name, grid in CURSORS.items():
    assert len({len(r) for r in grid}) == 1, name
    (out / f'{name}.svg').write_text(svg(grid))
    print(name, f'{math.ceil(len(grid[0]) * SCALE)}x{math.ceil(len(grid) * SCALE)}')
