#!/usr/bin/env python3
"""The picture: the kernel's font, a decoded screendump, a terminal model.

Moved verbatim out of `qemu-console-xtop-gate.py` so the gate and its session
helper share one copy of it. This half is everything that says what the screen
*is*: the glyph tables and geometry parsed out of the kernel's own boot_ui.c,
the PPM screendump decoded through them, and the terminal model an SSH client's
bytes are laid out into. None of it talks to a machine.

The repository root lives here because the gate and both helpers need it, and
the palette lives here because this half is what reads pixels.
"""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

# term_default_background() in boot_ui.c, and two xterm-256 shades xtop asks
# for by index: 24 behind the title, 238 behind the process table header.
DEFAULT_BACKGROUND = (4, 6, 10)
# xtop's field is xterm colour 68 and its header bar and gauge fill are 70;
# both are extended-colour backgrounds, which is the parsing this pins down.
FIELD_BACKGROUND = (95, 135, 215)
HEADER_BACKGROUND = (95, 175, 0)


# ---------------------------------------------------------------- font tables

def parse_font() -> tuple[dict[tuple[int, ...], str], dict[str, int]]:
    """The glyphs and the geometry, read out of the kernel source.

    Copying either into this file would let the two drift apart and leave the
    gate testing its own copy rather than the console.
    """
    source = (ROOT / "kernel" / "core" / "boot_ui.c").read_text()

    table = source[source.index("g_font[UINT32_C("):]
    table = table[: table.index("\n};")]
    glyphs: dict[tuple[int, ...], str] = {}
    rows = re.findall(r"\{((?:0x[0-9a-fA-F]{2},\s*){7}0x[0-9a-fA-F]{2})\}", table)
    if len(rows) != 96:
        raise RuntimeError(f"expected 96 ASCII glyphs, parsed {len(rows)}")
    for index, row in enumerate(rows):
        values = tuple(int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", row))
        glyphs.setdefault(values, chr(0x20 + index))

    extra = source[source.index("g_font_extra[] = {"):]
    extra = extra[: extra.index("\n};")]
    for match in re.finditer(
        r"\{0x([0-9a-fA-F]{4})U,\s*\{((?:0x[0-9a-fA-F]{2},\s*){7}0x[0-9a-fA-F]{2})\}\}",
        extra,
    ):
        values = tuple(
            int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", match.group(2))
        )
        glyphs.setdefault(values, chr(int(match.group(1), 16)))

    def constant(name: str) -> int:
        match = re.search(rf"#define {name} UINT32_C\((\d+)\)", source)
        if match is None:
            raise RuntimeError(f"{name} not found in boot_ui.c")
        return int(match.group(1))

    geometry = {
        "width": constant("FB_GLYPH_WIDTH"),
        "height": constant("FB_GLYPH_HEIGHT"),
        "margin_x": constant("TERM_MARGIN_X"),
        "margin_y": constant("TERM_MARGIN_Y"),
    }
    return glyphs, geometry


def scale_geometry(geometry: dict[str, int], framebuffer_width: int) -> dict[str, int]:
    """Glyph geometry follows the display mode, so it is known only once the
    screen has been read back. The arithmetic is boot_ui.c's own."""
    scale = min(max(framebuffer_width // 1024, 1), 3)
    scaled = dict(geometry)
    scaled["x_scale"] = scale
    scaled["y_scale"] = scale * 2
    scaled["advance"] = (geometry["width"] + 1) * scale
    scaled["line_height"] = geometry["height"] * scaled["y_scale"] + 2
    return scaled


# ------------------------------------------------------------------- decoding

class Screen:
    def __init__(self, path: Path, glyphs, geometry) -> None:
        data = path.read_bytes()
        if not data.startswith(b"P6"):
            raise RuntimeError(f"{path} is not a binary PPM")
        header = data.split(b"\n", 3)
        self.width, self.height = (int(v) for v in header[1].split())
        self.pixels = header[3]
        self.glyphs = glyphs
        geometry = scale_geometry(geometry, self.width)
        self.geometry = geometry
        self.columns = (self.width - 2 * geometry["margin_x"]) // geometry["advance"]
        self.rows = (self.height - 2 * geometry["margin_y"]) // geometry["line_height"]
        self.lines = [self._decode_row(row) for row in range(self.rows)]

    def pixel(self, x: int, y: int) -> tuple[int, int, int]:
        offset = (y * self.width + x) * 3
        return (self.pixels[offset], self.pixels[offset + 1], self.pixels[offset + 2])

    def _cell(self, column: int, row: int) -> list[tuple[int, int, int]]:
        g = self.geometry
        x0 = g["margin_x"] + column * g["advance"]
        y0 = g["margin_y"] + row * g["line_height"]
        return [
            self.pixel(x0 + gx * g["x_scale"], y0 + gy * g["y_scale"])
            for gy in range(g["height"])
            for gx in range(g["width"])
        ]

    def cell_background(self, column: int, row: int) -> tuple[int, int, int]:
        """The colour the cell was cleared to before its glyph was drawn.

        Every cell is cleared first, so whichever colour is furthest from the
        drawn strokes is the background; taking the most common colour is wrong
        for a solid block and right for everything else, so the row's own
        background is used as the tie-breaker.
        """
        colors = self._cell(column, row)
        if len(set(colors)) == 1:
            return colors[0]
        counted: dict[tuple[int, int, int], int] = {}
        for color in colors:
            counted[color] = counted.get(color, 0) + 1
        return max(counted.items(), key=lambda item: item[1])[0]

    def _row_background(self, row: int) -> tuple[int, int, int]:
        """The colour most of the row's blank cells were cleared to.

        A row is usually text on one background, so the commonest colour among
        its uniform cells is that background. Taking the rightmost blank cell
        instead breaks on a title bar that stops one cell short of the edge:
        every painted cell then differs from the "background" and reads as a
        solid block.
        """
        counted: dict[tuple[int, int, int], int] = {}
        for column in range(self.columns):
            colors = self._cell(column, row)
            if len(set(colors)) == 1:
                counted[colors[0]] = counted.get(colors[0], 0) + 1
        if not counted:
            return self.cell_background(self.columns - 1, row)
        return max(counted.items(), key=lambda item: item[1])[0]

    def _bits(self, colors, background) -> tuple[int, ...]:
        g = self.geometry
        bits = []
        for gy in range(g["height"]):
            value = 0
            for gx in range(g["width"]):
                if colors[gy * g["width"] + gx] != background:
                    value |= 1 << gx
            bits.append(value)
        return tuple(bits)

    def _decode_row(self, row: int) -> str:
        """Each cell is a glyph in one colour on a background in another.

        Which of a cell's two colours is the background is not always the
        row's: a footer paints its keys on cyan and their labels on green in
        the same row. So a two-colour cell is read both ways and the reading
        that is a glyph wins; a cell in one colour is blank unless that colour
        is a foreground painted edge to edge, which is what a full block is.
        """
        row_background = self._row_background(row)
        blank = (0,) * self.geometry["height"]
        text = ""
        for column in range(self.columns):
            colors = self._cell(column, row)
            distinct = set(colors)
            if len(distinct) == 1:
                color = colors[0]
                # The field, the row's own background and the screen's are
                # backgrounds wherever they appear; a solid run in any other
                # colour is a bar, which a row full of bar must not turn
                # into "background" for the blanks beside it.
                if color in (row_background, DEFAULT_BACKGROUND, FIELD_BACKGROUND):
                    text += " "
                else:
                    text += self.glyphs.get(self._bits(colors, None), "�")
                continue
            candidates = [c for c in (FIELD_BACKGROUND, row_background) if c in distinct]
            candidates += [c for c in distinct if c not in candidates]
            glyph = None
            for background in candidates:
                key = self._bits(colors, background)
                if key != blank and key in self.glyphs:
                    glyph = self.glyphs[key]
                    break
            text += glyph if glyph is not None else "�"
        return text.rstrip()


# --------------------------------------------------------- terminal model

def render_terminal(data: bytes, columns: int) -> list[str]:
    """What a terminal of this width shows for these bytes.

    An SSH client's terminal wraps at the last column exactly as the
    framebuffer terminal does, so the bytes have to be laid out before they
    can be compared with pixels: a line one column too wide is a line and a
    blank line on both, and stripping the escapes without wrapping would hide
    that on one side only.
    """
    text = data.decode("utf-8", errors="replace")
    lines: list[list[str]] = [[]]
    column = 0
    current_row = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\x1b":
            match = re.match(r"\x1b\[([0-9;?]*)([A-Za-z])", text[index:])
            if match:
                index += len(match.group(0))
                params, final = match.group(1), match.group(2)
                if final == "H":
                    # Cursor position: a partial update lands here. The
                    # monitor sends only the cells that changed, so the
                    # screen is the result of every update applied in order.
                    numbers = [int(n) if n else 1 for n in params.split(";")] if params else [1]
                    row = max(numbers[0], 1) - 1
                    column = max(numbers[1], 1) - 1 if len(numbers) > 1 else 0
                    while len(lines) <= row:
                        lines.append([])
                    current_row = row
                elif final == "J":
                    lines[:] = [[]]
                    current_row = 0
                    column = 0
                continue
            index += 1
            continue
        index += 1
        if char == "\r":
            column = 0
            continue
        if char == "\n":
            current_row += 1
            while len(lines) <= current_row:
                lines.append([])
            column = 0
            continue
        if column >= columns:
            current_row += 1
            while len(lines) <= current_row:
                lines.append([])
            column = 0
        row = lines[current_row]
        while len(row) <= column:
            row.append(" ")
        row[column] = char
        column += 1
    return ["".join(row).rstrip() for row in lines]
