#!/usr/bin/env python3
# The terminal-replay half of the QEMU gate helper, split out of qemu_gate_lib
# so that the shared helper stays under the repository's 500-line limit. The
# gates still import render_terminal and render_terminal_frames from
# qemu_gate_lib, which re-exports them.
from __future__ import annotations

from typing import List


# ------------------------------------------------------- reading a screen
#
# What a full-screen program sent, as what it put on the screen.
#
# Gates used to read these streams as teletype transcripts: strip the escapes,
# split on newlines, and look at the lines. That worked while programs redrew
# by printing whole frames. It stopped working when drawing moved into the
# screen framework, which sends only the cells that changed and moves the
# cursor between them -- there are no newlines to split on any more, a line of
# text can arrive in three pieces, and a substring that is plainly on the
# screen is not in the stream. Two checks in the external client suite went
# red for exactly that and stayed red because nothing had run them.
#
# So the stream is replayed into a grid instead, which is what the terminal on
# the other end does. Only what these programs actually use is implemented:
# absolute cursor moves, erase display and line, carriage return and line
# feed, and enough of the private modes to ignore them. Colours are dropped --
# a gate that wants a colour should look for its escape in the bytes, which is
# unambiguous; a gate that wants text should look at the screen.

def render_terminal_frames(data: bytes, columns: int = 240,
                           rows: int = 80) -> List[List[str]]:
    """Every screen this stream showed, in order.

    A frame ends where the program clears the display and starts another, and
    the last one is whatever was on screen when the stream stopped. A gate
    asking "did this ever appear" needs all of them: the final screen of a
    program that was asked to show its help and then hide it again is the one
    without the help on it.
    """
    frames: List[List[str]] = []
    _replay(data, columns, rows, frames)
    return frames


def render_terminal(data: bytes, columns: int = 240, rows: int = 80) -> List[str]:
    """Replay a terminal byte stream and return the rows it leaves on screen."""
    frames = render_terminal_frames(data, columns, rows)
    return frames[-1] if frames else []


def _replay(data: bytes, columns: int, rows: int,
            frames: List[List[str]]) -> None:
    grid = [[" "] * columns for _ in range(rows)]
    row = 0
    column = 0
    index = 0
    length = len(data)
    text = data.decode("utf-8", "replace")
    length = len(text)
    while index < length:
        character = text[index]
        if character == "\x1b" and index + 1 < length and text[index + 1] == "[":
            end = index + 2
            while end < length and text[end] not in "@ABCDEFGHJKSTfhilmnrst":
                end += 1
            if end >= length:
                break
            body = text[index + 2:end]
            final = text[end]
            index = end + 1
            if body.startswith("?"):
                continue  # private modes: alternate screen, cursor visibility
            parts = [int(p) if p.isdigit() else 0 for p in body.split(";")] or [0]
            if final in "Hf":
                row = max(0, (parts[0] if parts and parts[0] else 1) - 1)
                column = max(0, (parts[1] if len(parts) > 1 and parts[1] else 1) - 1)
            elif final == "J":
                mode = parts[0] if parts else 0
                if mode == 2:
                    frames.append(["".join(line).rstrip() for line in grid])
                    grid = [[" "] * columns for _ in range(rows)]
                    row = column = 0
                elif mode == 0:
                    for c in range(column, columns):
                        grid[row][c] = " "
                    for r in range(row + 1, rows):
                        grid[r] = [" "] * columns
            elif final == "K":
                mode = parts[0] if parts else 0
                start = column if mode == 0 else 0
                stop = columns if mode in (0, 2) else column + 1
                for c in range(start, min(stop, columns)):
                    grid[row][c] = " "
            elif final == "A":
                row = max(0, row - max(1, parts[0]))
            elif final == "B":
                row = min(rows - 1, row + max(1, parts[0]))
            elif final == "C":
                column = min(columns - 1, column + max(1, parts[0]))
            elif final == "D":
                column = max(0, column - max(1, parts[0]))
            continue
        index += 1
        if character == "\r":
            column = 0
        elif character == "\n":
            row = min(rows - 1, row + 1)
        elif character == "\b":
            column = max(0, column - 1)
        elif character in ("\x1b", "\x07"):
            continue
        else:
            if 0 <= row < rows and 0 <= column < columns:
                grid[row][column] = character
            column += 1
            if column >= columns:
                column = columns - 1
    frames.append(["".join(line).rstrip() for line in grid])
