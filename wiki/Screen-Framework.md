# Screen framework

How XAIOS puts a changing screen in front of a person without redrawing it.

## The rule

A screen is a grid of cells. A program that draws one keeps two grids: what
it wants shown and what the terminal shows. Presenting sends only the cells
that differ, positioned with cursor moves. An unchanged screen costs nothing;
a changed figure costs its own width; sixty presents a second are sixty small
writes, not sixty full frames. This is one mechanism for the whole system --
the same bytes drive an SSH client and the local framebuffer console -- and
not something each program does for itself.

Three layers carry it:

| Layer | Where | What it does |
|---|---|---|
| Library | `userspace/include/xaios_screen.h`, `userspace/lib/xaios_screen.c` | The grid, a terminal model that paints escape-coded output into it, the present that emits the difference, and a key decoder. Freestanding; the caller supplies the two grids. |
| Session filter | `userspace/sshd/ssh_channel.c` (SSH sessions), `userspace/sshd/sshd.c` (the local console) | Every program that enters the alternate screen (`ESC[?1049h`) is run through a screen the session holds, whether or not the program knows the library exists: it can write whole frames, and only the changed cells reach the terminal. Leaving the alternate screen (`ESC[?1049l`) returns the session to a plain stream. |
| Console terminal | `kernel/core/boot_ui.c` | The framebuffer terminal keeps a cell cache of its own and repaints only cells whose glyph or colour changed, presenting at most once per 16 ms. It implements cursor position, so positioned runs land where they were aimed. |

A program can be a user of the framework at either of two levels:

- **Draw whole frames and let the session filter diff them.** The built-in
  editor, pager and game do this. Nothing in them changed to gain it, and any
  future program -- an OS command, a third-party application -- gets it the
  same way, by using the alternate screen.
- **Hold a screen of its own.** `xtop` does this: it paints each rendered
  frame into its screen with `xaios_screen_paint`, presents with
  `xaios_screen_present`, and writes the result. It saves the session's
  parse, and it can send at sixty frames a second down a child channel that
  could not carry sixty whole frames.

## Pacing

Presenting is half of the cost of a live screen; waiting is the other half.
A program that polls a clock or a channel between frames spins a core. The
kernel's `xaios_wait_events(timeout_ns)` blocks until console input, activity
on a socket the process owns, or data or an exit on a child channel is
waiting, or until the timeout passes; between looks it sleeps in slices that
grow from one to eight milliseconds. `sshd`'s loop and `xtop`'s serve loop
wait on it, which is what took `sshd` from a whole core to a few percent of
one under emulation.

## What the model understands

Printable UTF-8, carriage return, line feed, backspace, tab; SGR reset, bold,
the sixteen named colours, `38;5;n` and `48;5;n`, default foreground and
background; cursor position (`H`, `f`), relative cursor moves (`A`–`D`, `G`,
`d`); erase in display (`J`) and in line (`K`); cursor show and hide
(`?25h/l`); and the alternate screen (`?1049h/l`). Other sequences are
consumed and ignored. The model does not scroll: it is for programs that draw
a screen, not for a stream, which is why the session filter engages only
inside the alternate screen.

## Evidence

- `make hosted-test` builds and runs `tests/system/test_screen.c`: a painted
  frame presents in full once and then not at all; one changed figure
  presents one positioned run; a present cut short by its buffer is finished
  by the next; resize forces a full present; multi-byte glyphs wrap; the key
  decoder reads arrows, paging, function keys and UTF-8.
- `make qemu-console-xtop-gate` (and `-x86_64`, `-riscv64`) reads the
  framebuffer back out of QEMU as pixels, decodes them through the kernel's
  own font tables, and compares the picture with one taken over SSH at the
  same size, with `xtop` running as a child of each session.

See also [Applications](Applications.md) and `docs/API.md`.
