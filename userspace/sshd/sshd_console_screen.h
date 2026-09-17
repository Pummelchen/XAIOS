#ifndef SSHD_CONSOLE_SCREEN_H
#define SSHD_CONSOLE_SCREEN_H

/*
 * Declarations shared between sshd.c and sshd_console_screen.c.
 *
 * These are private to the server, like sshd_internal.h: sshd.h stays the
 * public header for callers outside this directory. The screen itself and the
 * bytes that drive it live in sshd_console_screen.c; sshd.c keeps only the
 * thin console_write() wrapper over the byte writer below.
 */

#include <stdint.h>
#include <xaios_user.h>

/*
 * The frame the local console can hold, and one kernel write of it.
 *
 * SSHD_CONSOLE_OUTPUT_MAX sizes both sshd.c's g_console_output, which the
 * pager, the editor and the game render into, and the screen module's input
 * buffer, so it is shared here rather than owned by either side.
 */
#define SSHD_CONSOLE_OUTPUT_MAX UINT32_C(32768)
#define SSHD_CONSOLE_WRITE_MAX UINT32_C(4096)

/* The console's geometry, asked of the kernel and clamped to the largest
   screen the framework models. */
uint32_t sshd_console_columns(void);
uint32_t sshd_console_rows(void);

/* Write console bytes through the screen filter.
 *
 * Entering the alternate screen turns the filter on, leaving it turns the
 * filter off; everything between is painted into the grid and only the cells
 * that changed are written to the kernel, which keeps a cell cache of its
 * own. Returns 0, or -1 when a kernel write fails. */
int sshd_console_write_bytes(const char *text, u64 size);

#endif /* SSHD_CONSOLE_SCREEN_H */
