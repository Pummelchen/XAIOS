#ifndef SSHD_CONSOLE_UI_H
#define SSHD_CONSOLE_UI_H

/*
 * Declarations shared between sshd.c and sshd_console_ui.c.
 *
 * These are private to the server, like sshd_internal.h and
 * sshd_console_screen.h: sshd.h stays the public header for callers outside
 * this directory. The module is the console's presentation layer: its text
 * output, its shell and login prompts, the boot screen it paints, and the
 * pager, editor and game it runs full-screen. sshd.c keeps the console_tick()
 * hub that feeds it keystrokes, the command dispatcher and login state that
 * hub drives, and the connection state machine.
 *
 * The console state itself stays defined in sshd.c, next to console_tick(),
 * because that hub reads and writes it directly on every pass -- the command
 * buffer it edits, the program handles whose `.active` flags it tests, and the
 * frame buffer the pager and editor render into. The module reads and writes
 * the same state through the declarations below; nothing is defined twice.
 * The names keep the g_console_ prefix they already had, so what moved out of
 * sshd.c moved verbatim.
 */

#include <stdint.h>
#include <xaios_user.h>

#include "less_pager.h"
#include "nano_editor.h"
#include "pong_game.h"
#include "sshd_console_screen.h"

/* The state of the console's login. console_tick() drives the transitions; the
 * module paints the prompt for each state and decides when a shell opens. */
enum {
  SSHD_CONSOLE_AUTH_LOCKED = 0U,
  SSHD_CONSOLE_AUTH_USER = 1U,
  SSHD_CONSOLE_AUTH_PASSWORD = 2U,
  SSHD_CONSOLE_AUTH_SHELL = 3U
};

/* Defined in sshd.c and used by both sides. g_password_auth_enabled is set
 * there when the runtime configuration loads; the rest is the console state
 * the tick hub and the module share. */
extern char g_console_output[SSHD_CONSOLE_OUTPUT_MAX];
extern uint32_t g_console_ipv4;
extern uint32_t g_console_ssh_ready;
extern int32_t g_console_boot_error;
extern nano_editor_t g_console_nano;
extern pong_game_t g_console_pong;
extern less_pager_t g_console_less;
extern uint32_t g_console_auth_state;
extern uint32_t g_console_command_length;
extern uint32_t g_console_ignore_lf;
extern uint32_t g_password_auth_enabled;

/* Defined in sshd.c: the console's own session identity, the account a PIN
 * logs in as, and the two transitions console_begin_login() takes. */
void console_set_account_username(void);
const char *console_username(void);
void console_auth_succeeded(void);

/* From sshd_console_ui.c. The console's text writer, its error formatter and
 * its shell prompt; sshd_console_programs.c reaches the first and the third by
 * name through sshd_console_programs.h, which this module includes. */
void console_write(const char *text);
void console_write_error(int32_t status);
void console_prompt(void);

/* From sshd_console_ui.c: the login screen. */
void console_write_login_prompt(void);

/* From sshd_console_ui.c: the full-screen programs the command dispatcher
 * starts and console_tick() feeds. */
int console_nano_argument(const char *command, char *argument,
                          uint32_t capacity);
int console_start_less(const char *command);
void console_finish_less(void);
int console_start_nano(const char *command);
int console_render_pong(uint64_t now_ns);
int console_start_pong(void);
void console_finish_pong(void);
void console_service_pong(uint64_t now_ns);

/* From sshd_console_ui.c: the boot screen and the periodic repaint the service
 * loop asks for. */
void console_refresh_boot_ui(uint64_t now_ns);
void console_render_boot_status(void);
void console_render_ssh_loading(void);

#endif /* SSHD_CONSOLE_UI_H */
