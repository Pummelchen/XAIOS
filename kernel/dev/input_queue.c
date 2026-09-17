/*
 * The console input queue, its lock and the HID keyboard keymap. See
 * input_internal.h for how this unit sits beside input.c.
 *
 * This unit answers the console: serial and USB HID both drain through the
 * same byte queue, so the ordering the console gate observes is the order
 * queue_byte committed the bytes in. It touches no MMIO; input.c's poll hands
 * it one HID report at a time through input_process_report.
 */

#include <xaios/assert.h>
#include <xaios/input.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>

#include "input_internal.h"

#define INPUT_QUEUE_SIZE 128U

static uint8_t g_queue[INPUT_QUEUE_SIZE];
static uint32_t g_queue_head;
static uint32_t g_queue_tail;
static xaios_spinlock_t g_input_lock = XAIOS_SPINLOCK_INIT;

static void queue_byte(uint8_t value) {
  xaios_spin_lock(&g_input_lock);
  uint32_t next = (g_queue_head + 1U) % INPUT_QUEUE_SIZE;
  if (next != g_queue_tail) {
    g_queue[g_queue_head] = value;
    g_queue_head = next;
  }
  xaios_spin_unlock(&g_input_lock);
}
static int usage_was_pressed(const uint8_t report[8], uint8_t usage) {
  for (uint32_t i = 2U; i < 8U; ++i) if (report[i] == usage) return 1;
  return 0;
}
static void queue_escape(uint8_t code) {
  queue_byte(UINT8_C(0x1b));
  queue_byte('[');
  queue_byte(code);
}
static void translate_usage(uint8_t modifiers, uint8_t usage) {
  int shift = (modifiers & UINT8_C(0x22)) != 0U;
  if (usage >= 4U && usage <= 29U) {
    queue_byte((uint8_t)((shift ? 'A' : 'a') + usage - 4U));
    return;
  }
  if (usage >= 30U && usage <= 38U) {
    static const char shifted[] = ")!@#$%^&*(";
    queue_byte((uint8_t)(shift ? shifted[usage - 30U] : '1' + usage - 30U));
    return;
  }
  switch (usage) {
  case 39U: queue_byte(shift ? '(' : '0'); break;
  case 40U: queue_byte('\n'); break;
  case 42U: queue_byte('\b'); break;
  case 43U: queue_byte('\t'); break;
  case 44U: queue_byte(' '); break;
  case 45U: queue_byte(shift ? '_' : '-'); break;
  case 46U: queue_byte(shift ? '+' : '='); break;
  case 47U: queue_byte(shift ? '{' : '['); break;
  case 48U: queue_byte(shift ? '}' : ']'); break;
  case 49U: queue_byte(shift ? '|' : '\\'); break;
  case 51U: queue_byte(shift ? ':' : ';'); break;
  case 52U: queue_byte(shift ? '"' : '\''); break;
  case 53U: queue_byte(shift ? '~' : '`'); break;
  case 54U: queue_byte(shift ? '<' : ','); break;
  case 55U: queue_byte(shift ? '>' : '.'); break;
  case 56U: queue_byte(shift ? '?' : '/'); break;
  case 79U: queue_escape('C'); break;
  case 80U: queue_escape('D'); break;
  case 81U: queue_escape('B'); break;
  case 82U: queue_escape('A'); break;
  default: break;
  }
}
void input_process_report(const uint8_t report[8], uint8_t previous[8]) {
  if (report[2] == 1U) return; /* HID rollover error */
  for (uint32_t i = 2U; i < 8U; ++i) {
    uint8_t usage = report[i];
    if (usage != 0U && !usage_was_pressed(previous, usage)) {
      translate_usage(report[0], usage);
    }
  }
  for (uint32_t i = 0U; i < 8U; ++i) previous[i] = report[i];
}

int input_read_char(uint8_t *value) {
  if (value == 0) return 0;
  input_poll();
  xaios_spin_lock(&g_input_lock);
  if (g_queue_tail == g_queue_head) {
    xaios_spin_unlock(&g_input_lock);
    return 0;
  }
  *value = g_queue[g_queue_tail];
  g_queue_tail = (g_queue_tail + 1U) % INPUT_QUEUE_SIZE;
  xaios_spin_unlock(&g_input_lock);
  return 1;
}
int input_pending(void) {
  input_poll();
  xaios_spin_lock(&g_input_lock);
  int pending = g_queue_tail != g_queue_head;
  xaios_spin_unlock(&g_input_lock);
  return pending;
}

void input_self_test(void) {
  uint32_t old_head = g_queue_head;
  uint32_t old_tail = g_queue_tail;
  g_queue_head = 0U;
  g_queue_tail = 0U;
  translate_usage(0U, 4U);
  uint8_t value = 0U;
  kassert(input_read_char(&value) == 1 && value == 'a');
  translate_usage(UINT8_C(0x02), 4U);
  kassert(input_read_char(&value) == 1 && value == 'A');
  translate_usage(0U, 82U);
  kassert(input_read_char(&value) == 1 && value == UINT8_C(0x1b));
  kassert(input_read_char(&value) == 1 && value == '[');
  kassert(input_read_char(&value) == 1 && value == 'A');
  g_queue_head = old_head;
  g_queue_tail = old_tail;
  klog("input: keyboard translation self-test passed\n");
}
