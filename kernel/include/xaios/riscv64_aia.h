#ifndef XAIOS_RISCV64_AIA_H
#define XAIOS_RISCV64_AIA_H

#include <xaios/status.h>
#include <xaios/types.h>

/* RISC-V's Advanced Interrupt Architecture: the two controllers that make
 * message-signalled interrupts possible on this architecture at all.
 *
 * The IMSIC is the message receiver. Every hart gets a 4 KiB page of physical
 * address space per privilege level, and a device raises an interrupt on that
 * hart by writing a small integer -- the external interrupt identity -- as a
 * 32-bit word to that page. There is no translation table and no command
 * queue: the address selects the hart and the data selects the interrupt.
 * That makes it much simpler than a GIC ITS, and means the "message address"
 * and "message data" the shared MSI-X code asks for are trivially derivable
 * once the hart is known.
 *
 * The APLIC is the wire receiver. Devices that pull a line rather than write
 * a word -- the virtio-mmio transports, the UART -- are attached to it, and
 * in this configuration it forwards each of them onward as an MSI to an
 * IMSIC. So the APLIC is not an alternative to the IMSIC here; it is a
 * translator that puts wired devices on the same delivery path as PCI ones.
 *
 * Both are discovered from the device tree and neither is assumed. A board
 * that publishes a PLIC instead keeps the PLIC driver, which is what every
 * existing gate on this architecture runs on.
 */

typedef void (*riscv64_aia_handler_t)(uint32_t identifier, void *context);

/* Look for a supervisor-level IMSIC and APLIC and bring up whatever is
 * there. Returns non-zero when this hart can receive messages afterwards.
 * Safe to call on a board with neither, where it reports absence and changes
 * nothing. */
int riscv64_aia_init(const void *blob);

/* Whether message-signalled interrupts are available on this machine. */
int riscv64_aia_present(void);

/* Whether wired sources can be routed, which needs the APLIC as well. */
int riscv64_aia_wired_present(void);

/* Bring up this hart's own interrupt file. Must run on the hart it
   configures: the registers are CSRs, not memory. */
void riscv64_aia_init_hart(void);

/* Reserve an unused external interrupt identity. */
xaios_status_t riscv64_aia_allocate(uint32_t *identifier);

/* Attach a handler to an identity and enable it on the target hart's
   interrupt file. */
xaios_status_t riscv64_aia_register(uint32_t identifier, uint32_t cpu_id,
                                    riscv64_aia_handler_t handler,
                                    void *context);

xaios_status_t riscv64_aia_unregister(uint32_t identifier);

/* The address a device must write, and the word it must write there, to
   raise `identifier` on `cpu_id`. This is the whole of MSI on this
   architecture. */
xaios_status_t riscv64_aia_message_target(uint32_t identifier, uint32_t cpu_id,
                                          uint64_t *address, uint32_t *data);

/* Route a wired APLIC source to an identity on a hart. */
xaios_status_t riscv64_aia_route_wired(uint32_t source, uint32_t identifier,
                                       uint32_t cpu_id);
xaios_status_t riscv64_aia_disable_wired(uint32_t source);

/* Drain this hart's interrupt file, calling handlers. Returns how many
   messages were taken. Called from the trap handler on a supervisor external
   interrupt. */
uint32_t riscv64_aia_dispatch(void);

/* How many messages this machine has delivered since boot, and how many of
   them arrived with no handler attached. The second number is the one worth
   watching: it is what a mis-programmed target register produces. */
uint64_t riscv64_aia_delivered(void);
uint64_t riscv64_aia_spurious(void);

/* Describe what was found, and prove the receiver works by sending this hart
   a message through its own interrupt file and requiring it to arrive. */
void riscv64_aia_report(void);
void riscv64_aia_self_test(void);

#endif
