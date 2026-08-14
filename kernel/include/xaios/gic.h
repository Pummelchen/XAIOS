#ifndef XAIOS_GIC_H
#define XAIOS_GIC_H

#include <xaios/types.h>
#include <xaios/status.h>

typedef void (*xaios_irq_handler_t)(uint32_t intid, void *context);

typedef struct xaios_gic_info {
  uint64_t distributor_base;
  uint32_t typer;
  uint32_t iidr;
  uint32_t interrupt_lines;
  uint32_t cpu_count_hint;
} xaios_gic_info_t;

void gic_init_qemu_virt(void);
void gic_enable_full(void);
void gic_disable_full(void);
void gic_secondary_init(uint32_t cpu_id);
xaios_status_t gic_register_interrupt(uint32_t intid,
                                      xaios_irq_handler_t handler,
                                      void *context);
xaios_status_t gic_register_lpi(uint32_t intid, uint32_t cpu_id,
                               xaios_irq_handler_t handler, void *context);
xaios_status_t gic_unregister_interrupt(uint32_t intid,
                                        xaios_irq_handler_t handler,
                                        void *context);
xaios_status_t gic_route_interrupt(uint32_t intid, uint32_t cpu_id);
int gic_dispatch_interrupt(uint32_t intid);
const xaios_gic_info_t *gic_info(void);
void gic_self_test(void);
xaios_status_t gic_its_configure_msi(uint32_t device_id, uint32_t event_id,
                                     uint32_t intid, uint32_t cpu_id,
                                     uint64_t *message_address,
                                     uint32_t *message_data);
int gic_its_available(void);

#endif
