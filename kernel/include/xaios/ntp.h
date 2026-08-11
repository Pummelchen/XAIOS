#ifndef XAIOS_NTP_H
#define XAIOS_NTP_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef enum xaios_ntp_state {
  XAIOS_NTP_IDLE = 0,
  XAIOS_NTP_PENDING = 1,
  XAIOS_NTP_SYNCED = 2,
  XAIOS_NTP_TIMEOUT = 3,
  XAIOS_NTP_FAILED = 4,
} xaios_ntp_state_t;

typedef struct xaios_ntp_status {
  xaios_ntp_state_t state;
  uint32_t server_ip;
  uint32_t attempts;
  uint32_t stratum;
  uint64_t last_sync_epoch_ns;
  uint64_t round_trip_ns;
  xaios_status_t last_error;
} xaios_ntp_status_t;

void ntp_init(void);
xaios_status_t ntp_sync(uint32_t server_ip);
xaios_status_t ntp_process_ipv4_frame(const uint8_t *frame,
                                      uint32_t frame_len,
                                      uint64_t now_ns);
void ntp_tick(uint64_t now_ns);
xaios_ntp_status_t ntp_status(void);
void ntp_self_test(void);

#endif
