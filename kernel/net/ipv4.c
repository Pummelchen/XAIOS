#include <xaios/assert.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/timer.h>

#define XAIOS_IPV4_FRAG_BUCKETS 8U

static ipv4_frag_bucket_t g_frag_buckets[XAIOS_IPV4_FRAG_BUCKETS];

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

static void put_be32(uint8_t *dst, uint32_t value) {
  dst[0] = (uint8_t)(value >> 24U);
  dst[1] = (uint8_t)(value >> 16U);
  dst[2] = (uint8_t)(value >> 8U);
  dst[3] = (uint8_t)value;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static uint32_t get_be32(const uint8_t *src) {
  return ((uint32_t)src[0] << 24U) | ((uint32_t)src[1] << 16U) |
         ((uint32_t)src[2] << 8U) | (uint32_t)src[3];
}

static void bytes_copy(void *dst, const void *src, uint64_t n) {
  uint8_t *d = (uint8_t *)dst;
  const uint8_t *s = (const uint8_t *)src;
  for (uint64_t i = 0; i < n; ++i) { d[i] = s[i]; }
}

static void bytes_zero(void *dst, uint64_t n) {
  uint8_t *d = (uint8_t *)dst;
  for (uint64_t i = 0; i < n; ++i) d[i] = 0U;
}

uint16_t ipv4_checksum(const uint8_t *data, uint32_t length) {
  uint64_t sum = 0;
  for (uint32_t i = 0; i + 1U < length; i += 2U) {
    sum += ((uint64_t)data[i] << 8U) | (uint64_t)data[i + 1U];
  }
  if ((length & 1U) != 0U) {
    sum += ((uint64_t)data[length - 1U] << 8U);
  }
  while ((sum >> 16U) != 0U) {
    sum = (sum & 0xFFFFU) + (sum >> 16U);
  }
  return (uint16_t)(~sum & 0xFFFFU);
}

uint16_t ipv4_pseudo_checksum(uint32_t src_ip, uint32_t dst_ip,
                               uint8_t protocol, uint16_t payload_length,
                               const uint8_t *payload, uint32_t payload_len) {
  uint64_t sum = 0;
  sum += (src_ip >> 16U) & 0xFFFFU;
  sum += src_ip & 0xFFFFU;
  sum += (dst_ip >> 16U) & 0xFFFFU;
  sum += dst_ip & 0xFFFFU;
  sum += (uint64_t)protocol;
  sum += (uint64_t)payload_length;
  for (uint32_t i = 0; i + 1U < payload_len; i += 2U) {
    sum += ((uint64_t)payload[i] << 8U) | (uint64_t)payload[i + 1U];
  }
  if ((payload_len & 1U) != 0U) {
    sum += ((uint64_t)payload[payload_len - 1U] << 8U);
  }
  while ((sum >> 16U) != 0U) {
    sum = (sum & 0xFFFFU) + (sum >> 16U);
  }
  return (uint16_t)(~sum & 0xFFFFU);
}

void ipv4_build_header(uint8_t *hdr, uint16_t total_length, uint8_t protocol,
                        uint32_t src_ip, uint32_t dst_ip) {
  if (hdr == 0) { return; }
  hdr[0] = XAIOS_IPV4_VERSION_IHL;
  hdr[1] = 0;
  put_be16(hdr + 2, total_length);
  put_be16(hdr + 4, 0);
  put_be16(hdr + 6, 0x4000);
  hdr[8] = 64;
  hdr[9] = protocol;
  put_be16(hdr + 10, 0);
  put_be32(hdr + 12, src_ip);
  put_be32(hdr + 16, dst_ip);
  uint16_t cksum = ipv4_checksum(hdr, XAIOS_IPV4_HEADER_SIZE);
  put_be16(hdr + 10, cksum);
}

int ipv4_validate_incoming(const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < 34U) { return 0; }
  const uint8_t *ip = frame + 14U;
  uint8_t version = (uint8_t)(ip[0] >> 4U);
  uint8_t ihl = (uint8_t)(ip[0] & 0x0FU);
  if (version != 4U) { return 0; }
  if (ihl < 5U) { return 0; }
  uint64_t ip_header_bytes = (uint64_t)ihl * 4U;
  uint16_t total_length = (uint16_t)(((uint16_t)ip[2] << 8U) | ip[3]);
  if ((uint64_t)total_length < ip_header_bytes) { return 0; }
  if (14U + (uint64_t)total_length > frame_len) { return 0; }
  uint8_t ttl = ip[8];
  if (ttl == 0U) { return 0; }
  if (ipv4_checksum(ip, (uint32_t)ip_header_bytes) != 0U) { return 0; }
  return 1;
}

/* Fragment an outgoing IPv4 frame into concatenated Ethernet frames. */
xaios_status_t ipv4_fragment(const uint8_t *frame, uint64_t frame_len,
                              uint8_t *out_buf, uint64_t *out_len,
                              uint64_t out_capacity) {
  if (frame == 0 || out_buf == 0 || out_len == 0 || frame_len < 34U ||
      get_be16(frame + 12U) != UINT16_C(0x0800) ||
      frame[14U] != XAIOS_IPV4_VERSION_IHL) {
    return XAIOS_ERR_INVALID;
  }

  uint16_t total_len = get_be16(frame + 16U);
  if (total_len < XAIOS_IPV4_HEADER_SIZE ||
      14U + (uint64_t)total_len > frame_len) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t payload_len = (uint64_t)total_len - XAIOS_IPV4_HEADER_SIZE;

  if (payload_len <= 1400U) {
    uint64_t exact_len = 14U + total_len;
    if (out_capacity < exact_len) return XAIOS_ERR_NO_MEMORY;
    bytes_copy(out_buf, frame, exact_len);
    *out_len = exact_len;
    return XAIOS_OK;
  }

  uint16_t id = get_be16(frame + 18U);
  uint32_t src_ip = get_be32(frame + 26U);
  uint32_t dst_ip = get_be32(frame + 30U);
  uint8_t protocol = frame[23];

  uint64_t per_frag = 1392U; /* multiple of 8, leaves room for headers */
  uint64_t offset = 0;
  uint64_t written = 0;

  while (offset < payload_len) {
    uint64_t this_frag = payload_len - offset;
    if (this_frag > per_frag) { this_frag = per_frag; }
    uint64_t frag_total = 14U + XAIOS_IPV4_HEADER_SIZE + this_frag;
    if (written + frag_total > out_capacity) { return XAIOS_ERR_NO_MEMORY; }

    bytes_copy(out_buf + written, frame, 14U);

    uint8_t *frag_ip = out_buf + written + 14U;
    bytes_copy(frag_ip, frame + 14U, XAIOS_IPV4_HEADER_SIZE);
    put_be16(frag_ip + 2, (uint16_t)(XAIOS_IPV4_HEADER_SIZE + this_frag));
    put_be16(frag_ip + 4, id);
    uint16_t off_val = (uint16_t)(offset / 8U);
    int more = (offset + this_frag < payload_len) ? 1 : 0;
    put_be16(frag_ip + 6, (uint16_t)((more ? XAIOS_IPV4_FLAG_MF : 0) | off_val));
    frag_ip[9] = protocol;
    put_be16(frag_ip + 10, 0);
    put_be32(frag_ip + 12, src_ip);
    put_be32(frag_ip + 16, dst_ip);
    uint16_t cksum = ipv4_checksum(frag_ip, XAIOS_IPV4_HEADER_SIZE);
    put_be16(frag_ip + 10, cksum);

    bytes_copy(out_buf + written + 34U,
               frame + 14U + XAIOS_IPV4_HEADER_SIZE + offset, this_frag);
    written += frag_total;
    offset += this_frag;
  }

  *out_len = written;
  return XAIOS_OK;
}

/* B1: Check if frame is a fragment (MF set or offset > 0) */
int ipv4_is_fragment(const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < 34U) { return 0; }
  uint16_t flags_off = get_be16(frame + 20);
  if ((flags_off & XAIOS_IPV4_FLAG_MF) != 0 ||
      (flags_off & XAIOS_IPV4_OFFSET_MASK) != 0) {
    return 1;
  }
  return 0;
}

static void clear_bucket(ipv4_frag_bucket_t *bucket) {
  bytes_zero(bucket, sizeof(*bucket));
}

static ipv4_frag_bucket_t *find_or_allocate_bucket(
    uint32_t src_ip, uint32_t dst_ip, uint16_t id, uint8_t protocol,
    uint64_t now_ns) {
  ipv4_frag_bucket_t *free_bucket = 0;
  ipv4_frag_bucket_t *oldest = 0;
  for (uint32_t i = 0U; i < XAIOS_IPV4_FRAG_BUCKETS; ++i) {
    ipv4_frag_bucket_t *bucket = &g_frag_buckets[i];
    if (bucket->active != 0U && now_ns != 0U &&
        now_ns - bucket->first_arrival_ns >= XAIOS_IPV4_FRAG_TIMEOUT_NS) {
      clear_bucket(bucket);
    }
    if (bucket->active != 0U && bucket->src_ip == src_ip &&
        bucket->dst_ip == dst_ip && bucket->id == id &&
        bucket->protocol == protocol) {
      return bucket;
    }
    if (bucket->active == 0U && free_bucket == 0) free_bucket = bucket;
    if (bucket->active != 0U &&
        (oldest == 0 || bucket->first_arrival_ns < oldest->first_arrival_ns)) {
      oldest = bucket;
    }
  }
  ipv4_frag_bucket_t *bucket = free_bucket != 0 ? free_bucket : oldest;
  if (bucket == 0) return 0;
  clear_bucket(bucket);
  bucket->active = 1U;
  bucket->src_ip = src_ip;
  bucket->dst_ip = dst_ip;
  bucket->id = id;
  bucket->protocol = protocol;
  bucket->first_arrival_ns = now_ns;
  return bucket;
}

/* Store one fragment and reconstruct the frame only when every byte exists. */
xaios_status_t ipv4_reassemble(uint8_t *frame, uint64_t *frame_len) {
  if (frame == 0 || frame_len == 0 || *frame_len < 34U) {
    return XAIOS_ERR_INVALID;
  }
  if (!ipv4_validate_incoming(frame, *frame_len) ||
      get_be16(frame + 12U) != UINT16_C(0x0800)) {
    return XAIOS_ERR_INVALID;
  }
  uint8_t *ip = frame + 14U;
  uint8_t ihl = (uint8_t)(ip[0] & 0x0FU);
  if (ihl != 5U) return XAIOS_ERR_UNSUPPORTED;
  uint64_t ip_hdr_bytes = (uint64_t)ihl * 4U;
  uint16_t ip_total = get_be16(ip + 2U);
  uint16_t flags_off = get_be16(ip + 6U);
  uint32_t offset = (uint32_t)(flags_off & XAIOS_IPV4_OFFSET_MASK) * 8U;
  uint32_t frag_data_len = (uint32_t)ip_total - (uint32_t)ip_hdr_bytes;
  uint32_t end = offset + frag_data_len;
  uint32_t more = (flags_off & XAIOS_IPV4_FLAG_MF) != 0U;
  if ((flags_off & XAIOS_IPV4_FLAG_DF) != 0U || frag_data_len == 0U ||
      (more != 0U && (frag_data_len & 7U) != 0U) || end < offset ||
      end > XAIOS_IPV4_MAX_REASSEMBLED_PAYLOAD) {
    return XAIOS_ERR_INVALID;
  }

  uint64_t now_ns = timer_now_ns();
  ipv4_frag_bucket_t *bucket = find_or_allocate_bucket(
      get_be32(ip + 12U), get_be32(ip + 16U), get_be16(ip + 4U), ip[9U],
      now_ns);
  if (bucket == 0) return XAIOS_ERR_NO_MEMORY;
  if (more == 0U) {
    if (bucket->total_len != 0U && bucket->total_len != end) {
      clear_bucket(bucket);
      return XAIOS_ERR_INVALID;
    }
    bucket->total_len = end;
  }
  if (bucket->total_len != 0U && end > bucket->total_len) {
    clear_bucket(bucket);
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *fragment_data = ip + ip_hdr_bytes;
  for (uint32_t i = 0U; i < frag_data_len; ++i) {
    uint32_t position = offset + i;
    if (bucket->received[position] != 0U &&
        bucket->payload[position] != fragment_data[i]) {
      clear_bucket(bucket);
      return XAIOS_ERR_INVALID;
    }
  }
  for (uint32_t i = 0U; i < frag_data_len; ++i) {
    uint32_t position = offset + i;
    if (bucket->received[position] == 0U) {
      bucket->received[position] = 1U;
      bucket->payload[position] = fragment_data[i];
      ++bucket->received_count;
    }
  }
  if (offset == 0U) {
    bytes_copy(bucket->ethernet_header, frame, 14U);
    bytes_copy(bucket->ip_header, ip, XAIOS_IPV4_HEADER_SIZE);
    bucket->have_first = 1U;
  }
  if (bucket->total_len == 0U || bucket->have_first == 0U ||
      bucket->received_count < bucket->total_len) {
    return XAIOS_ERR_BUSY;
  }
  for (uint32_t i = 0U; i < bucket->total_len; ++i) {
    if (bucket->received[i] == 0U) return XAIOS_ERR_BUSY;
  }

  bytes_copy(frame, bucket->ethernet_header, 14U);
  bytes_copy(frame + 14U, bucket->ip_header, XAIOS_IPV4_HEADER_SIZE);
  put_be16(frame + 16U,
           (uint16_t)(XAIOS_IPV4_HEADER_SIZE + bucket->total_len));
  put_be16(frame + 20U, 0U);
  put_be16(frame + 24U, 0U);
  put_be16(frame + 24U,
           ipv4_checksum(frame + 14U, XAIOS_IPV4_HEADER_SIZE));
  bytes_copy(frame + 34U, bucket->payload, bucket->total_len);
  *frame_len = 34U + bucket->total_len;
  clear_bucket(bucket);
  return XAIOS_OK;
}

void ipv4_frag_init(void) { bytes_zero(g_frag_buckets, sizeof(g_frag_buckets)); }

void ipv4_frag_self_test(void) {
  uint8_t frame[1520];
  bytes_zero(frame, sizeof(frame));
  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = (uint8_t)(0x50U + i);
    frame[6U + i] = (uint8_t)(0x20U + i);
  }
  put_be16(frame + 12U, UINT16_C(0x0800));
  const uint32_t payload_len = 1450U;
  ipv4_build_header(frame + 14U,
                    (uint16_t)(XAIOS_IPV4_HEADER_SIZE + payload_len),
                    XAIOS_IPV4_PROTO_UDP, XAIOS_IPV4_GUEST_IP,
                    XAIOS_IPV4_GATEWAY);
  put_be16(frame + 18U, UINT16_C(0x1234));
  put_be16(frame + 24U, 0U);
  put_be16(frame + 24U, ipv4_checksum(frame + 14U, XAIOS_IPV4_HEADER_SIZE));
  for (uint32_t i = 0; i < payload_len; ++i) frame[34U + i] = (uint8_t)i;
  uint64_t flen = 34U + payload_len;
  uint8_t out[4096];
  uint64_t out_len = 0;
  kassert(ipv4_fragment(frame, flen, out, &out_len, sizeof(out)) == XAIOS_OK);
  uint64_t first_len = 14U + get_be16(out + 16U);
  kassert(first_len < out_len);
  uint64_t second_len = out_len - first_len;
  uint8_t reassembled[1520];
  bytes_copy(reassembled, out + first_len, second_len);
  uint64_t reassembled_len = second_len;
  kassert(ipv4_reassemble(reassembled, &reassembled_len) == XAIOS_ERR_BUSY);
  bytes_copy(reassembled, out, first_len);
  reassembled_len = first_len;
  kassert(ipv4_reassemble(reassembled, &reassembled_len) == XAIOS_OK);
  kassert(reassembled_len == flen);
  for (uint32_t i = 0U; i < payload_len; ++i) {
    kassert(reassembled[34U + i] == (uint8_t)i);
  }
  klog("ipv4: fragmentation/reassembly self-test passed frame=%lu wire=%lu out_of_order=1\n",
       flen, out_len);
}

void ipv4_self_test(void) {
  uint8_t hdr[20];
  ipv4_build_header(hdr, 40, XAIOS_IPV4_PROTO_UDP, 0x0a00020f, 0x0a000202);
  kassert(hdr[0] == 0x45);
  kassert(hdr[8] == 64);
  kassert(hdr[9] == XAIOS_IPV4_PROTO_UDP);
  kassert(ipv4_checksum(hdr, 20) == 0);

  uint8_t payload[4] = {0x00, 0x01, 0x00, 0x02};
  uint16_t cksum = ipv4_pseudo_checksum(0x0a00020f, 0x0a000202,
                                         XAIOS_IPV4_PROTO_UDP, 4, payload, 4);
  kassert(cksum != 0);
  klog("ipv4: self-test passed header_cksum=0x%04x pseudo_cksum=0x%04x\n",
       0, cksum);
  ipv4_frag_init();
  ipv4_frag_self_test();
}
