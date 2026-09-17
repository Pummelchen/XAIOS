#include <xaios/ipv6.h>
#include <xaios/timer.h>

#include "ipv6_internal.h"

#define XAIOS_IPV6_FRAG_BUCKETS 8U

typedef struct ipv6_frag_bucket {
  uint32_t active;
  uint32_t identification;
  uint8_t next_header;
  uint8_t have_first;
  uint16_t reserved;
  uint64_t first_arrival_ns;
  uint32_t total_len;
  uint32_t received_count;
  uint8_t source[16];
  uint8_t destination[16];
  uint8_t ethernet_header[14];
  uint8_t ipv6_header[XAIOS_IPV6_HEADER_SIZE];
  uint8_t payload[XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD];
  uint8_t received[XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD];
} ipv6_frag_bucket_t;

static ipv6_frag_bucket_t g_ipv6_frag_buckets[XAIOS_IPV6_FRAG_BUCKETS];
static uint32_t g_ipv6_fragment_identification = 1U;

/* ---- C1: IPv6 Extension Header Parsing ---- */
/*
 * Walk the IPv6 extension header chain starting at ip6_hdr (which must
 * point to the fixed 40-byte IPv6 header). The chain begins at offset 40.
 *
 * Returns 0 on success with out_next_hdr set to the final (non-extension)
 *   protocol number and out_upper_layer pointing to the start of that
 *   upper-layer payload.
 * Returns -1 on any parse error (truncated packet, unsupported extension, etc.).
 */
int ipv6_walk_extension_headers(const uint8_t *ip6_hdr, uint64_t hdr_len,
                                 uint8_t *out_next_hdr,
                                 const uint8_t **out_upper_layer,
                                 uint32_t *out_upper_len) {
  if (ip6_hdr == 0 || hdr_len < XAIOS_IPV6_HEADER_SIZE ||
      out_next_hdr == 0 || out_upper_layer == 0) {
    return -1;
  }

  uint64_t offset = XAIOS_IPV6_HEADER_SIZE; /* 40 bytes past the fixed header */
  uint8_t next_hdr = ip6_hdr[6];            /* first extension or transport */

  for (uint32_t depth = 0; depth < XAIOS_IPV6_MAX_EXTENSION_CHAIN_DEPTH; ++depth) {
    /* Check if we have found the real upper-layer protocol */
    if (next_hdr != XAIOS_IPV6_NEXT_HOP_BY_HOP &&
        next_hdr != XAIOS_IPV6_NEXT_ROUTING &&
        next_hdr != XAIOS_IPV6_NEXT_FRAGMENT &&
        next_hdr != XAIOS_IPV6_NEXT_AH &&
        next_hdr != XAIOS_IPV6_NEXT_ESP &&
        next_hdr != XAIOS_IPV6_NEXT_DEST) {
      /* Not an extension header — this is the upper layer protocol */
      if (offset > hdr_len) {
        return -1;
      }
      *out_next_hdr = next_hdr;
      *out_upper_layer = ip6_hdr + offset;
      if (out_upper_len != 0) {
        *out_upper_len = (uint32_t)(hdr_len - offset);
      }
      return 0;
    }

    /* Ensure we can read at least 2 bytes of the current extension header */
    if (offset + 2 > hdr_len) {
      return -1;
    }

    uint8_t ext_next    = ip6_hdr[offset];     /* next header after this ext */
    uint8_t ext_len_byte = ip6_hdr[offset + 1]; /* length field */
    uint64_t ext_size = 0;

    if (next_hdr == XAIOS_IPV6_NEXT_FRAGMENT) {
      /* Fragment header: always 8 bytes */
      ext_size = XAIOS_IPV6_FRAG_HEADER_SIZE;
    } else if (next_hdr == XAIOS_IPV6_NEXT_AH) {
      /* AH (RFC 4302): Payload_Len = total/4 - 2 */
      ext_size = (uint64_t)(ext_len_byte + 2) * 4;
    } else if (next_hdr == XAIOS_IPV6_NEXT_ESP) {
      /* ESP (RFC 4303): no parseable length; cannot skip without decrypting */
      return -1;
    } else {
      /* Hop-by-Hop (0), Routing (43), Destination (60):
       * Hdr Ext Len in 8-octet units, not counting first 8 octets.
       * Total = (ext_len_byte + 1) * 8 */
      ext_size = (uint64_t)(ext_len_byte + 1) * 8;
    }

    if (offset + ext_size > hdr_len || ext_size == 0) {
      return -1; /* truncated or invalid */
    }

    offset += ext_size;
    next_hdr = ext_next; /* next header comes from the extension's own first byte */
  }

  return -1; /* exceeded max extension chain depth */
}

/* ---- C2: IPv6 Fragmentation ---- */
int ipv6_is_fragment_v6(const uint8_t *frame, uint64_t frame_len) {
  if (frame == 0 || frame_len < XAIOS_IPV6_HEADER_SIZE + 14U) {
    return 0;
  }
  /* Check ethertype */
  if (ipv6_get_be16(frame + 12) != XAIOS_IPV6_ETHERTYPE) {
    return 0;
  }
  const uint8_t *ip6 = frame + 14;
  uint64_t ip6_len = frame_len - 14;
  if (ip6_len < XAIOS_IPV6_HEADER_SIZE) {
    return 0;
  }
  uint8_t nh = ip6[6];
  uint64_t offset = XAIOS_IPV6_HEADER_SIZE;

  for (uint32_t depth = 0; depth < XAIOS_IPV6_MAX_EXTENSION_CHAIN_DEPTH; ++depth) {
    if (nh == XAIOS_IPV6_NEXT_FRAGMENT) {
      return 1; /* found fragment header */
    }
    if (nh != XAIOS_IPV6_NEXT_HOP_BY_HOP && nh != XAIOS_IPV6_NEXT_ROUTING &&
        nh != XAIOS_IPV6_NEXT_AH && nh != XAIOS_IPV6_NEXT_ESP &&
        nh != XAIOS_IPV6_NEXT_DEST) {
      return 0; /* no fragment header in chain */
    }
    if (offset + 2 > ip6_len) return 0;

    uint8_t ext_next = ip6[offset];
    uint8_t ext_len  = ip6[offset + 1];
    uint64_t skip;

    if (nh == XAIOS_IPV6_NEXT_AH) {
      skip = (uint64_t)(ext_len + 2) * 4;
    } else if (nh == XAIOS_IPV6_NEXT_ESP) {
      return 0; /* can't parse through ESP */
    } else {
      skip = (uint64_t)(ext_len + 1) * 8;
    }
    if (offset + skip > ip6_len) return 0;
    offset += skip;
    nh = ext_next;
  }
  return 0;
}

xaios_status_t ipv6_fragment_v6(const uint8_t *frame, uint64_t frame_len,
                                 uint8_t *out_buf, uint64_t *out_len,
                                 uint64_t out_capacity) {
  if (frame == 0 || out_buf == 0 || out_len == 0 || frame_len < 54U ||
      ipv6_get_be16(frame + 12U) != XAIOS_IPV6_ETHERTYPE ||
      (frame[14U] >> 4U) != 6U) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *ip6 = frame + 14U;
  uint16_t payload_len = ipv6_get_be16(ip6 + 4U);
  uint64_t exact_len = 14U + XAIOS_IPV6_HEADER_SIZE + payload_len;
  if (exact_len > frame_len ||
      payload_len > XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD) {
    return XAIOS_ERR_INVALID;
  }
  const uint32_t fragment_payload =
      XAIOS_IPV6_MIN_MTU - XAIOS_IPV6_HEADER_SIZE -
      XAIOS_IPV6_FRAG_HEADER_SIZE;
  if (payload_len <= fragment_payload) {
    if (out_capacity < exact_len) return XAIOS_ERR_NO_MEMORY;
    ipv6_bytes_copy(out_buf, frame, exact_len);
    *out_len = exact_len;
    return XAIOS_OK;
  }
  if (ip6[6U] == XAIOS_IPV6_NEXT_FRAGMENT) return XAIOS_ERR_INVALID;

  uint32_t identification =
      __atomic_fetch_add(&g_ipv6_fragment_identification, 1U,
                         __ATOMIC_RELAXED);
  if (identification == 0U) {
    identification = __atomic_fetch_add(&g_ipv6_fragment_identification, 1U,
                                         __ATOMIC_RELAXED);
  }
  uint64_t written = 0U;
  uint32_t offset = 0U;
  while (offset < payload_len) {
    uint32_t chunk = payload_len - offset;
    if (chunk > fragment_payload) chunk = fragment_payload;
    uint32_t more = offset + chunk < payload_len;
    uint64_t frame_bytes = 14U + XAIOS_IPV6_HEADER_SIZE +
                           XAIOS_IPV6_FRAG_HEADER_SIZE + chunk;
    if (written + frame_bytes > out_capacity) return XAIOS_ERR_NO_MEMORY;
    ipv6_bytes_copy(out_buf + written, frame, 14U + XAIOS_IPV6_HEADER_SIZE);
    uint8_t *fragment_ip6 = out_buf + written + 14U;
    ipv6_put_be16(fragment_ip6 + 4U,
             (uint16_t)(XAIOS_IPV6_FRAG_HEADER_SIZE + chunk));
    fragment_ip6[6U] = XAIOS_IPV6_NEXT_FRAGMENT;
    uint8_t *fragment_header = fragment_ip6 + XAIOS_IPV6_HEADER_SIZE;
    fragment_header[0] = ip6[6U];
    fragment_header[1] = 0U;
    ipv6_put_be16(fragment_header + 2U,
             (uint16_t)((offset & UINT32_C(0xfff8)) | more));
    ipv6_put_be32(fragment_header + 4U, identification);
    ipv6_bytes_copy(fragment_header + XAIOS_IPV6_FRAG_HEADER_SIZE,
               ip6 + XAIOS_IPV6_HEADER_SIZE + offset, chunk);
    written += frame_bytes;
    offset += chunk;
  }
  *out_len = written;
  return XAIOS_OK;
}

static int ipv6_address_equal_raw(const uint8_t *left, const uint8_t *right) {
  for (uint32_t i = 0U; i < 16U; ++i) {
    if (left[i] != right[i]) return 0;
  }
  return 1;
}

static void clear_ipv6_bucket(ipv6_frag_bucket_t *bucket) {
  ipv6_bytes_zero(bucket, sizeof(*bucket));
}

static ipv6_frag_bucket_t *find_or_allocate_ipv6_bucket(
    const uint8_t source[16], const uint8_t destination[16],
    uint32_t identification, uint8_t next_header, uint64_t now_ns) {
  ipv6_frag_bucket_t *free_bucket = 0;
  ipv6_frag_bucket_t *oldest = 0;
  for (uint32_t i = 0U; i < XAIOS_IPV6_FRAG_BUCKETS; ++i) {
    ipv6_frag_bucket_t *bucket = &g_ipv6_frag_buckets[i];
    if (bucket->active != 0U && now_ns != 0U &&
        now_ns - bucket->first_arrival_ns >= XAIOS_IPV6_FRAG_TIMEOUT_NS) {
      clear_ipv6_bucket(bucket);
    }
    if (bucket->active != 0U &&
        bucket->identification == identification &&
        bucket->next_header == next_header &&
        ipv6_address_equal_raw(bucket->source, source) &&
        ipv6_address_equal_raw(bucket->destination, destination)) {
      return bucket;
    }
    if (bucket->active == 0U && free_bucket == 0) free_bucket = bucket;
    if (bucket->active != 0U &&
        (oldest == 0 || bucket->first_arrival_ns < oldest->first_arrival_ns)) {
      oldest = bucket;
    }
  }
  ipv6_frag_bucket_t *bucket = free_bucket != 0 ? free_bucket : oldest;
  if (bucket == 0) return 0;
  clear_ipv6_bucket(bucket);
  bucket->active = 1U;
  bucket->identification = identification;
  bucket->next_header = next_header;
  bucket->first_arrival_ns = now_ns;
  ipv6_bytes_copy(bucket->source, source, 16U);
  ipv6_bytes_copy(bucket->destination, destination, 16U);
  return bucket;
}

xaios_status_t ipv6_reassemble_v6(uint8_t *frame, uint64_t *frame_len) {
  if (frame == 0 || frame_len == 0 || *frame_len < 54U ||
      ipv6_get_be16(frame + 12U) != XAIOS_IPV6_ETHERTYPE ||
      (frame[14U] >> 4U) != 6U) {
    return XAIOS_ERR_INVALID;
  }
  if (!ipv6_is_fragment_v6(frame, *frame_len)) return XAIOS_OK;
  uint8_t *ip6 = frame + 14U;
  if (ip6[6U] != XAIOS_IPV6_NEXT_FRAGMENT) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint16_t payload_len = ipv6_get_be16(ip6 + 4U);
  if (payload_len < XAIOS_IPV6_FRAG_HEADER_SIZE ||
      14U + XAIOS_IPV6_HEADER_SIZE + payload_len > *frame_len) {
    return XAIOS_ERR_INVALID;
  }
  uint8_t *fh = ip6 + XAIOS_IPV6_HEADER_SIZE;
  uint16_t offset_flags = ipv6_get_be16(fh + 2U);
  uint32_t offset = offset_flags & UINT16_C(0xfff8);
  uint32_t more = offset_flags & 1U;
  uint32_t fragment_len = payload_len - XAIOS_IPV6_FRAG_HEADER_SIZE;
  uint32_t end = offset + fragment_len;
  if ((offset_flags & UINT16_C(0x0006)) != 0U || fragment_len == 0U ||
      (more != 0U && (fragment_len & 7U) != 0U) || end < offset ||
      end > XAIOS_IPV6_MAX_REASSEMBLED_PAYLOAD) {
    return XAIOS_ERR_INVALID;
  }

  ipv6_frag_bucket_t *bucket = find_or_allocate_ipv6_bucket(
      ip6 + 8U, ip6 + 24U, ipv6_get_be32(fh + 4U), fh[0], timer_now_ns());
  if (bucket == 0) return XAIOS_ERR_NO_MEMORY;
  if (more == 0U) {
    if (bucket->total_len != 0U && bucket->total_len != end) {
      clear_ipv6_bucket(bucket);
      return XAIOS_ERR_INVALID;
    }
    bucket->total_len = end;
  }
  if (bucket->total_len != 0U && end > bucket->total_len) {
    clear_ipv6_bucket(bucket);
    return XAIOS_ERR_INVALID;
  }

  const uint8_t *fragment_data = fh + XAIOS_IPV6_FRAG_HEADER_SIZE;
  for (uint32_t i = 0U; i < fragment_len; ++i) {
    uint32_t position = offset + i;
    if (bucket->received[position] != 0U &&
        bucket->payload[position] != fragment_data[i]) {
      clear_ipv6_bucket(bucket);
      return XAIOS_ERR_INVALID;
    }
  }
  for (uint32_t i = 0U; i < fragment_len; ++i) {
    uint32_t position = offset + i;
    if (bucket->received[position] == 0U) {
      bucket->received[position] = 1U;
      bucket->payload[position] = fragment_data[i];
      ++bucket->received_count;
    }
  }
  if (offset == 0U) {
    ipv6_bytes_copy(bucket->ethernet_header, frame, 14U);
    ipv6_bytes_copy(bucket->ipv6_header, ip6, XAIOS_IPV6_HEADER_SIZE);
    bucket->have_first = 1U;
  }
  if (bucket->total_len == 0U || bucket->have_first == 0U ||
      bucket->received_count < bucket->total_len) {
    return XAIOS_ERR_BUSY;
  }
  for (uint32_t i = 0U; i < bucket->total_len; ++i) {
    if (bucket->received[i] == 0U) return XAIOS_ERR_BUSY;
  }

  ipv6_bytes_copy(frame, bucket->ethernet_header, 14U);
  ipv6_bytes_copy(frame + 14U, bucket->ipv6_header, XAIOS_IPV6_HEADER_SIZE);
  frame[20U] = bucket->next_header;
  ipv6_put_be16(frame + 18U, (uint16_t)bucket->total_len);
  ipv6_bytes_copy(frame + 54U, bucket->payload, bucket->total_len);
  *frame_len = 54U + bucket->total_len;
  clear_ipv6_bucket(bucket);
  return XAIOS_OK;
}

void ipv6_frag_init(void) {
  ipv6_bytes_zero(g_ipv6_frag_buckets, sizeof(g_ipv6_frag_buckets));
}
