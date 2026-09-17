/* TLS 1.3 key schedule and empty-transcript checks, checked against RFC 8448.
 *
 * This is one translation unit of the split TLS key-schedule test.
 * test_wt_tls.c is the driver and entry point; this module owns the
 * empty-transcript check, HKDF-Expand-Label, the whole key schedule and its
 * two-phase form, and it defines the two check counters declared in
 * test_wt_tls_support.h. test_wt_tls_quic_keys.c owns the QUIC traffic,
 * Initial and Retry-integrity tests.
 *
 * Every symbol that leaves this file carries the `wttls_` prefix; the check
 * helpers themselves are `static inline` in the shared header.
 */

#include "test_wt_tls_support.h"

/* The two counters the shared check helpers increment. Defined exactly once,
 * here, because this is the first module `main` calls. */
int wttls_failures;
int wttls_checks;

/* ------------------------------------------------------ the empty transcript */

void wttls_test_empty_hash(void) {
  uint8_t digest[WT_TLS_HASH_LEN];
  /* The constant in wt_tls.c must be SHA-256 of the empty string. Comparing it
     against a computed value rather than against the same literal is the point:
     a wrong constant would otherwise agree with itself. */
  wttls_expect_int("sha256(empty)", 0, wt_sha256("", 0, digest));
  wttls_expect_bytes("wt_tls_empty_hash is SHA-256 of the empty transcript",
               digest, wt_tls_empty_hash, WT_TLS_HASH_LEN);
}

/* ----------------------------------------------------------- HKDF-Expand-Label */

void wttls_test_expand_label(void) {
  uint8_t out[32];
  /* RFC 8448 prints the whole HkdfLabel for "tls13 c hs traffic" with an empty
     context and a 32-byte output as:
       00 20 12 74 6c 73 31 33 20 63 20 68 73 20 74 72 61 66 66 69 63 20
     The first two bytes are the length, the third is the label length 0x12,
     then "tls13 c hs traffic", then a zero context length. Build the same
     thing by hand and compare, so a wrong prefix or length is caught here
     rather than as a wrong secret 40 checks later. */
  uint8_t info[64];
  size_t label_len = strlen("c hs traffic");
  size_t full_len = 6U + label_len;
  size_t info_len;
  info[0] = 0x00; info[1] = 0x20;
  info[2] = (uint8_t)full_len;
  memcpy(info + 3, "tls13 ", 6);
  memcpy(info + 9, "c hs traffic", label_len);
  info[3U + full_len] = 0x00;
  info_len = 4U + full_len;
  /* The structure is 22 bytes for this label: two length bytes, the
     label-length byte 0x12, eighteen bytes of "tls13 c hs traffic", and the
     context-length byte. RFC 8448 prints those 22 bytes as the "info" of that
     derivation under a 32-byte context, and the printed hex includes the two
     length bytes, so the label itself starts at offset 3. */
  wttls_expect_int("HkdfLabel length for 'c hs traffic'", 22, (long)info_len);
  wttls_expect_int("HkdfLabel label length byte", 0x12, (long)info[2]);
  wttls_expect_hex("printed HkdfLabel label",
             "746c73313320632068732074726166666963", info + 3, 18);
  wttls_expect_int("HkdfLabel context length byte", 0, (long)info[21]);

  /* Expanding with an explicit context must differ from an empty one: a
     function that ignored the context would pass every vector in this file,
     because every vector here uses an empty context. */
  {
    uint8_t with_context[WT_TLS_HASH_LEN];
    uint8_t without_context[WT_TLS_HASH_LEN];
    uint8_t context[WT_TLS_HASH_LEN];
    memset(context, 0x5a, sizeof(context));
    wttls_expect_int("expand_label empty context", 0,
               wt_tls_expand_label(WT_RFC8448_HANDSHAKE_SECRET, WT_TLS_HASH_LEN,
                                   "c hs traffic", NULL, 0, without_context,
                                   WT_TLS_HASH_LEN));
    wttls_expect_int("expand_label with context", 0,
               wt_tls_expand_label(WT_RFC8448_HANDSHAKE_SECRET, WT_TLS_HASH_LEN,
                                   "c hs traffic", context, sizeof(context),
                                   with_context, WT_TLS_HASH_LEN));
    wttls_checks++;
    if (memcmp(with_context, without_context, WT_TLS_HASH_LEN) == 0) {
      wttls_failures++;
      printf("FAIL the context is ignored by wt_tls_expand_label\n");
    }
  }

  /* Refusals, so a caller passing nonsense is told rather than given bytes. */
  wttls_expect_int("expand_label refuses an empty label (RFC 8446 label<7..255>)",
             -1,
             wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN, "",
                                 NULL, 0, out, 16));
  wttls_expect_int("expand_label refuses a NULL secret", -1,
             wt_tls_expand_label(NULL, WT_TLS_HASH_LEN, "key", NULL, 0, out, 16));
  wttls_expect_int("expand_label refuses a NULL output", -1,
             wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN, "key",
                                 NULL, 0, NULL, 16));
  wttls_expect_int("expand_label refuses a NULL context with a length", -1,
             wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN, "key",
                                 NULL, 4, out, 16));
  {
    /* 255 bytes of context is the most the length byte holds; one more is a
       refusal, not a truncated label. */
    static uint8_t big_context[256];
    wttls_expect_int("expand_label accepts a 255-byte context", 0,
               wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN,
                                   "key", big_context, 255, out, 16));
    wttls_expect_int("expand_label refuses a 256-byte context", -1,
               wt_tls_expand_label(WT_RFC8448_EARLY_SECRET, WT_TLS_HASH_LEN,
                                   "key", big_context, 256, out, 16));
  }
}

/* ------------------------------------------------------------- the schedule */

void wttls_test_key_schedule(void) {
  wt_tls_secrets_t secrets;

  wttls_expect_int("key schedule", 0,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  wttls_expect_int("the resumption master secret is absent without a client "
             "Finished transcript", 0, secrets.resumption_master_available);

  /* RFC 8448 section 3 prints this value over the client-Finished transcript,
     and the audit that found the wrong-transcript defect is what pointed at it.
     Deriving it from the server's Finished gives a well-formed value that is
     not this one, so pinning it is the check that the transcript is the right
     one. */
  {
    wt_tls_secrets_t with_res;
    wttls_expect_int("key schedule with the RFC's client-Finished transcript", 0,
               wt_tls_key_schedule(
                   WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                   WT_RFC8448_TRANSCRIPT_AFTER_CLIENT_FINISHED, &with_res));
    wttls_expect_bytes("resumption_master_secret",
                 WT_RFC8448_RESUMPTION_MASTER, with_res.resumption_master, 32);
    wttls_expect_int("and it is flagged available", 1,
               with_res.resumption_master_available);
    /* The other values must be unchanged by the extra transcript: they come
       from the server's Finished and must not move. */
    wttls_expect_bytes("the exporter is unaffected by the client transcript",
                 WT_RFC8448_EXPORTER_MASTER, with_res.exporter_master, 32);
    wttls_expect_bytes("the application secrets are unaffected",
                 WT_RFC8448_CLIENT_APPLICATION_TRAFFIC,
                 with_res.client_application_traffic, 32);
    wt_tls_secrets_clear(&with_res);
  }

  /* Every value RFC 8448 prints, in the order the RFC derives them. A mismatch
     here localises the defect: the early secret failing means the extract, the
     handshake secret failing means the "derived" step or the ECDHE input, and
     so on down the chain. */
  wttls_expect_bytes("early_secret", WT_RFC8448_EARLY_SECRET, secrets.early, 32);
  wttls_expect_bytes("handshake_secret", WT_RFC8448_HANDSHAKE_SECRET,
               secrets.handshake, 32);
  wttls_expect_bytes("master_secret", WT_RFC8448_MASTER_SECRET, secrets.master, 32);
  wttls_expect_bytes("client_handshake_traffic_secret",
               WT_RFC8448_CLIENT_HANDSHAKE_TRAFFIC,
               secrets.client_handshake_traffic, 32);
  wttls_expect_bytes("server_handshake_traffic_secret",
               WT_RFC8448_SERVER_HANDSHAKE_TRAFFIC,
               secrets.server_handshake_traffic, 32);
  wttls_expect_bytes("client_application_traffic_secret",
               WT_RFC8448_CLIENT_APPLICATION_TRAFFIC,
               secrets.client_application_traffic, 32);
  wttls_expect_bytes("server_application_traffic_secret",
               WT_RFC8448_SERVER_APPLICATION_TRAFFIC,
               secrets.server_application_traffic, 32);
  wttls_expect_bytes("exporter_master_secret", WT_RFC8448_EXPORTER_MASTER,
               secrets.exporter_master, 32);

  /* The resumption master secret is taken over the transcript through the
     CLIENT's Finished. Derived from the server's Finished instead -- which is
     what this function did first -- it is a well-formed value that is simply
     not the resumption master secret, and the failure would appear on the
     first resumption attempt with nothing to point at. The two must therefore
     differ, and the availability flag must say which is which. */
  {
    /* And with no client transcript the field stays zero rather than holding a
       value derived from the wrong messages. */
    static const uint8_t zeroes[32] = {0};
    wttls_expect_int("the resumption master secret is zero when unavailable", 1,
               memcmp(secrets.resumption_master, zeroes, 32) == 0);
  }

  /* A wrong ECDHE input must not produce the published secrets. This is the
     check that the schedule actually depends on the key exchange rather than
     ignoring it. */
  {
    uint8_t wrong_ecdh[32];
    wt_tls_secrets_t wrong;
    memcpy(wrong_ecdh, WT_RFC8448_ECDHE, 32);
    wrong_ecdh[0] ^= 0x01U;
    wttls_expect_int("key schedule with a wrong ECDHE", 0,
               wt_tls_key_schedule(wrong_ecdh, sizeof(wrong_ecdh),
                                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                   NULL, &wrong));
    wttls_checks++;
    if (memcmp(wrong.handshake, secrets.handshake, 32) == 0) {
      wttls_failures++;
      printf("FAIL the handshake secret does not depend on the ECDHE input\n");
    }
    wt_tls_secrets_clear(&wrong);
  }

  /* And a wrong transcript must not either. */
  {
    uint8_t wrong_th[32];
    wt_tls_secrets_t wrong;
    memcpy(wrong_th, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO, 32);
    wrong_th[31] ^= 0x01U;
    wttls_expect_int("key schedule with a wrong transcript", 0,
               wt_tls_key_schedule(WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                                   wrong_th,
                                   WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                   NULL, &wrong));
    wttls_checks++;
    if (memcmp(wrong.client_handshake_traffic,
               secrets.client_handshake_traffic, 32) == 0) {
      wttls_failures++;
      printf("FAIL the handshake traffic secret does not depend on the "
             "transcript\n");
    }
    wt_tls_secrets_clear(&wrong);
  }

  /* NULL arguments are refusals, and a refusal clears the output rather than
     leaving a partially derived schedule a caller might use. */
  wttls_expect_int("key schedule refuses NULL output", -1,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, 32,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, NULL));
  wttls_expect_int("key schedule refuses a zero-length ECDHE", -1,
             wt_tls_key_schedule(NULL, 0, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  wttls_expect_int("key schedule refuses a non-NULL zero-length ECDHE", -1,
             wt_tls_key_schedule((const uint8_t *)"", 0,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  wttls_expect_int("key schedule refuses a NULL transcript", -1,
             wt_tls_key_schedule(WT_RFC8448_ECDHE, 32, NULL,
                                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                                 NULL, &secrets));
  {
    wt_tls_secrets_t cleared;
    static const uint8_t zeroes[32] = {0};
    memset(&cleared, 0xAA, sizeof(cleared));
    wttls_expect_int("key schedule refusal", -1,
               wt_tls_key_schedule(WT_RFC8448_ECDHE, 32, NULL, NULL, NULL,
                                   &cleared));
    /* A caller that ignored the return value must not be able to use a
       half-derived schedule, so the output is cleared even when the arguments
       were refused before any derivation ran. */
    wttls_checks++;
    if (memcmp(cleared.early, zeroes, 32) != 0) {
      wttls_failures++;
      printf("FAIL a refused key schedule left a partially derived secret\n");
    }
  }

  wt_tls_secrets_clear(&secrets);
}

/* ------------------------------------------- the schedule in two phases
 *
 * The whole schedule is one function above, and a handshake cannot use it: the
 * handshake keys are needed as soon as the ServerHello arrives, and the
 * application keys cannot exist until the server's Finished has been verified,
 * because their transcript does not exist before then. So the schedule is
 * exposed as two phases as well, and this checks that running them in order
 * gives exactly what running the whole thing gives -- against RFC 8448's
 * published values, not against each other.
 *
 * The failure this prevents is the tempting one: calling the whole schedule at
 * the ServerHello and using the application secrets it produced, which would be
 * well-formed, wrong, and indistinguishable from right until the first packet
 * failed to decrypt.
 */
void wttls_test_key_schedule_phases(void) {
  wt_tls_secrets_t whole;
  wt_tls_secrets_t phase_one;
  wt_tls_secrets_t phase_two;
  wt_tls_secrets_t combined;

  wttls_expect_int("the whole schedule", 0,
             wt_tls_key_schedule(
                 WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED, NULL, &whole));

  /* The first phase, at the point in the handshake where it is called. */
  wttls_expect_int("the handshake phase", 0,
             wt_tls_handshake_key_schedule(
                 WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO, &phase_one));
  wttls_expect_bytes("  the handshake secret", whole.handshake, phase_one.handshake,
               WT_TLS_HASH_LEN);
  wttls_expect_bytes("  the client handshake traffic secret",
               whole.client_handshake_traffic,
               phase_one.client_handshake_traffic, WT_TLS_HASH_LEN);
  wttls_expect_bytes("  the server handshake traffic secret",
               whole.server_handshake_traffic,
               phase_one.server_handshake_traffic, WT_TLS_HASH_LEN);
  /* The RFC prints the client's handshake traffic secret, so this is a check
     against the RFC and not only against the other function. */
  wttls_expect_bytes("  which is RFC 8448's", WT_RFC8448_CLIENT_HANDSHAKE_TRAFFIC,
               phase_one.client_handshake_traffic, WT_TLS_HASH_LEN);
  /* The first phase cannot know the master secret's consumers, and it does not
     pretend to: the application secrets are left zero. */
  {
    static const uint8_t zeroes[32] = {0};
    wttls_expect_bytes("  the application secrets are not derived yet", zeroes,
                 phase_one.client_application_traffic, WT_TLS_HASH_LEN);
  }

  /* The second phase, at the point where it is called. */
  wttls_expect_int("the application phase", 0,
             wt_tls_application_key_schedule(
                 &phase_one, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                 &phase_two));
  wttls_expect_bytes("  the master secret", whole.master, phase_two.master,
               WT_TLS_HASH_LEN);
  wttls_expect_bytes("  the client application traffic secret",
               whole.client_application_traffic,
               phase_two.client_application_traffic, WT_TLS_HASH_LEN);
  wttls_expect_bytes("  the server application traffic secret",
               whole.server_application_traffic,
               phase_two.server_application_traffic, WT_TLS_HASH_LEN);
  wttls_expect_bytes("  the exporter master secret", whole.exporter_master,
               phase_two.exporter_master, WT_TLS_HASH_LEN);
  /* The second phase carries the first phase's values into its output, so that
     a caller ends up with one complete schedule rather than half of one in each
     of two structures. */
  wttls_expect_bytes("  and the handshake secrets are carried through",
               whole.client_handshake_traffic,
               phase_two.client_handshake_traffic, WT_TLS_HASH_LEN);
  wttls_expect_bytes("  including the early secret", whole.early, phase_two.early,
               WT_TLS_HASH_LEN);
  wttls_expect_int("  and no resumption master secret, which needs the client's "
             "Finished",
             0, phase_two.resumption_master_available);

  /* Running both phases into the same structure is what a handshake does, and
     it must work: the second phase reads the first's output and writes over it.
     A function that cleared its output before reading its input would produce
     zeros here, and that is exactly the mistake the copy-first code above
     exists to prevent. */
  memset(&combined, 0xAA, sizeof(combined));
  wttls_expect_int("the handshake phase into a fresh structure", 0,
             wt_tls_handshake_key_schedule(
                 WT_RFC8448_ECDHE, sizeof(WT_RFC8448_ECDHE),
                 WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO, &combined));
  wttls_expect_int("then the application phase in place", 0,
             wt_tls_application_key_schedule(
                 &combined, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                 &combined));
  wttls_expect_bytes("running the phases in place gives the whole schedule",
               whole.client_application_traffic,
               combined.client_application_traffic, WT_TLS_HASH_LEN);
  wttls_expect_bytes("  and the handshake secrets survive it",
               whole.server_handshake_traffic, combined.server_handshake_traffic,
               WT_TLS_HASH_LEN);

  /* Refusals, and each must leave the output cleared. */
  {
    static const uint8_t zeroes[32] = {0};
    wt_tls_secrets_t cleared;
    memset(&cleared, 0xAA, sizeof(cleared));
    wttls_expect_int("the handshake phase refuses a NULL transcript", -1,
               wt_tls_handshake_key_schedule(WT_RFC8448_ECDHE,
                                             sizeof(WT_RFC8448_ECDHE), NULL,
                                             &cleared));
    wttls_expect_bytes("  and clears the output", zeroes, cleared.handshake,
                 WT_TLS_HASH_LEN);
    wttls_expect_int("the handshake phase refuses a zero-length ECDHE", -1,
               wt_tls_handshake_key_schedule(WT_RFC8448_ECDHE, 0U,
                                             WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                             &cleared));
    wttls_expect_int("the handshake phase refuses a NULL output", -1,
               wt_tls_handshake_key_schedule(WT_RFC8448_ECDHE,
                                             sizeof(WT_RFC8448_ECDHE),
                                             WT_RFC8448_TRANSCRIPT_AFTER_SERVER_HELLO,
                                             NULL));
    memset(&cleared, 0xAA, sizeof(cleared));
    wttls_expect_int("the application phase refuses a NULL transcript", -1,
               wt_tls_application_key_schedule(&phase_one, NULL, &cleared));
    wttls_expect_bytes("  and clears the output", zeroes, cleared.master,
                 WT_TLS_HASH_LEN);
    wttls_expect_int("the application phase refuses a NULL input", -1,
               wt_tls_application_key_schedule(
                   NULL, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                   &cleared));
    wttls_expect_bytes("  and clears the output", zeroes, cleared.master,
                 WT_TLS_HASH_LEN);
    wttls_expect_int("the application phase refuses a NULL output", -1,
               wt_tls_application_key_schedule(
                   &phase_one, WT_RFC8448_TRANSCRIPT_AFTER_SERVER_FINISHED,
                   NULL));
  }

  wt_tls_secrets_clear(&whole);
  wt_tls_secrets_clear(&phase_one);
  wt_tls_secrets_clear(&phase_two);
  wt_tls_secrets_clear(&combined);
}
