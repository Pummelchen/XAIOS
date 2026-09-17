#ifndef XAIOS_TESTS_SECURITY_TEST_WT_TLS_CLIENT_SUPPORT_H
#define XAIOS_TESTS_SECURITY_TEST_WT_TLS_CLIENT_SUPPORT_H

/* Declarations shared by the three translation units of the QUIC TLS 1.3
 * client test.
 *
 * `test_wt_tls_client.c` was one 1402-line file. It is now the driver and
 * entry point plus two modules: `test_wt_tls_client_support.c` holds the
 * fixture, the ClientHello the fixture was built around, the message builders
 * and the CertificateVerify refusals; `test_wt_tls_client_flight.c` holds the
 * Certificate step and the flights that run to completion. Everything that
 * crosses a translation unit is declared here and defined exactly once.
 *
 * Every symbol that leaves its own translation unit carries the `wtc_`
 * prefix. The host runner links both modules into every WebTransport test
 * binary, so an unprefixed `expect_int` would collide with the sibling
 * handshake suite's own helper as soon as that suite is split too. The shared
 * test entry points are `wtc_test_*` so a name read in `main` names the module
 * it lives in; the driver's own three tests stay static and unrenamed.
 *
 * Nothing here is for anyone outside this test.
 */

#include "wt_tls_client.h"

#include <stddef.h>
#include <stdint.h>

/* The two counters, owned by the support module. A test increments them
 * directly; the driver's `main` reads them to decide the exit status. */
extern int wtc_failures;
extern int wtc_checks;

void wtc_expect_int(const char *name, long want, long got);
void wtc_expect_bytes(const char *name, const uint8_t *want,
                      const uint8_t *got, size_t len);

/* The fixture the whole suite runs on, filled by wtc_setup_params and
 * wtc_setup_pin in both `main` and each test that needs a fresh one. */
extern wt_tls_client_hello_params_t wtc_params;
extern uint8_t wtc_certificate_der[4096];
extern size_t wtc_certificate_der_len;

void wtc_setup_params(void);
void wtc_setup_pin(void);

/* Start a handshake and leave it waiting for a ServerHello. Returns 0 when the
 * ClientHello was produced. */
int wtc_start_client(wt_tls_client_t *handshake);

/* Feed one message and report whether it was accepted. */
int wtc_feed(wt_tls_client_t *handshake, wt_tls_level_t level,
             const uint8_t *message, size_t message_len);

/* The two extensions a QUIC server must send, and the extension an unoffered
 * one is built from, as the message builders take them. */
extern const uint8_t wtc_alpn_h3[5];
extern const uint8_t wtc_alpn_h2[5];
extern const uint8_t wtc_server_parameters[6];
extern const uint8_t wtc_empty_extension[1];

size_t wtc_build_server_hello(uint8_t *out, size_t capacity, uint16_t suite,
                              uint16_t group, const uint8_t *key_share,
                              size_t key_share_len, int retry,
                              uint16_t version);
size_t wtc_build_encrypted_extensions(uint8_t *out, size_t capacity,
                                      const uint16_t *types,
                                      const uint8_t *const *data,
                                      const size_t *lengths, size_t count);
size_t wtc_good_encrypted_extensions(uint8_t *out, size_t capacity);

/* Drive a handshake to the point where EncryptedExtensions is expected.
 * Defined in the flight module, which is the first place it is used. */
int wtc_reach_wait_encrypted_extensions(wt_tls_client_t *handshake);

/* The tests that live outside the driver. `main` calls them in the order the
 * one-file suite did. */
void wtc_test_client_hello_and_start(void);
void wtc_test_certificate(void);
void wtc_test_certificate_verify(void);
void wtc_test_full_handshake(void);
void wtc_test_client_auth_request(void);
void wtc_test_client_owns_what_it_keeps(void);

#endif
