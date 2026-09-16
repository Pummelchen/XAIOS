/* The endpoint configuration (Phase 8). */

#include "webtransport/api/endpoint.h"

#include <string.h>

const char *wt_endpoint_role_name(wt_endpoint_role_t role) {
  /* A switch with no default so that -Wswitch-enum makes a new role a compile error here
   * rather than a missing name at run time. */
  switch (role) {
    case WT_ENDPOINT_ROLE_CLIENT: return "client";
    case WT_ENDPOINT_ROLE_SERVER: return "server";
  }
  return "unknown";
}

wt_endpoint_config_t wt_endpoint_config_default(void) {
  wt_endpoint_config_t config;
  memset(&config, 0, sizeof(config));
  config.role = (wt_endpoint_role_t)0;
  config.host = NULL;
  config.port = 0U;
  config.authority = NULL;
  config.path = "/";
  /* Zeroed, which for a trust policy means "no mode" -- the same value a server must have,
   * so a default that was never touched is a valid server configuration and an invalid
   * client one. */
  config.trust.mode = (wt_tls_trust_mode_t)0;
  return config;
}

static int trust_mode_is_known(wt_tls_trust_mode_t mode) {
  /* Every enumerator is listed and anything else falls through to "not known": a mode that
   * is not one of these -- including the zero a configuration that was never filled in
   * carries -- is not a policy. A case label for a value outside the enum would not
   * compile under -Wswitch, which is the compiler saying the same thing. */
  switch (mode) {
    case WT_TLS_TRUST_SYSTEM:
    case WT_TLS_TRUST_STORE:
    case WT_TLS_TRUST_PINNED_CERTIFICATE:
    case WT_TLS_TRUST_LOCAL_DEVELOPMENT: return 1;
  }
  return 0;
}

static wt_status_t check_client_trust(const wt_endpoint_config_t *config) {
  const wt_tls_trust_policy_t *trust = &config->trust;

  if (!trust_mode_is_known(trust->mode)) {
    /* A client with no trust policy has nothing to judge the peer with, and a client that
     * trusts anything is not a client this library offers. */
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (trust->mode == WT_TLS_TRUST_PINNED_CERTIFICATE) {
    if (trust->fingerprint_count == 0U || trust->fingerprint_count > WT_TLS_PINNED_MAX) {
      return WT_ERR_INVALID_ARGUMENT;
    }
  }
  if (trust->mode == WT_TLS_TRUST_LOCAL_DEVELOPMENT &&
      !wt_tls_trust_host_is_loopback(trust->host_name != NULL ? trust->host_name : config->host)) {
    /* The bypass is tied to a loopback name, and the check is the TRUST LAYER's function
     * rather than a copy of its rule, so the two cannot drift. */
    return WT_ERR_TRUST;
  }
  return WT_OK;
}

wt_status_t wt_endpoint_config_check(const wt_endpoint_config_t *config) {
  wt_status_t status;

  if (config == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* No role is not "either": the two sides need different things, and guessing would decide
   * how the peer is authenticated. */
  if (config->role != WT_ENDPOINT_ROLE_CLIENT && config->role != WT_ENDPOINT_ROLE_SERVER) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  if (config->host == NULL || config->host[0] == '\0') return WT_ERR_INVALID_ARGUMENT;

  if (config->role == WT_ENDPOINT_ROLE_CLIENT && config->port == 0U) {
    /* A client cannot connect to "some port". */
    return WT_ERR_INVALID_ARGUMENT;
  }

  if (config->path != NULL) {
    if (config->path[0] != '/') {
      /* A WebTransport path is an absolute path; anything else is not one on the wire. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    if (strlen(config->path) >= WT_SESSION_AUTHORITY_MAX) return WT_ERR_LIMIT;
  }
  if (config->authority != NULL && strlen(config->authority) >= WT_SESSION_AUTHORITY_MAX) {
    /* The session copies the authority into a fixed buffer, so this is the bound it will
     * hit at create; finding out here names the field that is wrong. */
    return WT_ERR_LIMIT;
  }
  if (config->authority == NULL && strlen(config->host) >= WT_SESSION_AUTHORITY_MAX) {
    /* The HOST becomes the authority when none was named (`wt_endpoint_session_config` below), and the first
     * version bounded only the explicit authority -- so a 199-byte host passed this check and failed later, at
     * `wt_session_create`, with the same WT_ERR_LIMIT and no indication of which field caused it. A check that
     * reports the right status for the wrong reason still costs the caller the diagnosis. */
    return WT_ERR_LIMIT;
  }

  if (config->role == WT_ENDPOINT_ROLE_SERVER) {
    if (config->trust.mode != (wt_tls_trust_mode_t)0) {
      /* This draft has no client authentication: a server has no peer certificate to
       * judge, so a policy here would be a promise the library cannot keep. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    return WT_OK;
  }

  status = check_client_trust(config);
  if (status != WT_OK) return status;
  return WT_OK;
}

wt_status_t wt_endpoint_session_config(const wt_endpoint_config_t *config, uint64_t session_id,
                                       wt_session_config_t *out) {
  wt_status_t status;
  wt_session_config_t session = wt_session_config_default();

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_endpoint_config_check(config);
  if (status != WT_OK) return status;

  /* The authority the CONNECT request carries is the endpoint's own authority or, when it
   * did not name one, the host it is reached at. */
  session.authority = config->authority != NULL ? config->authority : config->host;
  session.path = config->path != NULL ? config->path : "/";
  session.session_id = session_id;
  *out = session;
  return WT_OK;
}
