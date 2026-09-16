/* The command-line tools' options (Phase 9). */

#include "webtransport/cli/options.h"

#include "cli_json.h"

#include <stdio.h>
#include <string.h>

#define WT_CLI_TIMEOUT_DEFAULT 5000U

wt_cli_options_t wt_cli_options_default(void) {
  wt_cli_options_t options;
  memset(&options, 0, sizeof(options));
  options.mode = WT_CLI_MODE_NONE;
  options.transport = WT_CLI_TRANSPORT_PACKET;
  options.trust = WT_CLI_TRUST_SYSTEM;
  options.exchange = WT_CLI_EXCHANGE_STREAM;
  /* Named rather than left to the memset, so the draft-16 default is a decision stated here rather than a zero
   * that happens to mean the current token (F-02b). */
  options.upgrade_token = WT_CLI_UPGRADE_TOKEN_DRAFT16;
  options.timeout_ms = WT_CLI_TIMEOUT_DEFAULT;
  return options;
}

const char *wt_cli_mode_name(wt_cli_mode_t mode) {
  switch (mode) {
    case WT_CLI_MODE_LISTEN: return "listen";
    case WT_CLI_MODE_CONNECT: return "connect";
    case WT_CLI_MODE_NONE: break;
  }
  return "none";
}

const char *wt_cli_transport_name(wt_cli_transport_t transport) {
  switch (transport) {
    case WT_CLI_TRANSPORT_PACKET: return "packet";
  }
  return "unknown";
}

const char *wt_cli_trust_name(wt_cli_trust_t trust) {
  switch (trust) {
    case WT_CLI_TRUST_SYSTEM: return "system";
    case WT_CLI_TRUST_LOCAL_DEVELOPMENT: return "local-development";
  }
  return "unknown";
}

const char *wt_cli_exchange_name(wt_cli_exchange_t exchange) {
  switch (exchange) {
    case WT_CLI_EXCHANGE_STREAM: return "stream";
    case WT_CLI_EXCHANGE_DATAGRAM: return "datagram";
  }
  return "unknown";
}

const char *wt_cli_upgrade_token_name(wt_cli_upgrade_token_t upgrade_token) {
  switch (upgrade_token) {
    case WT_CLI_UPGRADE_TOKEN_DRAFT16: return "draft16";
    case WT_CLI_UPGRADE_TOKEN_LEGACY: return "legacy";
  }
  return "unknown";
}

static int is_flag(const char *argument, const char *name) {
  return strcmp(argument, name) == 0;
}

/* A timeout is milliseconds, and only digits: a value with a sign, a suffix or a space is not
 * a number this tool will guess at. */
static int parse_timeout(const char *value, uint64_t *out) {
  uint64_t total = 0U;
  size_t i;

  if (value == NULL || value[0] == '\0') return 0;
  for (i = 0U; value[i] != '\0'; i++) {
    uint64_t digit;
    if (value[i] < '0' || value[i] > '9') return 0;
    digit = (uint64_t)(value[i] - '0');
    if (total > (UINT64_MAX - digit) / 10U) return 0;
    total = total * 10U + digit;
  }
  *out = total;
  return 1;
}

static wt_status_t fail(const char *message, const char *argument, const char **out_error,
                        const char **out_error_argument) {
  if (out_error != NULL) *out_error = message;
  if (out_error_argument != NULL) *out_error_argument = argument;
  return WT_ERR_INVALID_ARGUMENT;
}

wt_status_t wt_cli_options_parse(wt_cli_options_t *options, int argc, const char *const *argv,
                                 const char **out_error, const char **out_error_argument) {
  int i;

  if (options == NULL || argv == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (out_error != NULL) *out_error = NULL;
  if (out_error_argument != NULL) *out_error_argument = NULL;

  /* The options start from the defaults every time, so a caller cannot inherit a mode from a
   * previous parse. */
  *options = wt_cli_options_default();

  for (i = 1; i < argc; i++) {
    const char *argument = argv[i];

    if (is_flag(argument, "--help") || is_flag(argument, "-h")) {
      options->help = 1;
    } else if (is_flag(argument, "--version")) {
      options->version = 1;
    } else if (is_flag(argument, "--listen")) {
      options->mode = WT_CLI_MODE_LISTEN;
    } else if (is_flag(argument, "--connect")) {
      options->mode = WT_CLI_MODE_CONNECT;
    } else if (is_flag(argument, "--json")) {
      options->json = 1;
    } else if (is_flag(argument, "--settings-validation")) {
      options->settings_validation = 1;
    } else if (is_flag(argument, "--retry")) {
      options->retry = 1;
    } else if (is_flag(argument, "--early-stream")) {
      options->early_stream = 1;
    } else if (is_flag(argument, "--transport") || is_flag(argument, "--trust") ||
               is_flag(argument, "--origin") || is_flag(argument, "--authority") ||
               is_flag(argument, "--protocol") ||
               is_flag(argument, "--exchange") || is_flag(argument, "--message") ||
               is_flag(argument, "--upgrade-token") ||
               is_flag(argument, "--timeout-ms") || is_flag(argument, "--scenario") ||
               is_flag(argument, "--hostile") || is_flag(argument, "--address")) {
      const char *value;
      /* A flag that takes a value does not take the NEXT FLAG as its value. */
      if (i + 1 >= argc) return fail("missing value", argument, out_error, out_error_argument);
      value = argv[i + 1];
      if (value[0] == '-' && value[1] == '-') {
        return fail("missing value", argument, out_error, out_error_argument);
      }
      i++;

      if (is_flag(argument, "--transport")) {
        if (strcmp(value, "packet") == 0) {
          options->transport = WT_CLI_TRANSPORT_PACKET;
        } else {
          /* Supported modes are named, and everything else is refused with the same message:
           * a tool that half-supports a transport writes reports nobody can trust. */
          return fail("unsupported transport", value, out_error, out_error_argument);
        }
      } else if (is_flag(argument, "--trust")) {
        if (strcmp(value, "system") == 0) {
          options->trust = WT_CLI_TRUST_SYSTEM;
        } else if (strcmp(value, "local-development") == 0) {
          options->trust = WT_CLI_TRUST_LOCAL_DEVELOPMENT;
        } else {
          return fail("unsupported trust mode", value, out_error, out_error_argument);
        }
        options->trust_set = 1;
      } else if (is_flag(argument, "--origin")) {
        options->origin = value;
      } else if (is_flag(argument, "--authority")) {
        options->authority = value;
      } else if (is_flag(argument, "--protocol")) {
        options->protocol = value;
      } else if (is_flag(argument, "--message")) {
        options->message = value;
      } else if (is_flag(argument, "--address")) {
        options->address = value;
      } else if (is_flag(argument, "--exchange")) {
        if (strcmp(value, "stream") == 0) {
          options->exchange = WT_CLI_EXCHANGE_STREAM;
        } else if (strcmp(value, "datagram") == 0) {
          options->exchange = WT_CLI_EXCHANGE_DATAGRAM;
        } else {
          return fail("unsupported exchange", value, out_error, out_error_argument);
        }
      } else if (is_flag(argument, "--upgrade-token")) {
        /* The token cannot be negotiated on the wire -- a pre-draft peer rejects the CONNECT before it reads any
         * setting -- so it is selected here, and a value that is neither name is refused rather than left at the
         * default: a caller who asked for a token this tool does not send would otherwise get a report claiming
         * one it never offered (F-02b). */
        if (strcmp(value, "draft16") == 0) {
          options->upgrade_token = WT_CLI_UPGRADE_TOKEN_DRAFT16;
        } else if (strcmp(value, "legacy") == 0) {
          options->upgrade_token = WT_CLI_UPGRADE_TOKEN_LEGACY;
        } else {
          return fail("unsupported upgrade token", value, out_error, out_error_argument);
        }
        options->upgrade_token_set = 1;
      } else if (is_flag(argument, "--scenario")) {
        if (strcmp(value, "all") != 0) {
          return fail("unsupported scenario", value, out_error, out_error_argument);
        }
        options->scenario_all = 1;
      } else if (is_flag(argument, "--hostile")) {
        /* The act is a NAME, and an unknown one is refused here rather than at the peer: a caller that asked for
         * a misbehaviour nobody implements should be told, not given a peer that behaves (WT-147). */
        if (strcmp(value, "max-streams-decrease") != 0 &&
            strcmp(value, "datagram-for-another-session") != 0) {
          return fail("unsupported hostile act", value, out_error, out_error_argument);
        }
        options->hostile = value;
      } else if (is_flag(argument, "--timeout-ms")) {
        if (!parse_timeout(value, &options->timeout_ms)) {
          return fail("invalid timeout", value, out_error, out_error_argument);
        }
        options->timeout_set = 1;
      }
    } else {
      /* The address may also be positional, which is how a tool is usually driven by hand. A
       * double dash is a flag and an unknown one is refused; a SINGLE dash is a value, because
       * refusing to accept `-host:1` as an address would be this parser inventing a rule about
       * host names it has no business having. */
      if (argument[0] == '-' && argument[1] == '-') {
        return fail("unknown flag", argument, out_error, out_error_argument);
      }
      if (options->address != NULL) {
        return fail("more than one address", argument, out_error, out_error_argument);
      }
      options->address = argument;
    }
    options->parsed = i;
  }
  return WT_OK;
}

wt_status_t wt_cli_options_check(const wt_cli_options_t *options, const char **out_error) {
  if (options == NULL) {
    /* `options.h` promises "WT_ERR_INVALID_ARGUMENT with `*out_error` pointing at a static message" for a NULL
     * argument too, and this path returned without touching it -- so a caller that printed the error printed
     * whatever its own variable held. */
    if (out_error != NULL) *out_error = "no options to check";
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (out_error != NULL) *out_error = NULL;

  if (options->mode == WT_CLI_MODE_NONE) {
    if (out_error != NULL) *out_error = "no mode: pass --listen or --connect";
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (options->address == NULL || options->address[0] == '\0') {
    if (out_error != NULL) *out_error = "no address: pass host:port";
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (options->timeout_ms == 0U) {
    if (out_error != NULL) *out_error = "a zero timeout would wait forever";
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* A hostile act is something a LISTENING PEER does after a handshake, so it is refused anywhere else: a
   * command line that asked for one and got a well-behaved peer would be a test that passes while testing
   * nothing. */
  if (options->hostile != NULL && options->mode != WT_CLI_MODE_LISTEN) {
    if (out_error != NULL) *out_error = "--hostile is a listening peer's option: it names the act it performs";
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* A Retry is something a SERVER does to a client. A client that asked for one would be asking to be
   * validated, which is not a thing it can request: refusing it here is cheaper than a session that ignores the
   * flag, and a flag that is silently ignored is a report nobody can trust. */
  if (options->retry != 0 && options->mode != WT_CLI_MODE_LISTEN) {
    if (out_error != NULL) *out_error = "--retry is a listener's option: it validates a client's address";
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* And the mirror image: parking an early stream is something a SERVER does. A listener that asked to SEND one
   * would be asking for an order it cannot be in -- the CONNECT is what makes it a server (WT-189). */
  if (options->early_stream != 0 && options->mode != WT_CLI_MODE_CONNECT) {
    if (out_error != NULL) *out_error = "--early-stream is a client's option: it sends before its CONNECT";
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* And the token is a property of the client's own CONNECT: a listener never sends one, so a listener that
   * asked for a token would be stating something about a request it does not make. Refused, not ignored, for the
   * same reason as the two above -- and only when the caller actually passed the flag, because the DEFAULT is a
   * valid token for every mode that does send one. */
  if (options->upgrade_token_set != 0 && options->mode != WT_CLI_MODE_CONNECT) {
    if (out_error != NULL) *out_error = "--upgrade-token is a client's option: it names the CONNECT's :protocol";
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The development bypass is tied to a loopback name in the API as well, but a tool that
   * accepts it for any address would be offering something the library will refuse later;
   * saying so here is the cheap place to say it. */
  if (options->trust == WT_CLI_TRUST_LOCAL_DEVELOPMENT) {
    if (strncmp(options->address, "localhost", 9U) != 0 &&
        strncmp(options->address, "127.0.0.1", 9U) != 0 &&
        strncmp(options->address, "[::1]", 5U) != 0) {
      /* The message is set INSIDE the refusal. It used to be set before the test and left standing when the
       * address passed, so `--trust local-development 127.0.0.1:4433` returned WT_OK with `*out_error` naming a
       * refusal that had not happened -- an output that contradicts the return value is worse than no output,
       * because a caller that logs it reports a failure that did not occur. */
      if (out_error != NULL) {
        *out_error = "the development bypass is refused for a non-loopback address";
      }
      return WT_ERR_INVALID_ARGUMENT;
    }
  }
  return WT_OK;
}

void wt_cli_options_write_json(const wt_cli_options_t *options, FILE *stream) {
  if (options == NULL || stream == NULL) return;
  fprintf(stream, "{\"mode\":\"%s\",\"address\":", wt_cli_mode_name(options->mode));
  if (options->address == NULL) {
    fprintf(stream, "null");
  } else {
    /* Escaped like every other caller-supplied string. The comment here used to say no escaping was needed and
     * that an escaper would be "a second, weaker implementation of one the library already owns" -- there was no
     * such implementation to reuse for a command line, and `--origin 'x","evil":1'` proved it by injecting a
     * member into the report an audit was reading. */
    wt_cli_write_json_string(stream, options->address);
  }
  fprintf(stream, ",\"transport\":\"%s\",\"trust\":\"%s\",\"trustSet\":%s",
          wt_cli_transport_name(options->transport), wt_cli_trust_name(options->trust),
          options->trust_set != 0 ? "true" : "false");
  fprintf(stream, ",\"origin\":");
  if (options->origin == NULL) {
    fprintf(stream, "null");
  } else {
    wt_cli_write_json_string(stream, options->origin);
  }
  fprintf(stream, ",\"authority\":");
  if (options->authority == NULL) {
    fprintf(stream, "null");
  } else {
    wt_cli_write_json_string(stream, options->authority);
  }
  fprintf(stream, ",\"protocol\":");
  if (options->protocol == NULL) {
    fprintf(stream, "null");
  } else {
    wt_cli_write_json_string(stream, options->protocol);
  }
  fprintf(stream, ",\"settingsValidation\":%s%s,\"exchange\":\"%s\",\"timeoutMs\":%llu",
          options->settings_validation != 0 ? "true" : "false",
          options->retry != 0 ? ",\"retry\":true" : "",
          wt_cli_exchange_name(options->exchange), (unsigned long long)options->timeout_ms);
  /* Which `:protocol` token the CONNECT carries, so the interop runner's per-peer selection is in the report a
   * reader weighs rather than only in the command line that produced it (F-02b). */
  fprintf(stream, ",\"upgradeToken\":\"%s\"", wt_cli_upgrade_token_name(options->upgrade_token));
  fprintf(stream, ",\"scenario\":%s,\"hostile\":", options->scenario_all != 0 ? "\"all\"" : "null");
  if (options->hostile == NULL) {
    fprintf(stream, "null");
  } else {
    wt_cli_write_json_string(stream, options->hostile);
  }
  fprintf(stream, ",\"json\":%s}\n",
          options->json != 0 ? "true" : "false");
}
