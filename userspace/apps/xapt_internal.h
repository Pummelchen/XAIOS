#ifndef XAIOS_XAPT_INTERNAL_H
#define XAIOS_XAPT_INTERNAL_H

#include <xaios_user.h>

/* The private surface shared by xapt's translation units. `xapt.c` keeps the
   command implementations and `main`; the repository index it reads lives in
   `xapt_catalog.c`, and the TCP/TLS transfer lives in `xapt_http.c`. Types,
   constants and buffers are declared once here so no definition is duplicated,
   and every function named below is defined in exactly one of the three. */

#define XAPT_BUFFER_BYTES 4096U
#define XAPT_LINE_BYTES 1024U
#define XAPT_PATH_BYTES 160U
#define XAPT_HOST_BYTES 80U
#define XAPT_CONFIG_PATH "/state/xapt/config"
#define XAPT_CATALOG_PATH "/state/xapt/catalog"
#define XAPT_STAGED_CATALOG_PATH "/update/xapt/catalog"
#define XAPT_STAGED_TRUST_PATH "/update/xapt/trust"
/* The build this tool reports as the running system's, matching what the
   kernel's app store compares a package's minimum against. */
#define XAPT_OS_BUILD 1
#define XAPT_TLS_MODULUS_HEX_BYTES 512U

typedef struct xapt_config {
  char host[XAPT_HOST_BYTES];
  /* Optional literal to dial instead of resolving `host`. The name still
     identifies the origin: it is what goes in the Host header and what any
     certificate is checked against. Set this to reach an origin whose name
     the resolver cannot yet return, and drop it once it can. */
  char address[XAPT_HOST_BYTES];
  char base[64];
  u64 port;
  u32 tls_required;
  char tls_rsa_modulus[XAPT_TLS_MODULUS_HEX_BYTES + 1U];
} xapt_config_t;

typedef struct xapt_app_record {
  char name[32];
  char version[24];
  char architecture[16];
  char minimum_os[24];
  char manifest_path[XAPT_PATH_BYTES];
  char binary_path[XAPT_PATH_BYTES];
  char description[128];
} xapt_app_record_t;

typedef struct xapt_os_record {
  char version[24];
  u32 generation;
  char architecture[16];
  u64 size;
  unsigned char hash[32];
  char signature[320];
  char image_path[XAPT_PATH_BYTES];
} xapt_os_record_t;

typedef int (*xapt_sink_t)(const unsigned char *data, u32 size, void *context);

/* Buffers and counters the three translation units share. They are defined in
   xapt.c and reach the modules through these declarations. */
extern char xapt_buffer[XAPT_BUFFER_BYTES];
extern char xapt_catalog[131073U];
extern u64 xapt_request_id;
extern u32 xapt_http_error;
extern u32 xapt_control_status;
extern u64 xapt_http_received;
extern u64 xapt_http_expected;

/* Repository index: record parsing and lookup, defined in xapt_catalog.c. */
const char *xapt_architecture(void);
int xapt_text_equal(const char *left, const char *right);
int xapt_text_starts(const char *text, const char *prefix);
int xapt_copy_text(char *output, u64 capacity, const char *input, u64 length);
int xapt_parse_u64(const char *text, u64 length, u64 *value);
int xapt_path_valid(const char *path);
int xapt_read_catalog(void);
int xapt_parse_app_line(const char *line, u64 length,
                        xapt_app_record_t *record);
int xapt_find_app(const char *name, xapt_app_record_t *record);
int xapt_find_os(xapt_os_record_t *record);
int xapt_installed_version(const char *name, char version[24]);
int xapt_version_compare(const char *left, const char *right);

/* Transfer: HTTP over a plain socket or a xapt_tls session, defined in
   xapt_http.c. `sink` receives the response body in arrival order. */
int xapt_http_get(const xapt_config_t *config, const char *catalog_path,
                  xapt_sink_t sink, void *sink_context, u64 *body_size);
int xapt_http_download(const xapt_config_t *config, const char *remote_path,
                       const char *local_path, u64 *size);

#endif
