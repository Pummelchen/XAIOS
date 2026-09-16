/* The one JSON string writer the tools share.
 *
 * It exists because the same defect was found twice in two files: `report.c` escaped a quote and a backslash and
 * nothing else, and `options.c` escaped nothing at all and carried a comment saying no escaping was needed -- so
 * `wt-client-c99 --origin 'x","evil":1'` printed a field section no JSON reader could parse, and a report whose
 * detail contained a newline produced two lines where the contract (`report.h`) promises one object per line. A
 * value a caller supplied with a control byte in it is the same class of bug as a malformed report: it is the
 * difference between "this tool printed what it was given" and "this tool printed something else".
 *
 * RFC 8259 requires the quotation mark and the backslash to be escaped, and the C0 controls (0x00-0x1f) to be
 * escaped too -- the short forms where they exist and `\u00XX` otherwise. This is a private header with a static
 * function, like the platform layer's, so two translation units share one implementation without a new symbol. */

#ifndef WEBTRANSPORT_CLI_JSON_H
#define WEBTRANSPORT_CLI_JSON_H

#include <stdio.h>
#include <string.h>

static void wt_cli_write_json_string(FILE *stream, const char *text) {
  size_t i;

  if (stream == NULL) return;
  fputc('"', stream);
  if (text != NULL) {
    for (i = 0U; text[i] != '\0'; i++) {
      unsigned char c = (unsigned char)text[i];
      switch (c) {
        case '"': fputs("\\\"", stream); continue;
        case '\\': fputs("\\\\", stream); continue;
        case '\b': fputs("\\b", stream); continue;
        case '\f': fputs("\\f", stream); continue;
        case '\n': fputs("\\n", stream); continue;
        case '\r': fputs("\\r", stream); continue;
        case '\t': fputs("\\t", stream); continue;
        default: break;
      }
      if (c < 0x20U) {
        fprintf(stream, "\\u%04x", (unsigned)c);
      } else {
        fputc((int)c, stream);
      }
    }
  }
  fputc('"', stream);
}

#endif /* WEBTRANSPORT_CLI_JSON_H */
