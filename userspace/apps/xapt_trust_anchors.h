#ifndef XAIOS_XAPT_TRUST_ANCHORS_H
#define XAIOS_XAPT_TRUST_ANCHORS_H

#include <bearssl.h>

/* Root certificates the updater's chain is validated against, generated from
   userspace/apps/trust by scripts/gen-xapt-trust-anchors.py. */
extern const br_x509_trust_anchor XAPT_TRUST_ANCHORS[];
extern const size_t XAPT_TRUST_ANCHORS_COUNT;

#endif
