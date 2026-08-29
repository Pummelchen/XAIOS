#ifndef XAIOS_ENGINE_SHA256_DISPATCH_H
#define XAIOS_ENGINE_SHA256_DISPATCH_H

/*
 * Select the engine's SHA-256 compressor for this CPU.
 *
 * Call once, early, before anything hashes: it asks whether the ARMv8 SHA2
 * extension is present and, if so, checks the accelerated compressor against
 * the scalar reference before installing it. A disagreement leaves the scalar
 * path in place. Everything that verifies a model chunk goes through whatever
 * this chose.
 */
void engine_sha256_dispatch_init(void);

#endif
