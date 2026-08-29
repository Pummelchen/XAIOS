#ifndef XAIOS_CRASH_WRITER_H
#define XAIOS_CRASH_WRITER_H

/*
 * Ingest a staged xaiFS package one chunk at a time, committing each, and
 * keep going until the package is full or the machine dies.
 *
 * Built only under XAIOS_CRASH_WRITER=1, and paired with the crash fixture
 * from tests/xai_fs/create_crash_fixture.py: the pattern it writes is the one
 * that fixture signed, so a chunk that reaches the volume wrong fails its
 * checksum rather than passing. The gate cuts power partway through and then
 * checks what survived.
 */
void crash_writer_run(void);

#endif
