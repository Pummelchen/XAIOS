#ifndef XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_META_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_META_INTERNAL_H

/*
 * The stat, mkdir, touch and write handlers of remote_login_meta.c.
 *
 * They were static in remote_login.c's boot-test arm, so remote_login.c's
 * dispatcher could name them by definition order. The split makes them cross a
 * translation-unit boundary: they lose `static` and are declared here. The
 * guard is the same one they were born under, so a configuration with
 * XAIOS_BOOT_TEST_APPS off compiles neither the definitions nor these
 * declarations -- exactly the code it compiled before.
 */

#include <xaios/status.h>
#include <xaios/types.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

#if XAIOS_BOOT_TEST_APPS

xaios_status_t handle_stat(const char *arg, char *output,
                           uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t handle_mkdir(const char *args, char *output,
                            uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t handle_touch(const char *arg, char *output,
                            uint64_t output_capacity, uint64_t *output_bytes);
xaios_status_t handle_write(const char *path_arg, const char *payload,
                            char *output, uint64_t output_capacity,
                            uint64_t *output_bytes);

#endif /* XAIOS_BOOT_TEST_APPS */

#endif /* XAIOS_KERNEL_RUNTIME_REMOTE_LOGIN_META_INTERNAL_H */
