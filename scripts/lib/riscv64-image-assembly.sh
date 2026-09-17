# The same 4 MiB volume shape the other architectures' test image uses, with
# the marker the boot-storage check reads in sector zero and the rofs from
# sector one.
rm -f "$IMAGE"
dd if=/dev/zero of="$IMAGE" bs=512 count=65536 status=none
printf 'XAIOS-VIRTIO-BLOCK-TEST\n' | \
  dd of="$IMAGE" bs=512 count=1 conv=notrunc status=none
"$PYTHON3" "$ROOT_DIR/scripts/create-initfs.py" \
  "$IMAGE" \
  "$BUILD_DIR/init.elf" \
  "$BUILD_DIR/service-manager.elf" \
  "$BUILD_DIR/worker.elf" \
  "$ROOT_DIR/userspace/init/xaios-init.conf" \
  "$ROOT_DIR/userspace/service-manager/source-index.svc" \
  $APP_ARGS \
  $HOSTED_ARGS \
  $XAPT_ARGS \
  $SSHD_ARGS \
  $CREDENTIAL_ARGS \
  $AUTHORIZED_KEYS_ARGS \
  $CLIENT_IDENTITY_ARGS \
  "/etc/xapt.conf=$ROOT_DIR/userspace/init/xapt.conf" \
  "$@"
printf '%s\n' "Created $IMAGE"
