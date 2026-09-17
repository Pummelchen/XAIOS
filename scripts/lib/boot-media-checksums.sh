# Sourced by scripts/build-boot-media.sh; not a standalone script.
#
# The tail of the run: a per-kit SHA256SUMS over each staged kit, then the
# release archives and the summary. It runs in the caller's shell and
# reuses sha_of, ARCHS, BUILD_NUMBER, RELEASE_DIR, STAGE_ROOT and the $KITS
# the kit pass above filled in.

# ------------------------------------------------------------- checksums
# Per-kit, and covering the kit's own files rather than the release as a whole,
# so `shasum -c` works in the directory a person extracted without them having
# to fetch anything else.
for kit in $KITS; do
  ( cd "$kit" && find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort |
      while read -r file; do
        printf '%s  %s\n' "$(sha_of "$file")" "$file"
      done > SHA256SUMS )
done

# -------------------------------------------------------------- archives
printf '%s\n' "XAIOS build $BUILD_NUMBER boot media kits"
for kit in $KITS; do
  name=$(basename "$kit")
  archive="$RELEASE_DIR/$name.zip"
  rm -f "$archive"
  ( cd "$STAGE_ROOT" && zip -qr "$archive" "$name" )
  printf '  %s\n' "$name.zip"
  printf '    %s bytes\n' "$(wc -c < "$archive" | tr -d ' ')"
  printf '    SHA-256 %s\n' "$(sha_of "$archive")"
done
for arch in $ARCHS; do
  printf '  image %-8s %s\n' "$arch" \
    "$(sha_of "$RELEASE_DIR/xaios_b${BUILD_NUMBER}-${arch}.iso")"
done
