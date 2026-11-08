#!/bin/sh
# Patch a dumped RMX3286 lk image and byte-verify the result before flashing.
#
#   ./build_and_check.sh lk.bin
#
# Needs: lkpatcher (https://github.com/R0rt1z2/lkpatcher), python3, capstone not required.
# Produces: lk-patched.bin + a PASS/FAIL byte diff. Never flash on FAIL.
set -e

STOCK="${1:-lk.bin}"
OUT="${2:-lk-patched.bin}"
HERE="$(dirname "$0")"

[ -f "$STOCK" ] || { echo "stock dump '$STOCK' not found (dump with: mtk r lk lk.bin)"; exit 2; }

echo "== patching $STOCK -> $OUT (NO --patch-policies: known data-loss bug in lkpatcher 4.3.0)"
lkpatcher "$STOCK" -j "$HERE/verity_patch.json" -o "$OUT" --log-level DEBUG

echo "== byte verification"
python3 "$HERE/verify_lk.py" "$STOCK" "$OUT" \
    45e68:f0b50024 \
    45f38:08b50a4b \
    596a6:38b53224 \
    67158:f0b5adf5

echo
echo "verified. flash it:"
echo "  fastboot flash lk $OUT && fastboot reboot"
echo "rollback:"
echo "  fastboot flash lk $STOCK"