#!/usr/bin/env python3
"""Locate the function that prints a boot screen, given the screen's strings.

usage:
  find_handler.py IMAGE KEY_HEX_STRING [--entry]

Background: MTK lk takes string references with the Thumb idiom

    ldr r0, [pc, #imm]      ; T1 literal load -> W (a delta)
    add r0, pc              ; register add with rm == pc
    ; string_addr = (addr_of_add + 4) + W == file offset  (base == 0)

so absolute-pointer/xref scans find nothing while this pairing always resolves.
Steps: find every T1 literal load, read its pool word, pair it with a following
add-reg pc, solve for each requested string offset, cluster by loader site;
the densest cluster is the printing block. Then (optionally) scan backwards from
the cluster for the function's entry `push {..., lr}`.

Only dependencies: capstone (pip install capstone). No third-party lk parsers.
"""
import struct
import sys

import capstone as cm
from capstone.arm_const import ARM_REG_PC


def solve(image: bytes, offsets: list[int], window: int = 16):
    md = cm.Cs(cm.CS_ARCH_ARM, cm.CS_MODE_THUMB)
    clusters = {t: [] for t in offsets}
    n = len(image)
    for addr in range(0, n - 4, 2):
        h1 = struct.unpack_from("<H", image, addr)[0]
        if (h1 >> 11) != 0b01001:          # T1 ldr rt, [pc, #imm8*4]
            continue
        imm8 = h1 & 0xFF
        pool = ((addr + 4) & ~3) + imm8 * 4
        if not (0 <= pool <= n - 4):
            continue
        w = struct.unpack_from("<I", image, pool)[0]
        if w > 0x7FFFFFFF:                   # negative deltas are not strings here
            continue
        for off in range(2, window + 1, 2):
            b = addr + off
            if b + 2 > n:
                break
            h2 = struct.unpack_from("<H", image, b)[0]
            if (h2 & 0xFF00) != 0x4400:      # add rd, rm (reg form)
                continue
            if ((h2 >> 3) & 0xF) != 0xF:     # rm == pc
                continue
            solved = (b + 4) + w
            if solved in clusters:
                clusters[solved].append((addr, b, pool, w))
    return clusters


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if len(args) < 2:
        print(__doc__)
        sys.exit(2)

    image = open(args[0], "rb").read()
    offsets = [int(x, 16) for x in args[1:]]

    clusters = solve(image, offsets)
    for t, rows in clusters.items():
        print(f"  0x{t:x}: {len(rows)} reference(s)")

    if not any(clusters.values()):
        print("FAIL: no paired reference found for any string (different idiom?)")
        sys.exit(1)

    # Strings printed by one handler are referenced from nearby loaders;
    # score each loader by how many distinct strings resolve close to it.
    best_score, best_rows, lo_floor, lo_ceiling = 0, [], 0, 0
    for rows in clusters.values():
        for loader, _, _, _ in rows:
            near = []
            for off, others in clusters.items():
                rr = [r for r in others if abs(r[0] - loader) <= 0x60]
                if rr:
                    near.append((off, rr))
            if len(near) > best_score:
                best_score = len(near)
                best_rows = [r for _, rr in near for r in rr]
                loaders = [r[0] for _, rr in near for r in rr]
                lo_floor, lo_ceiling = min(loaders), max(loaders)

    if best_score == 0:
        print("FAIL: strings found but no shared loader site (different idiom?)")
        sys.exit(1)

    print(f"\nhandler cluster: {best_score}/{len(offsets)} strings referenced from "
          f"loaders in 0x{lo_floor:x}..0x{lo_ceiling:x}")

    entry = None
    anchor = min(r[1] for r in best_rows)
    md = cm.Cs(cm.CS_ARCH_ARM, cm.CS_MODE_THUMB)
    for addr in range(anchor, max(0, anchor - 0x800), -2):
        try:
            ins = next(md.disasm(image[addr:addr + 4], addr))
        except StopIteration:
            continue
        if ins.mnemonic == "push" and "lr" in ins.op_str:
            entry = addr
            break

    if "--entry" in flags:
        if entry is None:
            print("FAIL: could not walk back to a push {..., lr} prologue")
            sys.exit(1)
        print(f"entry push @ 0x{entry:x}: bytes {image[entry:entry + 8].hex()}")
        print(f'patch json needle: "{image[entry:entry + 8].hex()}" -> "00207047"')
    else:
        print(f"entry candidate (re-run with --entry to confirm bytes): "
              f"0x{entry:x}" if entry else "entry check skipped")


if __name__ == "__main__":
    main()