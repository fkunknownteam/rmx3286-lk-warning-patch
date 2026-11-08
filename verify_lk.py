#!/usr/bin/env python3
"""Byte-diff verifier for patched lk images.

A log line from lkpatcher is not proof. This is.

usage:
  verify_lk.py STOCK PATCHED [OFF:HEXNEEDLE ...]

Checks, failing loudly on any violation:
  * identical sizes
  * the set of differing byte regions is EXACTLY the expected regions
    (each expected `OFF:NEEDLE` must show up as a region starting at OFF,
    old bytes == NEEDLE, new bytes == "00207047")
  * nothing after the last region differs (tail identical)

Exit code 0 only when everything passes.
"""
import sys

PATCH = bytes.fromhex("00207047")


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    sys.exit(1)


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)

    stock = open(sys.argv[1], "rb").read()
    patched = open(sys.argv[2], "rb").read()

    if len(stock) != len(patched):
        fail(f"size mismatch: stock={len(stock)} patched={len(patched)}")

    regions = []
    i, n = 0, len(stock)
    while i < n:
        if stock[i] != patched[i]:
            start = i
            while i < n and stock[i] != patched[i]:
                i += 1
            regions.append((start, i))
        else:
            i += 1

    expected = {}
    for arg in sys.argv[3:]:
        off, _, needle = arg.partition(":")
        expected[int(off, 16)] = bytes.fromhex(needle)

    problems = []

    if set(expected) != {s for s, _ in regions}:
        problems.append(
            f"region set mismatch\n"
            f"  expected offsets: {sorted(hex(o) for o in expected)}\n"
            f"  actual   offsets: {sorted(hex(s) for s, _ in regions)}"
        )

    for start, end in regions:
        old, new = stock[start:end], patched[start:end]
        exp = expected.get(start)
        print(f"  0x{start:06x} len={end - start}  {old.hex()} -> {new.hex()}")
        if exp is not None and old != exp:
            problems.append(f"0x{start:x}: old bytes {old.hex()} != expected needle {exp.hex()}")
        if new != PATCH:
            problems.append(f"0x{start:x}: new bytes {new.hex()} != {PATCH.hex()}")

    last = max((e for _, e in regions), default=0)
    if stock[last:] != patched[last:]:
        problems.append(f"tail after 0x{last:x} differs ({len(stock) - last} bytes checked)")

    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        sys.exit(1)

    print(f"OK: {len(regions)} regions, sizes {len(stock)}, tail identical")


if __name__ == "__main__":
    main()