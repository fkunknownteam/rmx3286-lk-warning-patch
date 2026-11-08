# rmx3286 lk "Your device is corrupt" warning remover

Realme narzo 50 (**RMX3286**, codename `spaced`, MT6781/Helio G96): removes the boot-time
dm-verity / avb screen that blocks every boot until you press the power key, and kills its
5-second "device will power off in 5s" countdown:

```
dm-verity corruption
Your device is corrupt.
It can't be trusted and may not work properly.
Press power button to continue!        <- forced keypress every boot
Or, device will power off in %ds       <- 50 x 100 ms timer -> shutdown @0x1c168
```

Everything here is a **patch recipe for YOUR OWN dumped lk image** — no bootloader binaries
are shipped. Dump first, patch, verify the byte diff, then flash.

## Root cause (what was actually on the device)

The five strings live inside the `lk` partition at (file offset == virtual address, base 0):

| offset  | string |
|---------|--------|
| 0xa429c | `dm-verity corruption` |
| 0xa42b4 | `Your device is corrupt.` |
| 0xa42d0 | `It can't be trusted and may not work properly.` |
| 0xa4300 | `Press power button to continue!` |
| 0xa4324 | `Or, device will power off in %ds` |

All five are referenced from **one handler function whose prologue sits at `0x596a6`**
(bytes `38 b5 32 24`, unique in the image):

```asm
0x0596a6: push  {r3, r4, r5, lr}     ; ENTRY  <-- patch here
0x0596a8: movs  r4, #0x32            ; 50 iterations
          ... print the 4 lines via bl 0x33cb4 ...
0x0596e2: movs  r1, #5               ; "%ds" argument -> "5s"
          ...
0x0596f0: movs  r0, #0x64            ; loop: sleep 100 ms
0x0596f8: subs  r4, r4, #1           ;       50 x 100 ms = 5 s
0x0596fc: bl    #0x4be8              ;       poll key
0x059704: pop   {r3, r4, r5, pc}     ; key pressed -> return -> boot continues
0x059706: pop.w {r3, r4, r5, lr}
0x05970a: b.w   #0x1c168             ; timeout   -> SHUTDOWN
```

The fix is the same idiom lkpatcher itself uses for its default categories: replace the
first 4 bytes of the entry with `00 20 70 47` (`movs r0, #0` + `bx lr`), so the handler
returns 0 instantly — no text, no forced keypress, no 5 s power-off.

**Why stock lkpatcher did not fix it:** `lkpatcher`'s `dm_verity` category contains a
single build-variant needle (`30b583b002ab0022`) which does not exist in this ROM build
(exact-byte search fails: `Needle not found`). Debug the match state with
`--log-level DEBUG`; `--dry-run` output is an unconditional listing and **lies** about
matches.

## Build the patched image

```bash
# 1. dump stock lk first (mtkclient, phone off, hold both volume keys + USB):
mtk r lk lk.bin

# 2. patch ( lkpatcher https://github.com/R0rt1z2/lkpatcher ):
lkpatcher lk.bin -j verity_patch.json -o lk-patched.bin --log-level DEBUG

# 3. verify BEFORE flashing:
python3 verify_lk.py lk.bin lk-patched.bin \
    45e68:f0b50024 45f38:08b50a4b 596a6:38b53224 67158:f0b5adf5
```

`verify_lk.py` asserts: same size, exactly the expected diff regions, each region is a
clean `needle -> 00207047` rewrite, and everything from the last region to EOF is
byte-identical. A log line is not proof; a byte diff is.

> **DO NOT pass `--patch-policies` together with patching (lkpatcher 4.3.0 bug):** it
> truncates the output container to 1274128 bytes and can silently drop the code patches
> while still printing `Successfully applied patch`. Verified repeatedly on 2026-11-08.

### The default patches this recipe relies on

`verity_patch.json` uses `"mode": "update"`, so lkpatcher's stock categories still apply,
those that match this build (3 of them):

- `red_state`   @ 0x045e68 — verification-warning printer returns immediately
- `orange_state`@ 0x045f38 — LCS-state check always 0  (variant B does not exist here)
- `fastboot`    @ 0x067158 — oplusreserve unlock-bit check returns 0  (variant A absent)

Expected diff for stock RMX3286 build: **exactly 4 regions of 4 bytes**:

```
0x045e68: f0b50024 -> 00207047
0x045f38: 08b50a4b -> 00207047
0x0596a6: 38b53224 -> 00207047     <- this repo's fix
0x067158: f0b5adf5 -> 00207047
```

## Flash it (and roll back)

fastboot works for `lk` on RMX3286 (bootloader unlocked):

```bash
fastboot flash lk lk-patched.bin     # Sending (5120 KB) ... Finished, 0.2 s
fastboot reboot
```

Rollback with the untouched dump you kept locally:

```bash
fastboot flash lk lk.bin
```

`mtk w lk <img>` from mtkclient BROM mode (power off, hold both volume keys, plug USB) is
the alternative when fastboot is unavailable.

### Golden rules

1. Dump *before* patching; never distribute your dump — stock and patched images are
   device-specific, contain vendor code, and are your only unbrick path.
2. Verify the byte diff before every flash (see above).
3. A half-written `lk` on this device is recoverable via BROM + `mtk w lk lk.bin` — keep
   the cable and a working PC near, don't panic-flash from random sources.
4. Read-back proof after flash, when you want certainty: power off → BROM → `mtk r lk
   /tmp/verify.bin` → `sha256sum` vs your patched file.

## How the handler was located (reproducible)

`find_handler.py` implements the technique — it needs only `strings` offsets and the
image:

1. Grab the string offsets (`fd` = `str.encode()` search, base 0 verified empirically).
2. ARM32/Thumb never stores absolute string pointers here. The idiom is two instructions:

   ```asm
   ldr r0, [pc, #imm]   ; T1 literal load: halfword >> 11 == 0b01001
                        ;   W = word at align4(addr+4) + imm8*4   (a DELTA)
   add r0, pc           ; reg-add with rm == pc
   ; string_addr = (addr_of_add + 4) + W
   ```

3. Pair every T1 literal load with an `add rd,pc` in the following 4–16 bytes and check
   `(B + 4) + W == string_offset`. All five offsets solve with **one** pairing site
   (0x596c0…0x596e4) — that cluster *is* the handler.
4. Disassemble backwards for the entry `push {..., lr}` = `0x596a6`.

```bash
python3 find_handler.py lk.bin 0xa42b4 0xa42d0 0xa4300 0xa4324 0xa429c
# -> handler candidates: 0x596c0 (5/5 strings paired); entry push @ 0x596a6
```

Works unchanged on other MTK lk images for any screen you can locate by string text.

## Scope / results

- Tested device: Realme narzo 50 RMX3286 (`spaced`), `lk` dump sha256
  `ff687bf97eb9ea52a90e9478c3d7b26ef1cd1a3bb7132490f7d5bf514bd2dee5`, lkpatcher 4.3.0.
- Patched image sha256 `72a85a2eb24397b9a7105d2e96efc8e07aabfe712ac9a62f4127d0b6e5638e9e`.
- Effect: boot goes straight to the OS — no corrupt-text block, no power-key gate, no
  5-second power-off; recovery/fastboot unchanged; rollback verified on the same device.

MIT licensed (see LICENSE). Flashing bootloaders can brick devices — you own the risk,
keep the stock dump, and double-check every byte diff before writing.