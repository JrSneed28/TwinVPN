#!/usr/bin/env python3
"""Every shipped ABI's PT_LOAD alignment, read out of the APK itself.

===========================================================================
WHAT THIS ADDS OVER THE TWO CHECKS THAT ALREADY EXIST
===========================================================================
Three different things can be true at once, and only this one covers the third:

  * the instrumented test proves the ONE library the emulator maps loads on a
    16 KiB kernel. The emulator runs x86_64. It says nothing about arm64-v8a,
    which is what every actual phone runs;
  * `zipalign -c -P 16` proves each `.so` is 16 KiB-aligned WITHIN THE ZIP, so
    the loader can mmap it straight out of the APK. That is a property of the
    archive's layout;
  * this proves each `.so`'s own ELF PT_LOAD segments declare `p_align >=
    16384`, which is the property `-Wl,-z,max-page-size=16384` is supposed to
    produce and the one the kernel refuses on.

They fail independently. A build where the link flag was dropped for one ABI
still zipaligns perfectly and still passes on an x86_64 emulator; the failure
surfaces as an install-time refusal on a user's arm64 phone. That gap is the
whole reason this file exists.

===========================================================================
HOW IT READS THE ALIGNMENT, AND WHY NOT WITH readelf
===========================================================================
It parses the ELF program header table directly, with `struct`. The obvious
implementation shells out to `llvm-readelf --program-headers` and scrapes the
`Align` column, and it is a trap: GNU `readelf` wraps each LOAD entry across TWO
lines with the alignment on the continuation, `llvm-readelf` keeps it on one, and
which binary is on PATH under the name `readelf` differs per runner. A scraper
tuned to one of them silently finds zero LOAD rows under the other -- and "no
rows" reads identically to "no libraries", which is the exact
absence-versus-measurement confusion this check exists to remove.

The program header table is fixed-layout and forty years stable, so reading it
costs less than the scraper and cannot drift: `e_phoff`/`e_phentsize`/`e_phnum`
from the header, then `p_align` of every `p_type == PT_LOAD`, for both ELF32
(armeabi-v7a, x86) and ELF64 (arm64-v8a, x86_64). No NDK, no subprocess, nothing
to install on the runner.

The MINIMUM across LOAD segments is what counts: one under-aligned segment is
enough for the kernel to refuse the mapping, so a maximum or an average would
hide exactly the defect being looked for. An ABI whose `.so`s cannot be parsed
is a FAILURE, never a skip.

===========================================================================
USAGE
===========================================================================
    elf-align.py --apk app-release.apk
    elf-align.py --self-check

Prints a human-readable table to stderr and the evidence JSON to stdout:

    {"arm64-v8a": {"aligned": true, "min_p_align": 16384, "libraries": 2}, ...}

Exit 0 when every ABI is >= 16384, 1 otherwise.
"""

import argparse
import json
import pathlib
import struct
import sys
import zipfile

REQUIRED_ALIGN = 16384
PT_LOAD = 1


def load_aligns(blob: bytes) -> list[int]:
    """Every PT_LOAD segment's p_align, in file order.

    Returns [] for anything that is not a parseable ELF, which the caller treats
    as a failure rather than as an absence of segments.
    """
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        return []
    is64 = blob[4] == 2
    endian = "<" if blob[5] == 1 else ">"
    try:
        if is64:
            phoff, = struct.unpack_from(endian + "Q", blob, 0x20)
            phentsize, phnum = struct.unpack_from(endian + "HH", blob, 0x36)
        else:
            phoff, = struct.unpack_from(endian + "I", blob, 0x1C)
            phentsize, phnum = struct.unpack_from(endian + "HH", blob, 0x2A)
    except struct.error:
        return []
    # p_align is the last field of a program header in both classes; p_type is
    # the first in both. The two differ only in width and in where p_flags sits,
    # neither of which is read here.
    align_off = 0x30 if is64 else 0x1C
    fmt = endian + ("Q" if is64 else "I")
    out = []
    for i in range(phnum):
        base = phoff + i * phentsize
        if base + phentsize > len(blob) or phentsize < align_off + (8 if is64 else 4):
            return []
        p_type, = struct.unpack_from(endian + "I", blob, base)
        if p_type != PT_LOAD:
            continue
        align, = struct.unpack_from(fmt, blob, base + align_off)
        out.append(align)
    return out


def verdict(per_abi: dict) -> tuple[bool, list[str]]:
    """Whether every ABI holds, and one sentence per ABI that does not."""
    problems = []
    for abi, info in sorted(per_abi.items()):
        if info.get("libraries", 0) == 0:
            problems.append(
                f"{abi}: the APK carries lib/{abi}/ but no readable .so in it, "
                f"so nothing about its alignment was measured"
            )
        elif not info.get("aligned"):
            problems.append(
                f"{abi}: a PT_LOAD segment declares p_align "
                f"{info.get('min_p_align')}, below the {REQUIRED_ALIGN} a 16 KiB "
                f"kernel requires. This ABI's libraries will be REFUSED at load "
                f"time on a 16 KiB device -- most likely "
                f"-Wl,-z,max-page-size=16384 did not reach this target"
            )
    return not problems, problems


def scan(apk: pathlib.Path) -> dict:
    per_abi: dict[str, dict] = {}
    with zipfile.ZipFile(apk) as z:
        names = [n for n in z.namelist()
                 if n.startswith("lib/") and n.endswith(".so")]
        if not names:
            raise SystemExit(
                f"::error::{apk} carries no lib/*/*.so at all. The 16 KiB "
                f"criterion is about the shipped native libraries and this APK "
                f"has none, so it is not the artifact under test."
            )
        for name in names:
            abi = name.split("/")[1]
            info = per_abi.setdefault(
                abi, {"aligned": True, "min_p_align": None, "libraries": 0})
            info["libraries"] += 1
            aligns = load_aligns(z.read(name))
            if not aligns:
                # A PARSE FAILURE IS A FAILURE. A truncated entry, a file that
                # is not an ELF, a class this reader does not know -- all of them
                # mean this ABI was not measured, and an unmeasured ABI must not
                # inherit a measured one's verdict.
                info["aligned"] = False
                info["min_p_align"] = 0
                print(f"::error::{name} has no readable PT_LOAD program headers, "
                      f"so its load alignment could not be measured",
                      file=sys.stderr)
                continue
            low = min(aligns)
            if info["min_p_align"] is None or low < info["min_p_align"]:
                info["min_p_align"] = low
            if low < REQUIRED_ALIGN:
                info["aligned"] = False
    return per_abi


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", required=True, type=pathlib.Path)
    args = ap.parse_args()

    per_abi = scan(args.apk)
    ok, problems = verdict(per_abi)

    print(f"{'abi':<14} {'libs':>4} {'min p_align':>12}  result", file=sys.stderr)
    for abi, info in sorted(per_abi.items()):
        print(f"{abi:<14} {info['libraries']:>4} {info['min_p_align']:>12}  "
              f"{'OK' if info['aligned'] else 'UNDER-ALIGNED'}", file=sys.stderr)
    for p in problems:
        print(f"::error::{p}", file=sys.stderr)

    print(json.dumps(per_abi, sort_keys=True))
    return 0 if ok else 1


def self_check() -> int:
    # A synthesised ELF of each class, so both header layouts are exercised
    # without needing a cross-compiler on the machine running the check.
    def elf(is64: bool, aligns: list[int]) -> bytes:
        ent = 56 if is64 else 32
        hdr = bytearray(64 if is64 else 52)
        hdr[:4] = b"\x7fELF"
        hdr[4] = 2 if is64 else 1
        hdr[5] = 1
        phoff = len(hdr)
        if is64:
            struct.pack_into("<Q", hdr, 0x20, phoff)
            struct.pack_into("<HH", hdr, 0x36, ent, len(aligns))
        else:
            struct.pack_into("<I", hdr, 0x1C, phoff)
            struct.pack_into("<HH", hdr, 0x2A, ent, len(aligns))
        body = b""
        for a in aligns:
            ph = bytearray(ent)
            struct.pack_into("<I", ph, 0, PT_LOAD)
            struct.pack_into("<Q" if is64 else "<I", ph, 0x30 if is64 else 0x1C, a)
            body += bytes(ph)
        return bytes(hdr) + body

    assert load_aligns(elf(True, [0x4000, 0x4000])) == [0x4000, 0x4000]
    assert load_aligns(elf(False, [0x1000])) == [0x1000]
    assert load_aligns(b"not an elf at all") == []
    assert load_aligns(b"") == []

    # The minimum decides, not the maximum: one bad LOAD is a refused mapping.
    good = {"arm64-v8a": {"aligned": True, "min_p_align": 16384, "libraries": 2}}
    assert verdict(good) == (True, [])

    bad = {"arm64-v8a": {"aligned": False, "min_p_align": 4096, "libraries": 2}}
    ok, problems = verdict(bad)
    assert not ok and "max-page-size" in problems[0]

    # An ABI directory with nothing readable in it is a problem, not a pass.
    empty = {"x86_64": {"aligned": True, "min_p_align": None, "libraries": 0}}
    ok, problems = verdict(empty)
    assert not ok and "no readable .so" in problems[0]

    # Several bad ABIs report several problems, not just the first.
    assert len(verdict({**bad, **empty})[1]) == 2
    print("self-check passed")
    return 0


if __name__ == "__main__":
    sys.exit(self_check() if "--self-check" in sys.argv else main())
