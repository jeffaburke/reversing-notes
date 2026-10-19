#!/usr/bin/env python3
"""
bcsolve.py — parse a Bulls & Cows (Mastermind) gamefile.bin and print the
solve steps for a chosen Game ID.  Handles two step encodings:

    * version 2 : each step is 6 ASCII bytes  "NNCNNB"
    * version 3 : each step is a 32-byte SHA256 digest of that "NNCNNB"
                  string.  SHA256 isn't reversible, but the set of valid
                  feedback strings is tiny, so we precompute their hashes
                  once and look each stored digest up.

FILE HEADER (16 bytes, little-endian)
    0   4  magic "CBGF"
    4   4  version
    8   4  payload_size (= filesize - 16)
    12  4  entry_count

ENTRY HEADER (16 bytes, little-endian)
    0   4  game_id       (little-endian / byte-reversed)
    4   2  attempts      (number of steps that follow)
    6   2  key_length    (digits in the solution, usually 4)
    8   8  solution      (secret code as a LE integer)
    then: attempts * STEP_SIZE bytes of steps
          STEP_SIZE = 6  (v2, ASCII)  or  32 (v3, SHA256)

USAGE
    python3 bcsolve.py gamefile.bin
    python3 bcsolve.py gamefile.bin 1697721937
    python3 bcsolve.py gamefile.bin --hex           # FILE is hex text
    python3 bcsolve.py gamefile.bin --stepmode hash # force hashed mode
"""

import sys
import argparse
import binascii
import hashlib

FILE_HEADER_LEN = 16
MAGIC           = b"CBGF"
ENTRY_HEADER    = 16
STEP_ASCII      = 6
STEP_HASH       = 32    # SHA256 digest length


# ---------- feedback-string rainbow table (for hashed files) ----------

def feedback_candidates(keylen: int):
    """All plausible 'NNCNNB' strings for a key length (generous enumeration)."""
    for cows in range(0, keylen + 1):
        for bulls in range(0, keylen + 1):
            yield f"{cows:02d}C{bulls:02d}B"


def encodings(s: str):
    """Byte variants a program might hash. Add here if the real one differs."""
    yield "ascii",         s.encode()
    yield "ascii+newline", (s + "\n").encode()
    yield "ascii+null",    s.encode() + b"\x00"


def build_hash_table(keylen: int):
    """digest -> feedback string, over every candidate x encoding."""
    table = {}
    for cand in feedback_candidates(keylen):
        for _, b in encodings(cand):
            table[hashlib.sha256(b).digest()] = cand
    return table


# ---------- core parsing ----------

def byteswap32(n: int) -> int:
    return int.from_bytes((n & 0xFFFFFFFF).to_bytes(4, "little"), "big")


def load_bytes(path: str, as_hex: bool) -> bytes:
    if as_hex:
        return binascii.unhexlify("".join(open(path).read().split()))
    return open(path, "rb").read()


def read_file_header(data: bytes):
    if data[:4] == MAGIC:
        version = int.from_bytes(data[4:8], "little")
        psize   = int.from_bytes(data[8:12], "little")
        count   = int.from_bytes(data[12:16], "little")
        if psize != len(data) - FILE_HEADER_LEN:
            sys.stderr.write(f"[!] payload_size={psize} but have "
                             f"{len(data)-FILE_HEADER_LEN} payload bytes.\n")
        return FILE_HEADER_LEN, count, version
    return 0, None, None


def parse(data: bytes, stepmode: str):
    start, declared, version = read_file_header(data)

    # Decide step encoding: explicit flag wins, else infer from version.
    if stepmode == "ascii":
        step_size, hashed = STEP_ASCII, False
    elif stepmode == "hash":
        step_size, hashed = STEP_HASH, True
    else:  # auto
        hashed = (version is not None and version >= 3)
        step_size = STEP_HASH if hashed else STEP_ASCII

    table = {}  # built lazily per key length so variants are supported
    entries = []
    p, n = start, len(data)

    while p + ENTRY_HEADER <= n:
        gid_bytes = data[p:p + 4]
        game_id   = int.from_bytes(gid_bytes, "little")
        attempts  = int.from_bytes(data[p + 4:p + 6], "little")
        key_len   = int.from_bytes(data[p + 6:p + 8], "little")
        solution  = int.from_bytes(data[p + 8:p + 16], "little")
        p += ENTRY_HEADER

        steps_size = attempts * step_size
        if p + steps_size > n:
            sys.stderr.write(f"[!] entry {game_id} (0x{game_id:08X}): wanted "
                             f"{steps_size} step bytes, only {n-p} left — "
                             f"stopping.\n")
            break
        raw = data[p:p + steps_size]
        p += steps_size

        steps = []
        if hashed:
            if key_len not in table:
                table[key_len] = build_hash_table(key_len)
            tbl = table[key_len]
            for i in range(0, steps_size, STEP_HASH):
                dg = raw[i:i + STEP_HASH]
                steps.append(tbl.get(dg, "??UNKNOWN(" + dg[:4].hex() + "..)"))
        else:
            for i in range(0, steps_size, STEP_ASCII):
                steps.append(raw[i:i + STEP_ASCII].decode("ascii", "replace"))

        entries.append({
            "game_id": game_id, "gid_bytes": gid_bytes,
            "attempts": attempts, "key_len": key_len,
            "solution": str(solution).zfill(key_len), "steps": steps,
        })

    if declared is not None and declared != len(entries):
        sys.stderr.write(f"[!] header said {declared} entries, "
                         f"parsed {len(entries)}.\n")
    if p != n:
        sys.stderr.write(f"[!] {n - p} trailing byte(s) unparsed.\n")
    return entries, version, hashed


def describe_step(s: str) -> str:
    if len(s) == 6 and s[2] == "C" and s[5] == "B":
        try:
            return f"{s}   ->  {int(s[0:2])} cow(s), {int(s[3:5])} bull(s)"
        except ValueError:
            pass
    return s


def show_entry(e: dict) -> None:
    print("=" * 56)
    print(f" Game ID      : {e['game_id']}  (0x{e['game_id']:08X})")
    print(f" Stored bytes : {e['gid_bytes'].hex()}  (little-endian)")
    print(f" Attempts     : {e['attempts']}")
    print(f" Key length   : {e['key_len']}")
    print(f" Solution     : {e['solution']}")
    print("=" * 56)
    print(" Steps to solve:")
    for i, s in enumerate(e["steps"], 1):
        print(f"   {i:>3}. {describe_step(s)}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("game_id", nargs="?", type=int)
    ap.add_argument("--hex", action="store_true")
    ap.add_argument("--stepmode", choices=["auto", "ascii", "hash"],
                    default="auto")
    args = ap.parse_args()

    data = load_bytes(args.file, args.hex)
    entries, version, hashed = parse(data, args.stepmode)
    index = {e["game_id"]: e for e in entries}

    mode = "SHA256-hashed steps" if hashed else "ASCII steps"
    print(f"Parsed {len(entries)} entries from {args.file} "
          f"(version {version}, {mode})\n")
    print("Available Game IDs:")
    for e in entries:
        print(f"  {e['game_id']:<12} 0x{e['game_id']:08X}  "
              f"bytes={e['gid_bytes'].hex()}  attempts={e['attempts']:<3} "
              f"keylen={e['key_len']}  solution={e['solution']}")

    gid = args.game_id
    if gid is None:
        try:
            gid = int(input("\nEnter Game ID (decimal): ").strip())
        except (ValueError, EOFError):
            print("No valid Game ID entered.")
            return 1

    entry = index.get(gid) or index.get(byteswap32(gid))
    if entry is None:
        print(f"\nGame ID {gid} not found (also tried swapped "
              f"{byteswap32(gid)}).")
        return 1
    print()
    show_entry(entry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
