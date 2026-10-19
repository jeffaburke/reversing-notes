#!/usr/bin/env python3
"""
bcsolve.py — parse a Bulls & Cows (Mastermind) gamefile.bin and print the
solve steps for a chosen Game ID. Supports format versions 2, 3 and 4.

FILE HEADER (16 bytes, little-endian)
    0   4  magic "CBGF"
    4   4  version
    8   4  payload_size (= filesize - 16)
    12  4  entry_count

ENTRY HEADER (little-endian)
    0   4  game_id       (little-endian / byte-reversed)
    4   2  attempts
    6   2  key_length
    [v4 only] 16  salt          (prepended to each hashed guess)
    8/24 8  solution      (secret code as a LE integer)

AFTER THE HEADER
    [v4 only] attempts * 2 bytes : order[]  (uint16 permutation of 0..attempts-1)
    attempts * STEP_SIZE bytes   : steps
        v2 -> STEP_SIZE 6   ASCII "NNCNNB"
        v3 -> STEP_SIZE 32  SHA256( "NNCNNB" )
        v4 -> STEP_SIZE 32  SHA256( salt || "NNCNNB" )

USAGE
    python3 bcsolve.py gamefile.bin
    python3 bcsolve.py gamefile.bin 1049113847
    python3 bcsolve.py gamefile.bin --order    # apply the v4 order[] permutation
    python3 bcsolve.py gamefile.bin --hex      # FILE is hex text
"""

import sys
import argparse
import binascii
import hashlib

FILE_HEADER_LEN = 16
MAGIC           = b"CBGF"
STEP_ASCII      = 6
STEP_HASH       = 32


# ---------- feedback rainbow table (optionally salted) ----------

def feedback_candidates(keylen):
    for cows in range(keylen + 1):
        for bulls in range(keylen + 1):
            yield f"{cows:02d}C{bulls:02d}B"


def encodings(s):
    yield s.encode()
    yield (s + "\n").encode()
    yield s.encode() + b"\x00"


def build_hash_table(keylen, salt=b""):
    """digest -> feedback, over every candidate x encoding, with optional salt."""
    t = {}
    for cand in feedback_candidates(keylen):
        for b in encodings(cand):
            t[hashlib.sha256(salt + b).digest()] = cand
    return t


# ---------- helpers ----------

def byteswap32(n):
    return int.from_bytes((n & 0xFFFFFFFF).to_bytes(4, "little"), "big")


def load_bytes(path, as_hex):
    if as_hex:
        return binascii.unhexlify("".join(open(path).read().split()))
    return open(path, "rb").read()


def read_file_header(data):
    if data[:4] == MAGIC:
        version = int.from_bytes(data[4:8], "little")
        psize   = int.from_bytes(data[8:12], "little")
        count   = int.from_bytes(data[12:16], "little")
        if psize != len(data) - FILE_HEADER_LEN:
            sys.stderr.write(f"[!] payload_size={psize} but have "
                             f"{len(data)-FILE_HEADER_LEN} payload bytes.\n")
        return FILE_HEADER_LEN, count, version
    return 0, None, None


def parse(data, use_order):
    start, declared, version = read_file_header(data)
    if version is None:
        version = 2  # bare entries, assume oldest layout

    has_salt = (version >= 4)
    hashed   = (version >= 3)
    has_order = (version >= 4)
    step_size = STEP_HASH if hashed else STEP_ASCII

    entries = []
    p, n = start, len(data)

    while p + 8 <= n:
        gid_bytes = data[p:p + 4]
        game_id   = int.from_bytes(gid_bytes, "little")
        attempts  = int.from_bytes(data[p + 4:p + 6], "little")
        key_len   = int.from_bytes(data[p + 6:p + 8], "little")
        q = p + 8

        salt = b""
        if has_salt:
            salt = data[q:q + 16]; q += 16
        solution = int.from_bytes(data[q:q + 8], "little"); q += 8

        order = None
        if has_order:
            need = attempts * 2
            if q + need > n:
                sys.stderr.write(f"[!] entry {game_id}: truncated order[].\n")
                break
            order = [int.from_bytes(data[q + 2*i:q + 2*i + 2], "little")
                     for i in range(attempts)]
            q += need

        steps_size = attempts * step_size
        if q + steps_size > n:
            sys.stderr.write(f"[!] entry {game_id} (0x{game_id:08X}): wanted "
                             f"{steps_size} step bytes, only {n-q} left — "
                             f"stopping.\n")
            break
        raw = data[q:q + steps_size]
        p = q + steps_size

        if hashed:
            tbl = build_hash_table(key_len, salt)
            steps = [tbl.get(raw[i:i+STEP_HASH],
                             "??UNKNOWN(" + raw[i:i+6].hex() + "..)")
                     for i in range(0, steps_size, STEP_HASH)]
        else:
            steps = [raw[i:i+STEP_ASCII].decode("ascii", "replace")
                     for i in range(0, steps_size, STEP_ASCII)]

        # apply play-order permutation if present and requested
        if order is not None and use_order:
            try:
                steps = [steps[idx] for idx in order]
            except IndexError:
                sys.stderr.write(f"[!] entry {game_id}: order[] index out of "
                                 f"range; showing stored order.\n")

        entries.append({
            "game_id": game_id, "gid_bytes": gid_bytes,
            "attempts": attempts, "key_len": key_len,
            "solution": str(solution).zfill(key_len),
            "salt": salt.hex() if salt else None,
            "order": order, "steps": steps,
        })

    if declared is not None and declared != len(entries):
        sys.stderr.write(f"[!] header said {declared} entries, "
                         f"parsed {len(entries)}.\n")
    if p != n:
        sys.stderr.write(f"[!] {n - p} trailing byte(s) unparsed.\n")
    return entries, version, hashed, has_salt


def describe_step(s):
    if len(s) == 6 and s[2] == "C" and s[5] == "B":
        try:
            return f"{s}   ->  {int(s[0:2])} cow(s), {int(s[3:5])} bull(s)"
        except ValueError:
            pass
    return s


def show_entry(e, ordered):
    print("=" * 56)
    print(f" Game ID      : {e['game_id']}  (0x{e['game_id']:08X})")
    print(f" Stored bytes : {e['gid_bytes'].hex()}  (little-endian)")
    print(f" Attempts     : {e['attempts']}")
    print(f" Key length   : {e['key_len']}")
    print(f" Solution     : {e['solution']}")
    if e['salt']:
        print(f" Salt         : {e['salt']}")
    print("=" * 56)
    tag = " (play order)" if (ordered and e['order'] is not None) else \
          " (stored order)" if e['order'] is not None else ""
    print(f" Steps to solve{tag}:")
    for i, s in enumerate(e["steps"], 1):
        print(f"   {i:>3}. {describe_step(s)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("game_id", nargs="?", type=int)
    ap.add_argument("--hex", action="store_true")
    ap.add_argument("--order", action="store_true",
                    help="apply the v4 order[] permutation to the steps")
    args = ap.parse_args()

    data = load_bytes(args.file, args.hex)
    entries, version, hashed, has_salt = parse(data, args.order)
    index = {e["game_id"]: e for e in entries}

    mode = ("SHA256+salt steps" if has_salt else
            "SHA256 steps" if hashed else "ASCII steps")
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
    show_entry(entry, args.order)
    return 0


if __name__ == "__main__":
    sys.exit(main())
