#!/usr/bin/env python3
"""
bcsolve.py — parse a Bulls & Cows (Mastermind) gamefile.bin and print the
stored solve steps for a chosen Game ID.

FILE HEADER (optional, 16 bytes, all little-endian)
    offset  size  field
    0       4     magic         ASCII "CBGF"
    4       4     version
    8       4     payload_size  = filesize - 16
    12      4     entry_count   number of game entries that follow
If the "CBGF" magic is absent, the file is treated as raw back-to-back
entries starting at offset 0 (e.g. a single entry copied out on its own).

ENTRY FORMAT  (integers little-endian unless noted)
    offset  size        field
    0       4           game_id      stored little-endian / byte-reversed
    4       2           attempts     number of step instructions that follow
    6       2           key_length   digits in the solution (usually 4)
    8       8           solution     secret code, stored as a LE integer
    16      6*attempts  steps        ASCII, each step 6 bytes "NNCNNB"
                                     NN before C = cows  (right digit, wrong spot)
                                     NN before B = bulls (right digit, right spot)

USAGE
    python3 bcsolve.py gamefile.bin              # list IDs, then prompt
    python3 bcsolve.py gamefile.bin 908562386    # go straight to that ID
    python3 bcsolve.py gamefile.bin --hex        # input is a hex-text file
"""

import sys
import argparse
import binascii

# --- format constants (adjust here for a variant layout) ---
FILE_HEADER_LEN = 16
MAGIC           = b"CBGF"
ENTRY_HEADER    = 16   # game_id(4) + attempts(2) + key_length(2) + solution(8)
SOLUTION_BYTES  = 8
STEP_LEN        = 6    # "NNCNNB"


def byteswap32(n: int) -> int:
    """Reverse the 4 bytes of a 32-bit value (endianness swap)."""
    return int.from_bytes((n & 0xFFFFFFFF).to_bytes(4, "little"), "big")


def load_bytes(path: str, as_hex: bool) -> bytes:
    """Read a real binary file, or a text file of hex digits if as_hex."""
    if as_hex:
        text = open(path, "r").read()
        text = "".join(text.split())          # strip whitespace/newlines
        return binascii.unhexlify(text)
    return open(path, "rb").read()


def read_file_header(data: bytes):
    """Return (payload_start, declared_count, header_info)."""
    if data[:4] == MAGIC:
        version    = int.from_bytes(data[4:8],  "little")
        payload_sz = int.from_bytes(data[8:12], "little")
        count      = int.from_bytes(data[12:16], "little")
        if payload_sz != len(data) - FILE_HEADER_LEN:
            sys.stderr.write(
                f"[!] header payload_size={payload_sz} but file has "
                f"{len(data) - FILE_HEADER_LEN} payload bytes.\n")
        return FILE_HEADER_LEN, count, {"version": version}
    # No magic: assume raw entries from offset 0, count unknown.
    return 0, None, None


def parse(data: bytes):
    """Walk the file and return (entries, header_info)."""
    start, declared_count, hinfo = read_file_header(data)
    entries = []
    p, n = start, len(data)

    while p + ENTRY_HEADER <= n:
        gid_bytes = data[p:p + 4]
        game_id   = int.from_bytes(gid_bytes, "little")
        attempts  = int.from_bytes(data[p + 4:p + 6], "little")
        key_len   = int.from_bytes(data[p + 6:p + 8], "little")
        solution  = int.from_bytes(data[p + 8:p + 16], "little")
        p += ENTRY_HEADER

        steps_size = attempts * STEP_LEN
        if p + steps_size > n:
            sys.stderr.write(
                f"[!] entry {game_id} (0x{game_id:08X}): expected {steps_size} "
                f"step bytes but only {n - p} remain — stopping.\n")
            break

        raw = data[p:p + steps_size]
        p += steps_size
        steps = [raw[i:i + STEP_LEN].decode("ascii", "replace")
                 for i in range(0, steps_size, STEP_LEN)]

        entries.append({
            "game_id":   game_id,
            "gid_bytes": gid_bytes,
            "attempts":  attempts,
            "key_len":   key_len,
            "solution":  str(solution).zfill(key_len),
            "steps":     steps,
        })

    if declared_count is not None and declared_count != len(entries):
        sys.stderr.write(f"[!] header said {declared_count} entries, "
                         f"parsed {len(entries)}.\n")
    if p != n:
        sys.stderr.write(f"[!] {n - p} trailing byte(s) left unparsed.\n")
    return entries, hinfo


def describe_step(s: str) -> str:
    """Turn 'NNCNNB' into a human line; fall back to raw if malformed."""
    if len(s) == 6 and s[2] == "C" and s[5] == "B":
        try:
            cows, bulls = int(s[0:2]), int(s[3:5])
            return f"{s}   ->  {cows} cow(s), {bulls} bull(s)"
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
    ap = argparse.ArgumentParser(description="Bulls & Cows gamefile parser.")
    ap.add_argument("file", help="path to gamefile.bin")
    ap.add_argument("game_id", nargs="?", type=int,
                    help="Game ID in decimal (optional; prompts if omitted)")
    ap.add_argument("--hex", action="store_true",
                    help="treat FILE as a text file of hex digits, not binary")
    args = ap.parse_args()

    data = load_bytes(args.file, args.hex)
    entries, hinfo = parse(data)
    index = {e["game_id"]: e for e in entries}

    hdr = f" (version {hinfo['version']})" if hinfo else " (no file header)"
    print(f"Parsed {len(entries)} entr{'y' if len(entries)==1 else 'ies'} "
          f"from {args.file}{hdr}\n")
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
        print(f"\nGame ID {gid} not found (also tried byte-swapped "
              f"{byteswap32(gid)}).")
        return 1

    print()
    show_entry(entry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
