#!/usr/bin/env python3
"""
r2-style Yan85 disassembler.

usage: python3 yan85dis.py [hexfile] [--no-color]
       (no hexfile -> uses CODE_HEX below)
"""
import re
import sys

CODE_HEX = "b84002010840010440ff0202020840020440080001040001080808040408040810000401000801150202020204ff02020201400002020201100302020202040102010040013008026404020901020202024002400200010140020001020102104b02020201049b0202020c040800010400010100010001010004010008011740020800010400010100010104022004404b02020200014502020200015902020200013a02020200012002020200010501020108020204200001010004010008010800010400010100013004020b01020008020201200001010004010008012440020104022004404302020200014f02020200015202020200015202020200014502020200014302020200015402020200012102020200012002020200015902020200016f02020200017502020200017202020200012002020200016602020200016c02020200016102020200016702020200013a02020200010a02020200011401020108020204202f02028001020201806602028101020201806c0202820102020180610202830102020180670202840102020180000202850102020180800802000402020820000402200440ff01020008020208400201200004022004400001020201400108020204200008020010200104022004404902020200014e02020200014302020200014f02020200015202020200015202020200014502020200014302020200015402020200012102020200010a02020200010b0102010802020420010802001020370202620102020180c30202630102020180110202640102020180720202650102020180900202660102020180610202670102020180ec02026801020201803d0202690102020180c202026a01020201804b02026b01020201807e02026c01020201802b40020000"

# ---------------------------------------------------------------------------
# Per-level encoding (these get randomized, so they live up here)
# ---------------------------------------------------------------------------
INST_LEN = 3
ARG2_IDX, ARG1_IDX, OP_IDX = 0, 1, 2

REG = {1: 'c', 2: 'd', 4: 'b', 8: 'a', 0x10: 'f', 0x20: 's', 0x40: 'i'}
SYS = {1: 'read_memory', 2: 'read_code', 4: 'write', 0x20: 'sleep', 8: 'open', 0x10: 'exit'}
# Must be in the same order the interpreter tests the bits
OPS = [(2, 'imm'), (0x40, 'add'), (1, 'stk'), (0x80, 'stm'), (8, 'ldm'),
       (0x10, 'cmp'), (4, 'jmp'), (0x20, 'sys')]
CON = {8: '<', 4: '>', 1: '==', 2: '!=', 0x10: '==0'}

# Which registers each syscall reads, for the argument comment
SYS_ARGS = {
    'read_memory': ('fd', 'a'), 'read_code': ('fd', 'a'),
    'write': ('fd', 'a'), 'open': ('path', 'a'),
    'sleep': ('secs', 'a'), 'exit': ('code', 'a'),
}

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty() and '--no-color' not in sys.argv
def col(code):
    return (lambda s: f"\x1b[{code}m{s}\x1b[0m") if USE_COLOR else (lambda s: s)
C_ADDR, C_BYTES, C_MNEM, C_JMP = col('32'), col('90'), col('1;37'), col('1;33')
C_REG, C_IMM, C_CMT, C_LABEL = col('36'), col('35'), col('34'), col('1;31')
C_ARROW, C_STR = col('33'), col('1;32')

reg = lambda x: REG.get(x, 'NONE' if x == 0 else f'?{x:#x}')

# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------
class Insn:
    def __init__(self, n, raw):
        self.n = n
        self.raw = raw
        self.a2, self.a1, self.op = raw[ARG2_IDX], raw[ARG1_IDX], raw[OP_IDX]
        self.names = [name for bit, name in OPS if self.op & bit]
        self.text = []        # list of (mnemonic, operands) for display
        self.comments = []
        self.target = None    # resolved jump/call destination
        self.kind = None      # 'jmp', 'cjmp', 'call', 'ret'

def decode(code):
    return [Insn(n, code[n * INST_LEN:(n + 1) * INST_LEN])
            for n in range(len(code) // INST_LEN)]

# ---------------------------------------------------------------------------
# Analysis: constant tracking, jump/call resolution, string recovery
# ---------------------------------------------------------------------------
def analyze(insns):
    known = {}      # reg name -> value, reset at control flow
    mem = {}        # constant stores done with stm
    pushed = []     # characters pushed in the current run
    targets = set(i.target for i in insns if i.target is not None)

    def val(r, n):
        return n + 1 if r == 'i' else known.get(r)   # i is pre-incremented

    def flush(at):
        nonlocal pushed
        if len(pushed) >= 2:
            s = ''.join(pushed).encode('unicode_escape').decode()
            at.comments.append(C_STR(f'"{s}"') + C_CMT(' (pushed)'))
        pushed = []

    prev = None
    for ins in insns:
        n = ins.n
        r1, r2 = reg(ins.a1), reg(ins.a2)
        for name in ins.names:
            if name == 'imm':
                ch = f"  '{chr(ins.a2)}'" if 0x20 <= ins.a2 < 0x7f else ''
                if r1 == 'i':
                    ins.target = ins.a2
                    is_call = (prev is not None and prev.kind == 'push_ret')
                    ins.kind = 'call' if is_call else 'jmp'
                    ins.text.append(('call' if is_call else 'jmp', C_IMM(f'{ins.a2:#04x}')))
                    known.clear()
                else:
                    known[r1] = ins.a2
                    ins.text.append(('imm', f'{C_REG(r1)}, {C_IMM(f"{ins.a2:#04x}")}'))
                    if ch:
                        ins.comments.append(C_CMT(ch.strip()))
            elif name == 'add':
                v1, v2 = val(r1, n), val(r2, n)
                known.pop(r1, None)
                if v1 is not None and v2 is not None:
                    known[r1] = (v1 + v2) & 0xff
                    ins.comments.append(C_CMT(f'{r1} = {known[r1]:#04x}'))
                ins.text.append(('add', f'{C_REG(r1)}, {C_REG(r2)}'))
            elif name == 'stk':
                if ins.a2:
                    v = val(r2, n)
                    ins.text.append(('push', C_REG(r2)))
                    if v is not None and (0x20 <= v < 0x7f or v == 0x0a):
                        pushed.append(chr(v))
                    else:
                        flush(ins)
                    if v is not None and r2 != 'i' and v == n + 2:
                        ins.kind = 'push_ret'   # return address for a following call
                        ins.comments.append(C_CMT(f'return address {v:#04x}'))
                if ins.a1:
                    if r1 == 'i':
                        ins.text.append(('ret', ''))
                        ins.kind = 'ret'
                        known.clear()
                    else:
                        ins.text.append(('pop', C_REG(r1)))
                        known.pop(r1, None)
            elif name == 'stm':
                p, v = val(r1, n), val(r2, n)
                if p is not None and v is not None:
                    mem[p] = v
                    ins.comments.append(C_CMT(f'[{p:#04x}] = {v:#04x}'))
                ins.text.append(('stm', f'[{C_REG(r1)}], {C_REG(r2)}'))
            elif name == 'ldm':
                known.pop(r1, None)
                ins.text.append(('ldm', f'{C_REG(r1)}, [{C_REG(r2)}]'))
            elif name == 'cmp':
                ins.text.append(('cmp', f'{C_REG(r1)}, {C_REG(r2)}'))
            elif name == 'jmp':
                cond = ' | '.join(v for k, v in CON.items() if ins.a1 & k)
                mnem = f'j[{cond}]' if cond else 'jmp'
                ins.kind = 'cjmp' if cond else 'jmp'
                t = val(r2, n)
                if t is not None:
                    ins.target = t
                ins.text.append((mnem, C_REG(r2)))
                if not cond:
                    known.clear()
            elif name == 'sys':
                calls = [v for k, v in SYS.items() if ins.a1 & k] or [f'{ins.a1:#x}']
                for c in calls:
                    args = []
                    if c in ('read_memory', 'read_code', 'write'):
                        a, b, cc = val('a', n), val('b', n), val('c', n)
                        fmt = lambda x: '?' if x is None else f'{x:#x}'
                        args = [f'fd={fmt(a)}', f'buf={fmt(b)}', f'n={fmt(cc)}']
                    elif c == 'open':
                        a = val('a', n)
                        path = ''
                        if a is not None:
                            s = []
                            p = a
                            while mem.get(p, 0):
                                s.append(chr(mem[p])); p += 1
                            path = f' "{"".join(s)}"' if s else ''
                        args = [f'path={a:#x}{path}' if a is not None else 'path=?']
                    elif c in ('exit', 'sleep'):
                        a = val('a', n)
                        args = [f'{a:#x}' if a is not None else '?']
                    ins.comments.append(C_CMT(f'{c}({", ".join(args)})'))
                ins.text.append(('sys', f'{C_IMM(f"{ins.a1:#04x}")}, {C_REG(r2)}'))
                known.pop(r2, None)
        if not ins.names:
            ins.text.append(('???', ''))
        if not any(nm in ('imm', 'stk') for nm in ins.names):
            flush(ins)
        if ins.target is not None and ins.kind in ('jmp', 'cjmp', 'call'):
            ins.comments.append(C_CMT(f'-> {ins.target:#04x}'))
        prev = ins
    flush(insns[-1])

# ---------------------------------------------------------------------------
# Labels, xrefs and arrows
# ---------------------------------------------------------------------------
def build_labels(insns):
    labels, xrefs = {}, {}
    for ins in insns:
        if ins.target is None:
            continue
        xrefs.setdefault(ins.target, []).append(ins)
        name = f'fcn_{ins.target:02x}' if ins.kind == 'call' else f'loc_{ins.target:02x}'
        if ins.target not in labels or ins.kind == 'call':
            labels[ins.target] = name
    labels.setdefault(0, 'entry')
    return labels, xrefs

def build_arrows(insns):
    edges = [(i.n, i.target) for i in insns
             if i.target is not None and i.kind in ('jmp', 'cjmp') and i.target < len(insns)]
    edges.sort(key=lambda e: abs(e[0] - e[1]))
    lanes = []   # list of lists of (lo, hi)
    placed = []
    for s, d in edges:
        lo, hi = min(s, d), max(s, d)
        for k, lane in enumerate(lanes):
            if all(hi < a or lo > b for a, b in lane):
                lane.append((lo, hi)); placed.append((s, d, k)); break
        else:
            lanes.append([(lo, hi)]); placed.append((s, d, len(lanes) - 1))
    width = max(1, len(lanes)) * 2 + 1
    rows = {}
    for n in range(len(insns)):
        line = [' '] * width
        for s, d, k in placed:
            x = width - 3 - 2 * k
            lo, hi = min(s, d), max(s, d)
            if lo < n < hi and line[x] == ' ':
                line[x] = '│'
            elif n in (lo, hi):
                line[x] = '┌' if n == lo else '└'
                for j in range(x + 1, width - 1):
                    if line[j] in (' ', '│'):
                        line[j] = '─'
                line[width - 1] = '>' if n == d else '<'
        rows[n] = ''.join(line)

    def passthrough(n):
        # Lanes that continue through the header lines printed above row n
        line = [' '] * width
        for s, d, k in placed:
            if min(s, d) < n <= max(s, d):
                line[width - 3 - 2 * k] = '│'
        return ''.join(line)

    return rows, width, passthrough

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    hexstr = open(args[0]).read() if args else CODE_HEX
    code = bytearray.fromhex(''.join(hexstr.split()))
    insns = decode(code)
    analyze(insns)
    labels, xrefs = build_labels(insns)
    arrows, width, passthrough = build_arrows(insns)

    for ins in insns:
        if ins.n in labels:
            pad = C_ARROW(passthrough(ins.n))
            print(pad)
            refs = xrefs.get(ins.n, [])
            if labels[ins.n].startswith('fcn_'):
                print(f'{pad} {C_LABEL("┌ " + labels[ins.n])}')
            else:
                print(f'{pad} {C_LABEL(";-- " + labels[ins.n] + ":")}')
            for r in refs:
                kind = {'call': 'CALL', 'cjmp': 'CJMP', 'jmp': 'JMP'}[r.kind]
                print(f'{pad} {C_CMT(f"; {kind} XREF from {r.n:#04x}")}')
        raw = ' '.join(f'{b:02x}' for b in ins.raw)
        body = '; '.join(
            f'{(C_JMP if m in ("jmp", "call", "ret") or m.startswith("j[") else C_MNEM)(m.ljust(7))} {ops}'
            for m, ops in ins.text)
        # pad using visible length, ignoring color escapes
        vis = len(re.sub(r'\x1b\[[0-9;]*m', '', body))
        cmt = ('  ' + ' '*max(0, 26 - vis) + C_CMT('; ') + C_CMT(', ').join(ins.comments)) if ins.comments else ''
        print(f'{C_ARROW(arrows[ins.n])} {C_ADDR(f"0x{ins.n:02x}")}  {C_BYTES(raw)}   {body}{cmt}')
    leftover = len(code) % INST_LEN
    if leftover:
        print(C_CMT(f'\n; {leftover} trailing byte(s): {code[-leftover:].hex(" ")}'))

if __name__ == '__main__':
    main()
