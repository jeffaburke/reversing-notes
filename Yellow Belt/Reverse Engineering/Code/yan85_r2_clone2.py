#!/usr/bin/env python3
"""
r2-style Yan85 disassembler with register, stack and memory tracking.

usage:
    python3 yan85dis2.py [code.hex] [--mem mem.hex] [--mem-unknown] [--no-color]

    code.hex       bytecode as hex (default: CODE_HEX below)
    --mem FILE     initial contents of the 0x100-byte memory/stack area as hex
                   (shorter input is zero padded). Default: all zeros, which is
                   what main() sets up before the interpreter starts.
    --mem-unknown  start with every memory byte unknown instead of zero
    --no-color     plain output

The analysis follows every path from instruction 0 without merging, so loops
are walked one iteration at a time and each ldm sees concrete addresses.
Values derived from input show as '?', and a branch that depends on them is
explored both ways. If an instruction is reached in too many distinct states
(VISIT_CAP), its states are merged so the analysis always finishes.
"""
import re
import sys

CODE_HEX = "b84002010840010440ff0202020840020440080001040001080808040408040810000401000801150202020204ff02020201400002020201100302020202040102010040013008026404020901020202024002400200010140020001020102104b02020201049b0202020c040800010400010100010001010004010008011740020800010400010100010104022004404b02020200014502020200015902020200013a02020200012002020200010501020108020204200001010004010008010800010400010100013004020b01020008020201200001010004010008012440020104022004404302020200014f02020200015202020200015202020200014502020200014302020200015402020200012102020200012002020200015902020200016f02020200017502020200017202020200012002020200016602020200016c02020200016102020200016702020200013a02020200010a02020200011401020108020204202f02028001020201806602028101020201806c0202820102020180610202830102020180670202840102020180000202850102020180800802000402020820000402200440ff01020008020208400201200004022004400001020201400108020204200008020010200104022004404902020200014e02020200014302020200014f02020200015202020200015202020200014502020200014302020200015402020200012102020200010a02020200010b0102010802020420010802001020370202620102020180c30202630102020180110202640102020180720202650102020180900202660102020180610202670102020180ec02026801020201803d0202690102020180c202026a01020201804b02026b01020201807e02026c01020201802b40020000"

# ---------------------------------------------------------------------------
# Per-level encoding (randomized between levels, so it all lives up here)
# ---------------------------------------------------------------------------
INST_LEN = 3
ARG2_IDX, ARG1_IDX, OP_IDX = 1, 2, 0
MEM_SIZE = 0x100

REG = {1: 'd', 2: 'i', 4: 'c', 8: 'f', 0x10: 'a', 0x20: 'b', 0x40: 's'}
SYS = {8: 'read_memory', 1: 'read_code', 0x20: 'write', 0x4: 'sleep', 0x10: 'open', 0x2: 'exit'}
# Must be in the same order the interpreter tests the bits
OPS = [(0x20, 'imm'), (0x10, 'add'), (0x80, 'stk'), (0x8, 'stm'), (4, 'ldm'),
       (0x1, 'cmp'), (2, 'jmp'), (0x40, 'sys')]
CON = {2: '<', 4: '>', 0x10: '==', 0x1: '!=', 0x8: '==0'}
FLAG = {v: k for k, v in CON.items()}

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
USE_COLOR = sys.stdout.isatty() and '--no-color' not in sys.argv
def col(code):
    return (lambda s: f"\x1b[{code}m{s}\x1b[0m") if USE_COLOR else (lambda s: s)
C_ADDR, C_BYTES, C_MNEM, C_JMP = col('32'), col('90'), col('1;37'), col('1;33')
C_REG, C_IMM, C_CMT, C_LABEL = col('36'), col('35'), col('34'), col('1;31')
C_ARROW, C_STR, C_DIM = col('33'), col('1;32'), col('2')
strip_ansi = lambda s: re.sub(r'\x1b\[[0-9;]*m', '', s)

reg = lambda x: REG.get(x, 'NONE' if x == 0 else f'?{x:#x}')
hx = lambda v: '?' if v is None else f'{v:#04x}'

def as_str(vals):
    """Bytes (possibly with unknowns) -> printable string, or None."""
    if not vals or any(v is None for v in vals):
        return None
    s = ''.join(chr(v) for v in vals)
    return s.encode('unicode_escape').decode()

# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------
class Insn:
    def __init__(self, n, raw):
        self.n, self.raw = n, raw
        self.a2, self.a1, self.op = raw[ARG2_IDX], raw[ARG1_IDX], raw[OP_IDX]
        self.names = [name for bit, name in OPS if self.op & bit]
        self.text = self.render()
        self.comments = []
        self.target = None   # jump/call destination for labels and arrows
        self.kind = None     # 'jmp', 'cjmp', 'call', 'ret'
        self.reached = False

    def render(self):
        r1, r2 = reg(self.a1), reg(self.a2)
        out = []
        for name in self.names:
            if name == 'imm':
                if r1 == 'i':
                    out.append(('jmp', C_IMM(f'{self.a2:#04x}')))
                else:
                    out.append(('imm', f'{C_REG(r1)}, {C_IMM(f"{self.a2:#04x}")}'))
            elif name == 'add':
                out.append(('add', f'{C_REG(r1)}, {C_REG(r2)}'))
            elif name == 'stk':
                if self.a2:
                    out.append(('push', C_REG(r2)))
                if self.a1:
                    out.append(('ret', '') if r1 == 'i' else ('pop', C_REG(r1)))
            elif name == 'stm':
                out.append(('stm', f'[{C_REG(r1)}], {C_REG(r2)}'))
            elif name == 'ldm':
                out.append(('ldm', f'{C_REG(r1)}, [{C_REG(r2)}]'))
            elif name == 'cmp':
                out.append(('cmp', f'{C_REG(r1)}, {C_REG(r2)}'))
            elif name == 'jmp':
                cond = ' | '.join(v for k, v in CON.items() if self.a1 & k)
                out.append((f'j[{cond}]' if cond else 'jmp', C_REG(r2)))
            elif name == 'sys':
                out.append(('sys', f'{C_IMM(f"{self.a1:#04x}")}, {C_REG(r2)}'))
        return out or [('???', '')]

def decode(code):
    return [Insn(n, code[n * INST_LEN:(n + 1) * INST_LEN])
            for n in range(len(code) // INST_LEN)]

# ---------------------------------------------------------------------------
# Abstract state: None means "unknown"
# ---------------------------------------------------------------------------
class State:
    def __init__(self, regs, mem):
        self.regs = regs    # name -> int or None  (i is implicit)
        self.mem = mem      # list[MEM_SIZE] of int or None

    def copy(self):
        return State(dict(self.regs), list(self.mem))

    def merge(self, other):
        """Keep only values both states agree on. Returns True if self changed."""
        changed = False
        for k in self.regs:
            if self.regs[k] is not None and self.regs[k] != other.regs.get(k):
                self.regs[k] = None
                changed = True
        for a in range(MEM_SIZE):
            if self.mem[a] is not None and self.mem[a] != other.mem[a]:
                self.mem[a] = None
                changed = True
        return changed

def step(ins, st, notes=None):
    """
    Execute one instruction on an abstract state.
    Returns (new_state, successors) where successors is a list of instruction
    indexes, plus None if control goes somewhere unknown.
    If notes is a list, human-readable comments are appended to it.
    """
    st = st.copy()
    n = ins.n
    nxt = n + 1            # value of i while this instruction runs
    branches = []          # extra successors from conditional jumps
    halted = False
    note = notes.append if notes is not None else (lambda s: None)

    def get(r):
        if r == 'i':
            return nxt
        if r == 'NONE':
            return 0
        return st.regs.get(r)

    def put(r, v):
        nonlocal nxt
        if r == 'i':
            nxt = v
        elif r != 'NONE':
            st.regs[r] = None if v is None else v & 0xff

    def mread(addr):
        return None if addr is None else st.mem[addr & 0xff]

    def mwrite(addr, v):
        if addr is None:
            st.mem = [None] * MEM_SIZE   # unknown address: could be anywhere
        else:
            st.mem[addr & 0xff] = v

    info = {}
    r1, r2 = reg(ins.a1), reg(ins.a2)
    for name in ins.names:
        if name == 'imm':
            if r1 == 'i':
                sp = get('s')
                info['top'] = mread(sp)
            put(r1, ins.a2)
            if r1 != 'i' and 0x20 <= ins.a2 < 0x7f:
                note(f"'{chr(ins.a2)}'")

        elif name == 'add':
            v1, v2 = get(r1), get(r2)
            v = None if v1 is None or v2 is None else (v1 + v2) & 0xff
            put(r1, v)
            if v is not None and r1 != 'i':
                note(f'{r1} = {hx(v)}')

        elif name == 'stk':
            if ins.a2:                                   # push: s++, mem[s] = r2
                v = get(r2)
                s = get('s')
                s = None if s is None else (s + 1) & 0xff
                put('s', s)
                mwrite(s, v)
                note(f'[{hx(s)}] = {hx(v)}')
            if ins.a1:                                   # pop: r1 = mem[s], s--
                s = get('s')
                v = mread(s)
                put(r1, v)
                put('s', None if s is None else s - 1)
                if r1 == 'i':
                    note(f'return to {hx(v)}')
                elif ins.a2 and r1 != 'NONE':
                    note(f'{r1} = {r2} ({hx(v)})')
                else:
                    note(f'{r1} = [{hx(s)}] = {hx(v)}')

        elif name == 'stm':
            p, v = get(r1), get(r2)
            mwrite(p, v)
            note(f'[{hx(p)}] = {hx(v)}')

        elif name == 'ldm':
            p = get(r2)
            v = mread(p)
            put(r1, v)
            note(('ldm', r1, p, v))

        elif name == 'cmp':
            x, y = get(r1), get(r2)
            if x is None or y is None:
                put('f', None)
            else:
                f = 0
                f |= FLAG['<'] if x < y else 0
                f |= FLAG['>'] if x > y else 0
                f |= FLAG['=='] if x == y else 0
                f |= FLAG['!='] if x != y else 0
                f |= FLAG['==0'] if x == 0 and y == 0 else 0
                put('f', f)
                note(f'{hx(x)} vs {hx(y)}')

        elif name == 'jmp':
            t = get(r2)
            info['jtarget'] = t
            if ins.a1 == 0:
                put('i', t)
            else:
                f = get('f')
                if f is None:
                    branches.append(t)                   # maybe taken
                    note(('jmp', '?'))
                elif f & ins.a1:
                    put('i', t)
                    note(('jmp', 'taken'))
                else:
                    note(('jmp', 'not taken'))

        elif name == 'sys':
            calls = [v for k, v in SYS.items() if ins.a1 & k] or [f'{ins.a1:#x}']
            a, b, c = get('a'), get('b'), get('c')
            for call in calls:
                if call in ('read_memory', 'write', 'read_code'):
                    if b is None or c is None:
                        count = None
                    else:
                        limit = MEM_SIZE - b
                        if call == 'read_code':
                            limit = (MEM_SIZE - b) * INST_LEN
                        count = min(c, limit)
                    args = f'fd={hx(a)}, buf={hx(b)}, n={hx(count)}'
                    if call == 'write' and b is not None and count is not None:
                        s = as_str(st.mem[b:b + count])
                        if s is not None:
                            args += ', ' + C_STR(f'"{s}"')
                    if call == 'read_memory':
                        if b is None or count is None:
                            st.mem = [None] * MEM_SIZE
                        else:
                            for k in range(b, b + count):
                                st.mem[k] = None
                    note(f'{call}({args})')
                elif call == 'open':
                    path = None
                    if a is not None:
                        chars, p = [], a
                        while p < MEM_SIZE and st.mem[p] not in (0, None):
                            chars.append(st.mem[p]); p += 1
                        if p < MEM_SIZE and st.mem[p] == 0:
                            path = as_str(chars)
                    shown = C_STR(f'"{path}"') if path is not None else hx(a)
                    note(f'open(path={shown}, flags={hx(b)})')
                elif call == 'exit':
                    note(f'exit({hx(a)})')
                    halted = True
                elif call == 'sleep':
                    note(f'sleep({hx(a)})')
                else:
                    note(f'sys {call}')
            put(r2, None)                                # return value unknown

    succ = [] if halted else [nxt] + branches
    return st, succ, info

# ---------------------------------------------------------------------------
# Analysis
#
# Paths are explored separately (no merging) so loops are walked iteration by
# iteration and each ldm sees concrete addresses. An instruction visited more
# than VISIT_CAP times switches to a merged state, which keeps the analysis
# finite for long or input-dependent loops.
# ---------------------------------------------------------------------------
VISIT_CAP = 64
STEP_LIMIT = 200000

def state_key(n, st):
    return (n, tuple(sorted(st.regs.items())), tuple(st.mem))

def explore(insns, init_mem):
    regs0 = {r: 0 for r in REG.values() if r != 'i'}
    work = [(0, State(regs0, list(init_mem)))]
    seen = set()
    visits = {}
    widened = {}
    records = {}   # n -> list of (notes, info), one per distinct visit
    steps = 0

    while work:
        steps += 1
        if steps > STEP_LIMIT:
            print(C_CMT('; analysis stopped early: step limit reached'))
            break
        n, st = work.pop()
        if not (0 <= n < len(insns)):
            continue
        key = state_key(n, st)
        if key in seen:
            continue
        seen.add(key)

        visits[n] = visits.get(n, 0) + 1
        if visits[n] > VISIT_CAP:
            # Too many distinct states here: fall back to one merged state
            if n not in widened:
                widened[n] = st.copy()
            elif not widened[n].merge(st):
                continue
            st = widened[n].copy()

        insns[n].reached = True
        notes = []
        new_state, succ, info = step(insns[n], st, notes)
        records.setdefault(n, []).append((notes, info))
        for s_ in succ:
            if s_ is not None:
                work.append((s_, new_state))
    return records

def summarize_ldm(items):
    r1 = items[0][1]
    pairs = sorted({(p, v) for _, _, p, v in items},
                   key=lambda pv: (pv[0] is None, pv[0] or 0))
    if len(pairs) == 1:
        p, v = pairs[0]
        ch = f" '{chr(v)}'" if v is not None and 0x20 <= v < 0x7f else ''
        return f'{r1} = [{hx(p)}] = {hx(v)}{ch}'
    addrs = [p for p, _ in pairs]
    if None not in addrs and len(set(addrs)) == len(addrs) and addrs == list(range(addrs[0], addrs[-1] + 1)):
        vals = ' '.join('??' if v is None else f'{v:02x}' for _, v in pairs)
        text = f'{r1} = [{addrs[0]:#04x}..{addrs[-1]:#04x}] = {vals}'
        s = as_str([v for _, v in pairs])
        if s is not None and all(0x20 <= v < 0x7f for _, v in pairs):
            text += ' ' + C_STR(f'"{s}"')
        return text
    shown = ', '.join(f'[{hx(p)}]={hx(v)}' for p, v in pairs[:6])
    more = f' (+{len(pairs) - 6} more)' if len(pairs) > 6 else ''
    return f'{r1} = {shown}{more}'

def summarize(note_lists):
    out = []
    width = max((len(nl) for nl in note_lists), default=0)
    for k in range(width):
        items = []
        for nl in note_lists:
            if k < len(nl) and nl[k] not in items:
                items.append(nl[k])
        if not items:
            continue
        first = items[0]
        if isinstance(first, tuple) and first[0] == 'ldm':
            out.append(summarize_ldm([x for x in items if isinstance(x, tuple)]))
        elif isinstance(first, tuple) and first[0] == 'jmp':
            outcomes = {x[1] for x in items}
            if outcomes == {'taken'}:
                out.append('always taken')
            elif outcomes == {'not taken'}:
                out.append('never taken')
            elif '?' in outcomes and len(outcomes) == 1:
                out.append('taken: ?')
            else:
                out.append('taken on some paths')
        else:
            out.append(merge_strings([str(x) for x in items]))
    return out

HEX_RE = re.compile(r'0x[0-9a-f]+')

def fmt_values(vals):
    vals = sorted(set(vals))
    if len(vals) == 1:
        return f'{vals[0]:#04x}'
    if len(vals) > 2 and vals == list(range(vals[0], vals[-1] + 1)):
        return f'{vals[0]:#04x}..{vals[-1]:#04x}'
    shown = ','.join(f'{v:#04x}' for v in vals[:4])
    return '{' + shown + (',...' if len(vals) > 4 else '') + '}'

def merge_strings(strs):
    """'a = 0x38', 'a = 0x37', ... -> 'a = 0x30..0x38'"""
    if len(strs) == 1:
        return strs[0]
    templates = {HEX_RE.sub('{}', x) for x in strs}
    if len(templates) == 1:
        tpl = templates.pop()
        slots = list(zip(*[[int(h, 16) for h in HEX_RE.findall(x)] for x in strs]))
        return tpl.replace('{}', '%s') % tuple(fmt_values(v) for v in slots)
    if len(strs) <= 4:
        return ' | '.join(strs)
    return ' | '.join(strs[:3]) + f' (+{len(strs) - 3} more)'

def analyze(insns, init_mem):
    records = explore(insns, init_mem)
    for ins in insns:
        recs = records.get(ins.n)
        if not recs:
            continue
        ins.comments = [x if '\x1b' in x else C_CMT(x) for x in summarize([r[0] for r in recs])]
        infos = [r[1] for r in recs]

        r1 = reg(ins.a1)
        if 'imm' in ins.names and r1 == 'i':
            ins.target = ins.a2
            is_call = any(i.get('top') == ins.n + 1 for i in infos)
            ins.kind = 'call' if is_call else 'jmp'
            if is_call:
                ins.text = [('call', t[1]) if t[0] == 'jmp' else t for t in ins.text]
        elif 'stk' in ins.names and r1 == 'i':
            ins.kind = 'ret'
        elif 'jmp' in ins.names:
            targets = {i.get('jtarget') for i in infos}
            ins.kind = 'jmp' if ins.a1 == 0 else 'cjmp'
            if len(targets) == 1 and None not in targets:
                ins.target = targets.pop()
            elif targets - {None}:
                ins.comments.append(C_CMT('-> ' + ' | '.join(hx(t) for t in sorted(targets - {None}))))
        if ins.target is not None and ins.kind in ('jmp', 'cjmp', 'call'):
            ins.comments.append(C_CMT(f'-> {ins.target:#04x}'))

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
    lanes, placed = [], []
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
        line = [' '] * width
        for s, d, k in placed:
            if min(s, d) < n <= max(s, d):
                line[width - 3 - 2 * k] = '│'
        return ''.join(line)

    return rows, passthrough

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def load_hex(path):
    return bytearray.fromhex(''.join(open(path).read().split()))

def main():
    argv = sys.argv[1:]
    mem_path = None
    if '--mem' in argv:
        k = argv.index('--mem')
        mem_path = argv[k + 1]
        del argv[k:k + 2]
    files = [a for a in argv if not a.startswith('--')]

    code = load_hex(files[0]) if files else bytearray.fromhex(CODE_HEX)

    if '--mem-unknown' in argv:
        init_mem = [None] * MEM_SIZE
    else:
        init_mem = [0] * MEM_SIZE
        if mem_path:
            data = load_hex(mem_path)[:MEM_SIZE]
            init_mem[:len(data)] = list(data)

    insns = decode(code)
    analyze(insns, init_mem)
    labels, xrefs = build_labels(insns)
    arrows, passthrough = build_arrows(insns)

    for ins in insns:
        if ins.n in labels:
            pad = C_ARROW(passthrough(ins.n))
            print(pad)
            name = labels[ins.n]
            head = '┌ ' + name if name.startswith('fcn_') else ';-- ' + name + ':'
            print(f'{pad} {C_LABEL(head)}')
            for r in xrefs.get(ins.n, []):
                kind = {'call': 'CALL', 'cjmp': 'CJMP', 'jmp': 'JMP'}[r.kind]
                print(f'{pad} {C_CMT(f"; {kind} XREF from {r.n:#04x}")}')

        raw = ' '.join(f'{b:02x}' for b in ins.raw)
        body = '; '.join(
            f'{(C_JMP if m in ("jmp", "call", "ret") or m.startswith("j[") else C_MNEM)(m.ljust(7))} {ops}'
            for m, ops in ins.text)
        if ins.reached:
            cmt = ins.comments
        else:
            cmt = [C_DIM('unreachable')]
        gap = ' ' * max(0, 26 - len(strip_ansi(body)))
        tail = f'  {gap}{C_CMT("; ")}{C_CMT(", ").join(cmt)}' if cmt else ''
        print(f'{C_ARROW(arrows[ins.n])} {C_ADDR(f"0x{ins.n:02x}")}  {C_BYTES(raw)}   {body}{tail}')

    leftover = len(code) % INST_LEN
    if leftover:
        print(C_CMT(f'\n; {leftover} trailing byte(s): {code[-leftover:].hex(" ")}'))

if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        pass
