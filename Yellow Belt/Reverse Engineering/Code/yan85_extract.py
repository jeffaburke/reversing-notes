#!/usr/bin/env python3
"""
Pull the per-level Yan85 encoding out of a challenge binary.

usage: python3 yan85_extract.py <binary> [-o level.py]

Finds, by the shape of the code rather than by symbol names (so it works on
stripped binaries):
  * register codes        (read_register's compare chain)
  * opcode bits + order   (interpret_instruction's bit tests)
  * which handler is which (fingerprinting each handler)
  * instruction byte order (which byte imm uses for register / value)
  * syscall bits          (interpret_sys's bit tests + libc call behind each)
  * cmp flag bits         (interpret_cmp's or-chain)
  * the bytecode and initial memory from main()

Prints a ready-to-paste config block and, with -o, writes it to a file that
yan85dis2.py can load with --config.

Needs only Python 3 and objdump (binutils).
"""
import re
import struct
import subprocess
import sys

REG_OFFSETS = {0x400: 'a', 0x401: 'b', 0x402: 'c', 0x403: 'd', 0x404: 's', 0x405: 'i', 0x406: 'f'}
OFF_S, OFF_I, OFF_F = 0x404, 0x405, 0x406
MEM_BASE = 0x300

# ---------------------------------------------------------------------------
# Disassembly
# ---------------------------------------------------------------------------
LINE_RE = re.compile(r'^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$')

class Ins:
    def __init__(self, addr, mnem, ops):
        self.addr, self.mnem, self.ops = addr, mnem, ops.strip()

    @property
    def call_target(self):
        m = re.match(r'([0-9a-f]+)\s*<([^>]*)>', self.ops)
        return (int(m.group(1), 16), m.group(2)) if m else (None, None)

    def imm(self):
        m = re.search(r',\s*(0x[0-9a-f]+|\d+)\s*$', self.ops)
        return int(m.group(1), 0) if m else None

    def rip_target(self):
        m = re.search(r'#\s*([0-9a-f]+)', self.ops)
        return int(m.group(1), 16) if m else None

    def __repr__(self):
        return f'{self.addr:x}: {self.mnem} {self.ops}'

def disassemble(path):
    out = subprocess.run(['objdump', '-d', '-M', 'intel', '--no-show-raw-insn', '-j', '.text', path],
                         capture_output=True, text=True, check=True).stdout
    insns = []
    for line in out.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        addr, mnem, ops = int(m.group(1), 16), m.group(2), m.group(3)
        if mnem in ('rex.W', 'rex.RB', '(bad)') or mnem.startswith('.byte'):
            continue
        insns.append(Ins(addr, mnem, ops))
    return insns

def split_functions(insns):
    """Split at endbr64 (every function in these binaries starts with it).
    Falls back to 'push rbp; mov rbp,rsp' if there is no endbr64."""
    starts = [k for k, i in enumerate(insns) if i.mnem == 'endbr64']
    if len(starts) < 10:
        starts = [k for k in range(len(insns) - 1)
                  if insns[k].mnem == 'push' and insns[k].ops == 'rbp'
                  and insns[k + 1].mnem == 'mov' and insns[k + 1].ops == 'rbp,rsp']
    funcs = {}
    for a, b in zip(starts, starts[1:] + [len(insns)]):
        funcs[insns[a].addr] = insns[a:b]
    return funcs

def plt_name(name):
    """'open@plt' -> 'open'; anything else (incl. 'sleep@plt+0x3cb') -> None"""
    m = re.fullmatch(r'(\w+)@plt', name or '')
    return m.group(1) if m else None

def calls(body):
    return [i.call_target for i in body if i.mnem == 'call' and i.call_target[0] is not None]

def mem_offsets(body):
    """Displacements like [rax+0x405] used in a function."""
    return {int(x, 16) for i in body for x in re.findall(r'\[r[a-z0-9]+\+(0x4[0-9a-f]{2})\]', i.ops)}

def struct_base(body):
    """Stack slot where the handler stores the instruction struct (rsi)."""
    for i in body:
        m = re.match(r'QWORD PTR \[rbp-(0x[0-9a-f]+)\],rsi$', i.ops)
        if i.mnem == 'mov' and m:
            return int(m.group(1), 16)
    return None

def byte_index(ops, base):
    m = re.search(r'BYTE PTR \[rbp-(0x[0-9a-f]+)\]', ops)
    return base - int(m.group(1), 16) if m and base is not None else None

# ---------------------------------------------------------------------------
# Individual pieces
# ---------------------------------------------------------------------------
def find_register_funcs(funcs):
    """read_register / write_register: chains of cmp K -> access [rax+0x40N]."""
    read = write = None
    regmap = {}
    for addr, body in funcs.items():
        found, kind = {}, None
        for k, i in enumerate(body):
            if i.mnem == 'cmp' and i.ops.startswith('BYTE PTR [rbp-') and i.imm() is not None:
                for j in body[k + 1:k + 6]:
                    m = re.search(r'\[rax\+(0x40[0-6])\]', j.ops)
                    if m:
                        found[i.imm()] = REG_OFFSETS[int(m.group(1), 16)]
                        kind = 'read' if j.mnem == 'movzx' else 'write'
                        break
        if len(found) == 7:
            if kind == 'read':
                read, regmap = addr, found
            else:
                write = addr
    return read, write, regmap

def find_memory_funcs(funcs):
    read = write = None
    for addr, body in funcs.items():
        if len(body) > 20:
            continue
        for i in body:
            if f'+{MEM_BASE:#x}]' in i.ops and 'rax*1' in i.ops:
                if i.mnem == 'movzx':
                    read = addr
                elif i.mnem == 'mov' and i.ops.startswith('BYTE PTR'):
                    write = addr
    return read, write

def bit_dispatch(body, accept=lambda target: True):
    """[(bit, call_target, block_instructions)] for a chain of bit tests + calls.
    Calls rejected by `accept` (printf, puts, describe_* in teaching builds)
    are skipped."""
    out, bit, block = [], None, []
    for k, i in enumerate(body):
        if i.mnem == 'and' and i.ops.startswith('eax,') and i.imm() is not None:
            bit, block = i.imm(), []
        elif i.mnem == 'test' and i.ops == 'al,al' and k + 1 < len(body) and body[k + 1].mnem == 'jns':
            bit, block = 0x80, []          # sign bit test: (int8)op < 0
        elif i.mnem == 'call' and bit is not None and accept(i.call_target):
            out.append((bit, i.call_target, block + [i]))
            bit = None
            continue
        block.append(i)
    return out

def find_dispatcher(funcs):
    best = None
    for addr, body in funcs.items():
        d = bit_dispatch(body, accept=lambda t: plt_name(t[1]) is None and t[0] in funcs)
        targets = {t[0] for _, t, _ in d}
        if len(d) == 8 and len(targets) == 8:
            best = (addr, d)
    return best

def opcode_index(body):
    """Byte loaded right before the first bit test is the opcode."""
    base, last = struct_base(body), None
    for k, i in enumerate(body):
        if i.mnem == 'movzx' and 'BYTE PTR [rbp-' in i.ops:
            last = byte_index(i.ops, base)
        elif (i.mnem == 'and' and i.ops.startswith('eax,')) or \
             (i.mnem == 'test' and i.ops == 'al,al' and body[k + 1].mnem == 'jns'):
            return last
    return None

def find_libc_wrappers(funcs):
    """Small functions that call open/read/write/exit/sleep."""
    wrappers = {}
    for addr, body in funcs.items():
        for target, name in calls(body):
            libc = plt_name(name)
            if libc in ('open', 'read', 'write', 'exit', 'sleep') and len(body) < 40:
                wrappers[addr] = libc
    return wrappers

def classify(body, regf, memf, wrappers):
    read_reg, write_reg = regf
    read_mem, write_mem = memf
    targets = [t for t, _ in calls(body)]
    offs = mem_offsets(body)
    ops = ' '.join(i.ops for i in body)
    if any(t in wrappers for t in targets):
        return 'sys'
    if any(i.mnem == 'or' and i.ops.startswith('eax,') for i in body) and OFF_F in offs:
        return 'cmp'
    if OFF_I in offs and 'eax,edx' in ops:
        return 'jmp'
    if OFF_S in offs:
        return 'stk'
    if read_mem in targets:
        return 'ldm'
    if write_mem in targets:
        return 'stm'
    if targets.count(read_reg) >= 2 and write_reg in targets:
        return 'add'
    if write_reg in targets and read_reg not in targets:
        return 'imm'
    return None

def arg_indexes(imm_body, write_reg):
    """Follow which instruction byte ends up in esi (register) / edx (value)."""
    base = struct_base(imm_body)
    src = {}           # register name -> byte index it holds
    for i in imm_body:
        if i.mnem == 'movzx' and 'BYTE PTR [rbp-' in i.ops:
            dst = i.ops.split(',')[0]
            src[dst] = byte_index(i.ops, base)
        elif i.mnem in ('movzx', 'mov'):
            parts = i.ops.split(',')
            if len(parts) == 2:
                dst, s = parts
                s = {'al': 'eax', 'cl': 'ecx', 'dl': 'edx'}.get(s, s)
                if s in src:
                    src[dst] = src[s]
        elif i.mnem == 'call' and i.call_target[0] == write_reg:
            break
    return src.get('esi'), src.get('edx')

def cmp_flags(body):
    """Map flag bit -> condition from the cmp handler's or-chain."""
    flags, last_jcc, zero_check = {}, None, False
    cond_for = {'jae': '<', 'jnb': '<', 'jbe': '>', 'jna': '>', 'jne': '==', 'jnz': '==', 'je': '!=', 'jz': '!='}
    for i in body:
        if i.mnem == 'cmp':
            zero_check = re.search(r',0x0$', i.ops) is not None
        elif i.mnem.startswith('j') and i.mnem != 'jmp':
            last_jcc = i.mnem
        elif i.mnem == 'or' and i.ops.startswith('eax,'):
            flags[i.imm()] = '==0' if zero_check else cond_for.get(last_jcc, f'?{last_jcc}')
    return flags

def sys_bits(body, wrappers):
    out = {}
    for bit, (target, _), block in bit_dispatch(body, accept=lambda t: t[0] in wrappers):
        name = wrappers.get(target)
        if name == 'read':
            name = 'read_memory' if any(f'+{MEM_BASE:#x}]' in i.ops for i in block) else 'read_code'
        if name:
            out[bit] = name
    return out

# ---------------------------------------------------------------------------
# Bytecode and memory from main
# ---------------------------------------------------------------------------
class Elf:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        d = self.data
        phoff, = struct.unpack_from('<Q', d, 0x20)
        phentsize, phnum = struct.unpack_from('<HH', d, 0x36)
        self.segs = []
        for k in range(phnum):
            p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from('<IIQQQQQQ', d, phoff + k * phentsize)
            if p_type == 1:
                self.segs.append((p_vaddr, p_offset, p_filesz))

    def read(self, vaddr, n):
        for v, o, sz in self.segs:
            if v <= vaddr < v + sz:
                return self.data[o + vaddr - v: o + vaddr - v + n]
        return None

def find_program(funcs, elf):
    for addr, body in funcs.items():
        for k, i in enumerate(body):
            if i.mnem == 'call' and plt_name(i.call_target[1]) == 'memcpy':
                code_addr = len_addr = None
                for j in reversed(body[max(0, k - 8):k]):
                    if code_addr is None and j.mnem == 'lea' and j.ops.startswith('rsi,') and j.rip_target():
                        code_addr = j.rip_target()
                    if len_addr is None and j.mnem == 'mov' and 'DWORD PTR [rip' in j.ops:
                        len_addr = j.rip_target()
                if code_addr is None or len_addr is None:
                    continue
                length, = struct.unpack('<I', elf.read(len_addr, 4))
                code = elf.read(code_addr, length)
                # memory: the run of 8-byte rip-relative loads right after memcpy
                mem_addrs = [j.rip_target() for j in body[k + 1:]
                             if j.mnem == 'mov' and 'QWORD PTR [rip' in j.ops and j.rip_target()]
                mem = None
                if mem_addrs:
                    start = min(mem_addrs)
                    mem = elf.read(start, 0x100)
                return code, mem, code_addr, mem_addrs and min(mem_addrs)
    return None, None, None, None

# ---------------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    path = sys.argv[1]
    out_path = sys.argv[sys.argv.index('-o') + 1] if '-o' in sys.argv else None

    funcs = split_functions(disassemble(path))
    elf = Elf(path)
    problems = []

    read_reg, write_reg, regmap = find_register_funcs(funcs)
    if not regmap:
        problems.append('register functions not found')
    memf = find_memory_funcs(funcs)
    wrappers = find_libc_wrappers(funcs)

    disp = find_dispatcher(funcs)
    ops, op_idx, arg1_idx, arg2_idx, con, sysmap = [], None, None, None, {}, {}
    if not disp:
        problems.append('interpret_instruction not found')
    else:
        d_addr, chain = disp
        op_idx = opcode_index(funcs[d_addr])
        for bit, (target, _), _ in chain:
            body = funcs.get(target, [])
            kind = classify(body, (read_reg, write_reg), memf, wrappers)
            ops.append((bit, kind or f'?{target:#x}'))
            if kind == 'imm':
                arg1_idx, arg2_idx = arg_indexes(body, write_reg)
            elif kind == 'cmp':
                con = cmp_flags(body)
            elif kind == 'sys':
                sysmap = sys_bits(body, wrappers)

    code, mem, code_addr, mem_addr = find_program(funcs, elf)

    idx = {OP_IDX_NAME: v for OP_IDX_NAME, v in
           (('OP_IDX', op_idx), ('ARG1_IDX', arg1_idx), ('ARG2_IDX', arg2_idx))}
    order = sorted(idx, key=lambda k: (idx[k] is None, idx[k]))

    h = lambda v: f'{v:#x}'
    lines = [
        f'# Extracted from {path}',
        'INST_LEN = 3',
        f'{", ".join(order)} = {", ".join(str(idx[k]) for k in order)}',
        'REG = {' + ', '.join(f'{h(k)}: {v!r}' for k, v in sorted(regmap.items())) + '}',
        'SYS = {' + ', '.join(f'{h(k)}: {v!r}' for k, v in sorted(sysmap.items())) + '}',
        '# Must be in the same order the interpreter tests the bits',
        'OPS = [' + ', '.join(f'({h(b)}, {n!r})' for b, n in ops) + ']',
        'CON = {' + ', '.join(f'{h(k)}: {v!r}' for k, v in sorted(con.items())) + '}',
    ]
    if code is not None:
        lines.append(f'CODE_HEX = "{code.hex()}"  # {len(code)} bytes from {code_addr:#x}')
    if mem is not None:
        lines.append(f'MEM_HEX = "{mem.hex()}"  # 0x100 bytes from {mem_addr:#x}')
    text = '\n'.join(lines) + '\n'
    print(text)

    for name, have, want in (('REG', len(regmap), 7), ('OPS', len(ops), 8),
                             ('SYS', len(sysmap), 6), ('CON', len(con), 5)):
        if have != want:
            problems.append(f'{name}: found {have}, expected {want}')
    if any(n.startswith('?') for _, n in ops):
        problems.append('some handlers could not be identified (marked ?addr)')
    if None in idx.values():
        problems.append('instruction byte order incomplete')
    if code is None:
        problems.append('bytecode not found in main')
    for p in problems:
        print(f'# WARNING: {p}', file=sys.stderr)

    if out_path:
        open(out_path, 'w').write(text)
        print(f'# written to {out_path}', file=sys.stderr)

if __name__ == '__main__':
    main()
