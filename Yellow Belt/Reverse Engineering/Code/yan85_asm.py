#!/usr/bin/env python3
"""
Yan85 assembler.

usage:
    python3 yan85asm.py program.s --config level.py [-o out.hex] [--raw out.bin]
    python3 yan85asm.py program.s --config level.py --labels   # show label map

Reads a .s listing in the same syntax yan85dis2.py prints and emits bytecode
as hex (default), or raw bytes with --raw. The encoding (opcode bits, register
codes, syscall bits, flag bits, byte order) comes from a --config file written
by yan85_extract.py, so one assembler covers every level.

Syntax
------
  imm d, 0x2f            registers and hex/decimal/char immediates
  stm [c], d             brackets around a memory operand are ignored
  add b, s
  cmp a, b
  sys WRITE, d           syscalls by name (from the config's SYS) or number
  sys EXIT               a one-operand sys leaves arg2 = 0
  jmp EQ, d              conditional jump: flags by name, then the target reg
  jmp d                  unconditional jump (arg1 = 0)
  imm i, label           'imm i, X' is how you jump to a fixed address

  loop:                  a label (its own line, or before an instruction)
  imm c, 'A'             character immediate -> 0x41
  ; comment              ';' or '#' starts a comment

Labels resolve to instruction indexes (0, 1, 2, ...), which is what the VM's
instruction pointer counts in. Forward references are fine.

Condition names accepted for jmp (mapped through the config's CON):
  LT <   GT >   EQ ==   NE !=   ZERO ==0
and you can OR them: 'jmp LT|GT, d' or 'jmp <|>, d'.
"""
import re
import sys

INST_LEN = 3
OP_IDX, ARG1_IDX, ARG2_IDX = 0, 1, 2
REG, SYS, OPS, CON = {}, {}, [], {}

COND_ALIAS = {'LT': '<', 'GT': '>', 'EQ': '==', 'NE': '!=', 'ZERO': '==0',
              'LE': '<=', 'GE': '>='}

def load_config(path):
    cfg = {}
    exec(open(path).read(), cfg)
    for name in ('INST_LEN', 'OP_IDX', 'ARG1_IDX', 'ARG2_IDX', 'REG', 'SYS', 'OPS', 'CON'):
        if name in cfg:
            globals()[name] = cfg[name]

class AsmError(Exception):
    pass

def parse_immediate(tok):
    tok = tok.strip()
    if len(tok) == 3 and tok[0] == tok[2] == "'":        # 'A'
        return ord(tok[1])
    if tok == "'\\n'" or tok == '"\\n"':
        return 0x0a
    try:
        return int(tok, 0) & 0xff
    except ValueError:
        raise AsmError(f'bad immediate {tok!r}')

def cond_value(tok):
    """'LT|GT' or '<|>' -> OR of the matching CON bits."""
    flag_bit = {v: k for k, v in CON.items()}
    total = 0
    for part in tok.split('|'):
        p = part.strip()
        name = COND_ALIAS.get(p.upper(), p)
        if name not in flag_bit:
            raise AsmError(f'unknown condition {part!r} (known: '
                           f'{", ".join(sorted(flag_bit))})')
        total |= flag_bit[name]
    return total

def tokenize(line):
    line = re.split(r'[;#]', line, 1)[0].strip()      # strip comments
    return line

def first_pass(lines):
    """Return [(lineno, mnemonic, [operands])] and {label: index}."""
    insns, labels = [], {}
    for lineno, raw in enumerate(lines, 1):
        line = tokenize(raw)
        if not line:
            continue
        # leading labels: one or more "name:" before an optional instruction
        while True:
            m = re.match(r'^([A-Za-z_.][\w.]*)\s*:\s*(.*)$', line)
            if not m:
                break
            label = m.group(1)
            if label in labels:
                raise AsmError(f'line {lineno}: duplicate label {label!r}')
            labels[label] = len(insns)
            line = m.group(2).strip()
        if not line:
            continue
        mnem, _, rest = line.partition(' ')
        mnem = mnem.lower()
        if mnem not in OPCODE_BIT:
            raise AsmError(f'line {lineno}: unknown mnemonic {mnem!r}')
        operands = [o.strip() for o in rest.split(',')] if rest.strip() else []
        insns.append((lineno, mnem, operands))
    return insns, labels

def reg_value(tok, lineno):
    if tok not in REG_BY_NAME:
        raise AsmError(f'line {lineno}: unknown register {tok!r} '
                       f'(known: {", ".join(REG_BY_NAME)})')
    return REG_BY_NAME[tok]

def encode(insns, labels):
    out = bytearray()
    for lineno, mnem, ops in insns:
        op = OPCODE_BIT[mnem]
        a1 = a2 = 0
        strip = lambda s: s.strip('[]').strip()

        if mnem == 'imm':
            # imm REG, IMM   (and imm i, label)
            if len(ops) != 2:
                raise AsmError(f'line {lineno}: imm needs 2 operands')
            a1 = reg_value(strip(ops[0]), lineno)
            tgt = strip(ops[1])
            if tgt in labels:
                a2 = labels[tgt]
            else:
                a2 = parse_immediate(tgt)

        elif mnem in ('add', 'cmp', 'stm', 'ldm'):
            if len(ops) != 2:
                raise AsmError(f'line {lineno}: {mnem} needs 2 operands')
            a1 = reg_value(strip(ops[0]), lineno)
            a2 = reg_value(strip(ops[1]), lineno)

        elif mnem == 'stk':
            # stk PUSH, POP  — either operand may be a register or '-'/0 for none
            if len(ops) != 2:
                raise AsmError(f'line {lineno}: stk needs 2 operands '
                               f'(push_reg, pop_reg; use - for none)')
            push, pop = strip(ops[0]), strip(ops[1])
            a2 = 0 if push in ('-', '0', '') else reg_value(push, lineno)
            a1 = 0 if pop in ('-', '0', '') else reg_value(pop, lineno)

        elif mnem == 'jmp':
            # jmp COND, REG  or  jmp REG  (unconditional)
            if len(ops) == 1:
                a1, a2 = 0, reg_value(strip(ops[0]), lineno)
            elif len(ops) == 2:
                a1 = cond_value(ops[0])
                a2 = reg_value(strip(ops[1]), lineno)
            else:
                raise AsmError(f'line {lineno}: jmp needs 1 or 2 operands')

        elif mnem == 'sys':
            # sys CALL[, RETREG]
            if not ops:
                raise AsmError(f'line {lineno}: sys needs a syscall')
            call = strip(ops[0])
            if call in SYS_BY_NAME:
                a1 = SYS_BY_NAME[call]
            else:
                try:
                    a1 = int(call, 0) & 0xff
                except ValueError:
                    raise AsmError(f'line {lineno}: unknown syscall {call!r} '
                                   f'(known: {", ".join(SYS_BY_NAME)})')
            a2 = reg_value(strip(ops[1]), lineno) if len(ops) > 1 else 0

        slot = [0, 0, 0]
        slot[OP_IDX] = op
        slot[ARG1_IDX] = a1
        slot[ARG2_IDX] = a2
        out += bytes(slot)
    return out

def main():
    argv = sys.argv[1:]
    if '--config' not in argv:
        print(__doc__); sys.exit(1)
    cfg = argv[argv.index('--config') + 1]
    load_config(cfg)

    global OPCODE_BIT, SYS_BY_NAME, REG_BY_NAME
    OPCODE_BIT = {name: bit for bit, name in OPS}
    REG_BY_NAME = {name: code for code, name in REG.items()}
    SYS_BY_NAME = {name.upper(): bit for bit, name in SYS.items()}
    # also accept the lowercase names as written in SYS
    SYS_BY_NAME.update({name: bit for bit, name in SYS.items()})

    src = [a for a in argv if not a.startswith('-') and a != cfg]
    if not src:
        print('no input file'); sys.exit(1)
    lines = open(src[0]).read().splitlines()

    try:
        insns, labels = first_pass(lines)
        code = encode(insns, labels)
    except AsmError as e:
        print(f'error: {e}', file=sys.stderr); sys.exit(1)

    if '--labels' in argv:
        for name, idx in sorted(labels.items(), key=lambda kv: kv[1]):
            print(f'{idx:#04x}  {name}')
        return

    if '--raw' in argv:
        path = argv[argv.index('--raw') + 1]
        open(path, 'wb').write(code)
        print(f'wrote {len(code)} bytes to {path}', file=sys.stderr)
    elif '-o' in argv:
        path = argv[argv.index('-o') + 1]
        open(path, 'w').write(code.hex() + '\n')
        print(f'wrote {len(code)} bytes ({len(insns)} instructions) to {path}', file=sys.stderr)
    else:
        print(code.hex())

if __name__ == '__main__':
    main()
