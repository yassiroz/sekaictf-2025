# python3 -m pip install iced-x86 z3python
from iced_x86 import *
from z3 import *
from dataclasses import dataclass

@dataclass
class RegContents:
    pass

# zmm register containing permute indices (0-127)
@dataclass
class RegContentPermute(RegContents):
    permutes: list[int]

# zmm register containing 64 bits of data, represented as z3 Bool variables
@dataclass
class RegContentBits(RegContents):
    values: list[Bool]

# both bits (all false) and permute (all 0) registers
@dataclass
class RegContentEmpty(RegContents):
    permutes: list[int]
    values: list[bool]

# emulate ternlog for the given immediate, a, b, c
def emulate_ternlog(A, B, C, imm: int):
    match imm:
        case 128: return A & B
        case 63: return ~(A & B)
        case 254: return A | B
        case 3: return ~(A | B)
        case 60: return A ^ B
        case 195: return ~(A ^ B)
        case 48: return (A & ~B)
        case 243: return (A | ~B)
        case 21: return ~((A & B) | C)
        case 87: return ~((A | B) & C)
        case x: raise ValueError(f"Unknown immediate: {x}")

BIN = open("./what-in-ternation", "rb").read()

# range of instructions we want to disassemble
start = 0x21F5
end = 0xC461

# keep track of whats in registers or on the stack
regs: dict[Register, RegContents] = {}
stack: dict[int, RegContents] = {}

# initialize zmm0 through 7 with the initial flag bits (8 chars per register, 64 bits total)
flag_bits = [Bool(f"flag_bit_{i}") for i in range(64 * 8)]
for i in range(8):
    regs[Register.ZMM0 + i] = RegContentBits(flag_bits[i * 64:(i + 1) * 64])

decoder = Decoder(64, BIN[start:end], ip=start)
for insn in decoder:
    def set_reg(reg: Register, value: RegContents):
        assert reg >= Register.ZMM0 and reg <= Register.ZMM31, "Only ZMM registers are supported"
        regs[reg] = value

    def read_operand(op_idx: int) -> RegContents:
        op_kind = insn.op_kind(op_idx)
        if op_kind == OpKind.REGISTER:
            reg_name = insn.op_register(op_idx)
            if reg_name in regs:
                return regs[reg_name]
            else:
                raise NotImplementedError(f"Register for operand {op_idx} has no value: {insn.ip:#x} {insn}")
        elif op_kind == OpKind.MEMORY:
            if insn.memory_base == Register.RSP:
                # stack access
                stack_offs = insn.memory_displacement
                if stack_offs in stack:
                    return stack[stack_offs]
                else:
                    raise NotImplementedError(f"Stack offset {stack_offs} not implemented")
            else:
                # global access; this must be a permute
                addr = insn.ip_rel_memory_address
                return RegContentPermute(BIN[addr:addr + 64])
        else:
            raise NotImplementedError(f"Unhandled operand kind: {op_kind}")
        
    def write_operand(op_idx: int, value: RegContents):
        if insn.op_kind(op_idx) == OpKind.REGISTER:
            reg_name = insn.op_register(op_idx)
            set_reg(reg_name, value)
        elif insn.op_kind(op_idx) == OpKind.MEMORY:
            if insn.memory_base == Register.RSP:
                # stack access
                stack_offs = insn.memory_displacement
                stack[stack_offs] = value
            else:
                raise NotImplementedError(f"Cannot write to global memory: {insn.ip:#x} {insn}")
        else:
            raise NotImplementedError(f"Unhandled operand kind for writing: {insn.op_kind(op_idx)}")

    print(f"{insn.ip:#x} {insn}")
    match insn.mnemonic:
        case Mnemonic.VMOVDQA64 | Mnemonic.VMOVDQA32:
            src = read_operand(1)
            write_operand(0, src)
        case Mnemonic.VPXOR:
            if len(set([insn.op0_register, insn.op1_register, insn.op2_register])) != 1:
                raise NotImplementedError(f"VPXOR with multiple different registers: {insn}")
            regs[RegisterInfo(insn.op0_register).full_register] = RegContentEmpty([0] * 64, [BoolVal(False)] * 64)
        case Mnemonic.VPTERNLOGD:
            a = read_operand(0)
            b = read_operand(1)
            c = read_operand(2)
            imm = insn.immediate(3)
            assert isinstance(a, RegContentBits) and isinstance(b, RegContentBits) and isinstance(c, RegContentBits), "Operands must be RegContentBits"
            result = RegContentBits([emulate_ternlog(a.values[i], b.values[i], c.values[i], imm) for i in range(64)])
            write_operand(0, result)
        case Mnemonic.VPERMI2B | Mnemonic.VPERMT2B:
            if insn.mnemonic == Mnemonic.VPERMI2B:
                mask = read_operand(0)
                a = read_operand(1)
                b = read_operand(2)
            else:  # Mnemonic.VPERMT2B
                mask = read_operand(1)
                a = read_operand(0)
                b = read_operand(2)
            assert isinstance(mask, RegContentPermute)
            result = [0] * 64
            for i in range(64):
                idx = mask.permutes[i]
                if idx >= 64:
                    result[i] = b.values[idx - 64]
                else:
                    result[i] = a.values[idx]
            write_operand(0, RegContentBits(result))
        case Mnemonic.VPERMB:
            mask = read_operand(1)
            a = read_operand(2)
            result = [a.values[mask.permutes[i]] for i in range(64)]
            write_operand(0, RegContentBits(result))
        case Mnemonic.VPBROADCASTB:
            if insn.op1_kind == OpKind.MEMORY:
                val = BIN[insn.ip_rel_memory_address]
                write_operand(0, RegContentPermute([val] * 64))
            else:
                raise NotImplementedError(f"VPBROADCASTB with non-memory operand: {insn}")
        case Mnemonic.MOV | Mnemonic.AND | Mnemonic.SUB | Mnemonic.LEAVE:
            pass # ignored
        case x:
            raise NotImplementedError(f"Unhandled mnemonic: {insn}")
        
s = Solver()
s.add(regs[Register.ZMM0].values[0] == True)
print(f"Solver status: {s.check()}")
if s.check() == sat:
    model = s.model()
    flag_bytes = [0] * 64
    for i in range(64):
        byte_value = 0
        for j in range(8):
            if model.evaluate(flag_bits[i * 8 + j]):
                byte_value |= (1 << j)
        flag_bytes[i] = byte_value
    print("Flag: ", bytes(flag_bytes).decode('utf-8', errors='ignore'))