# Deobfuscate stackstrings used by Godzilla Loader
# @category: Godzilla Loader

import string


def set_comments(stackstrings):
    for addr, value in stackstrings.items():
        if len(value) <= 4:
            continue
        listing = currentProgram.getListing()
        codeUnit = listing.getCodeUnitAt(toAddr(addr))
        codeUnit.setComment(codeUnit.EOL_COMMENT, value)
        print('%08x: %s' % (addr, value))

def is_ascii(value):
    if value == 0 or chr(value) in string.printable:
        return True
    return False

def is_ascii_dword(value):
    for i in range(4):
        if not is_ascii((value >> (i * 8)) & 0xff):
            return False
    return True

def get_ascii_from_dword(value):
    return ''.join([chr((value >> (i * 8)) & 0xff) for i in range(4)]).rstrip('\x00')

def decode_ss2(stackstrings):
    result = {}
    prev_offset = None

    for offset, ss in sorted(stackstrings.items()):
        if prev_offset == None:
            value = ss[0]
            start_addr = ss[1]
        elif ss[0] == '\x00':
            if len(value) > 4:
               result[start_addr] = value
            prev_offset = None
            continue
        elif prev_offset + 2 == offset:
            value += ss[0]
        prev_offset = offset
    return result

def handle_ss2_clear(reg_state, inst):
    reg = inst.getOpObjects(0)[0].getName()[1:]
    reg_state[reg] = '\x00'
    return reg_state

def handle_ss2_push(inst):
    value = chr(inst.getOpObjects(0)[0].getUnsignedValue())
    return value

def handle_ss2_pop(reg_state, inst, tos_value):
    dst_reg = inst.getOpObjects(0)[0].getName()[1:]
    reg_state[dst_reg] = tos_value
    return reg_state

def handle_ss2_copy(reg_state, inst):
    dst_reg = inst.getOpObjects(0)[0].getName()[1:]
    src_reg = inst.getOpObjects(1)[0].getName()[1:]
    src_value = reg_state.get(src_reg, '\x00')
    reg_state[dst_reg] = src_value
    return reg_state

def handle_ss2_store(reg_state, inst):
    dst = inst.getOpObjects(0)
    if isinstance(dst[0], ghidra.program.model.lang.Register):
        if len(dst) == 2:
            dst_offset = dst[1].getSignedValue()
        else:
            dst_offset = 0
    else:
        dst_offset = dst[0].getSignedValue()
    src_reg = inst.getOpObjects(1)[0].getName()
    src_value = reg_state.get(src_reg, '\x00')
    return dst_offset, src_value

def deobfuscate_stackstrings2(func):
    stackstrings = {}
    tos_value = '\x00'
    reg_state = {}

    func_addr = func.getEntryPoint()
    inst = getInstructionAt(func_addr)
    while inst and getFunctionContaining(inst.getAddress()) == func:
        # print('[%08x] %s' % (inst.getAddress().getOffset(), inst.toString()))
        if is_ss2_clear(inst):
            reg_state = handle_ss2_clear(reg_state, inst)
        elif is_ss2_push(inst):
            tos_value = handle_ss2_push(inst)
        elif is_ss2_pop(inst):
            reg_state = handle_ss2_pop(reg_state, inst, tos_value)
        elif is_ss2_store(inst):
            offset, value = handle_ss2_store(reg_state, inst)
            inst_addr = inst.getAddress().getOffset()
            stackstrings[offset] = (value, inst_addr)
        elif is_ss2_copy(inst):
            reg_state = handle_ss2_copy(reg_state, inst)
        inst = inst.getNext()
    result = decode_ss2(stackstrings)
    return result

def is_ss2_clear(inst):
    mnemonic = inst.getMnemonicString()
    if not mnemonic.startswith('XOR'):
        return False

    dst = inst.getOpObjects(0)
    if len(dst) != 1 or not isinstance(dst[0], ghidra.program.model.lang.Register) or \
        dst[0].minimumByteSize != 4:
        return False  

    src = inst.getOpObjects(1)
    if len(src) != 1 or not isinstance(src[0], ghidra.program.model.lang.Register) or \
        src[0].minimumByteSize != 4:
        return False

    src_reg = src[0].getName()
    dst_reg = dst[0].getName()

    if src_reg != dst_reg:
        return False

    return True

def is_ss2_push(inst):
    mnemonic = inst.getMnemonicString()
    if not mnemonic.startswith('PUSH') or inst.getLength() != 2:
        return False

    op = inst.getOpObjects(0)[0]
    if not isinstance(op, ghidra.program.model.scalar.Scalar):
        return False

    value = op.getUnsignedValue() & 0xff
    if not chr(value) in string.printable:
        return False

    return True

def is_ss2_pop(inst):
    mnemonic = inst.getMnemonicString()
    if not mnemonic.startswith('POP'):
        return False

    op = inst.getOpObjects(0)[0]
    if not isinstance(op, ghidra.program.model.lang.Register):
        return False

    return True

def is_ss2_copy(inst):
    mnemonic = inst.getMnemonicString()
    if not mnemonic.startswith('MOV'):
        return False

    dst = inst.getOpObjects(0)
    if len(dst) != 1 or not isinstance(dst[0], ghidra.program.model.lang.Register):
        return False

    src = inst.getOpObjects(1)
    if len(src) != 1 or not isinstance(src[0], ghidra.program.model.lang.Register) or \
        dst[0].getName() == 'ESP':
        return False

    return True

def is_ss2_store(inst):
    mnemonic = inst.getMnemonicString()
    if not mnemonic.startswith('MOV'):
        return False

    src = inst.getOpObjects(1)
    if len(src) != 1 or not isinstance(src[0], ghidra.program.model.lang.Register) or \
        src[0].minimumByteSize != 2:
        return False

    dst = inst.getOpObjects(0)

    if len(dst) == 1 and isinstance(dst[0], ghidra.program.model.lang.Register) and \
        dst[0].getName() == 'EBP':
        return True

    if len(dst) == 2 and isinstance(dst[0], ghidra.program.model.lang.Register) and \
        dst[0].getName() == 'EBP' and isinstance(dst[1], ghidra.program.model.scalar.Scalar):
        return True

    if len(dst) == 2 and isinstance(dst[1], ghidra.program.model.lang.Register) and \
        dst[1].getName() == 'EBP' and isinstance(dst[0], ghidra.program.model.scalar.Scalar):
        return True
    
    return False


def decode_ss1(stackstrings):
    result = {}
    prev_offset = None

    for offset, ss in sorted(stackstrings.items()):
        if prev_offset == None:
            if len(ss[0]) == 4:
                value = ss[0]
                start_addr = ss[1]
                prev_offset = offset
        elif prev_offset + 4 == offset:
            if len(ss[0]) == 4:
                value += ss[0]
                prev_offset = offset
            else:
                value += ss[0]
                result[start_addr] = value
                prev_offset = None
        else:
            result[start_addr] = value
            prev_offset = offset
            value = ss[0]
            start_addr = ss[1]

    return result

def is_ss1_store(inst):
    mnemonic = inst.getMnemonicString()
    if not mnemonic.startswith('MOV'):
        return False

    dst = inst.getOpObjects(0)
    if len(dst) != 2 or not isinstance(dst[0], ghidra.program.model.lang.Register) or \
        dst[0].getName() != 'EBP' or not isinstance(dst[1], ghidra.program.model.scalar.Scalar):
        return False

    offset = dst[1].getSignedValue()
    src = inst.getOpObjects(1)
    if len(src) != 1 or not isinstance(src[0], ghidra.program.model.scalar.Scalar):
        return False

    value = src[0].getUnsignedValue()
    if not is_ascii_dword(value):
        return False

    return True

def handle_ss1_store(inst):
    offset = inst.getOpObjects(0)[1].getSignedValue()
    value = get_ascii_from_dword(inst.getOpObjects(1)[0].getUnsignedValue())
    return offset, value

def deobfuscate_stackstrings1(func):
    stackstrings = {}
    func_addr = func.getEntryPoint()
    inst = getInstructionAt(func_addr)
    while inst and getFunctionContaining(inst.getAddress()) == func:
        # print('[%08x] %s' % (inst.getAddress().getOffset(), inst.toString()))
        if is_ss1_store(inst):
            offset, value = handle_ss1_store(inst)
            inst_addr = inst.getAddress().getOffset()
            stackstrings[offset] = (value, inst_addr)
            # print('[%08x:%08x] %s' % (inst_addr, offset, value))
        inst = inst.getNext()
    result = decode_ss1(stackstrings)
    return result

def deobfuscate_godzilla_loader():
    func = getFirstFunction()
    while func:
        stackstrings1 = deobfuscate_stackstrings1(func)
        set_comments(stackstrings1)
        stackstrings2 = deobfuscate_stackstrings2(func)
        set_comments(stackstrings2)
        func = getFunctionAfter(func)

deobfuscate_godzilla_loader()