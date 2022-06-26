# inspired by https://github.com/Vector35/arch-arm64/blob/staging/arm64test.py
from .m68k import *

test_cases = [
    # subq.b    #$1,d0b
    (b'\x53\x00', 'LLIL_SET_REG.d(d0,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xFFFFFF00),LLIL_REG.d(d0)),LLIL_AND.d(LLIL_CONST.d(0xFF),LLIL_SUB.b{*}(LLIL_REG.b(d0),LLIL_CONST.b(0x1)))))'),
    # ror.b     #$1,d1
    (b'\xe2\x19', 'LLIL_SET_REG.d(d1,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xFFFFFF00),LLIL_REG.d(d1)),LLIL_AND.d(LLIL_CONST.d(0xFF),LLIL_ROR.b{*}(LLIL_REG.b(d1),LLIL_CONST.b(0x1)))))'),
]

import re
import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation

def il2str(il):
    sz_lookup = {1:'.b', 2:'.w', 4:'.d', 8:'.q', 16:'.o'}
    if isinstance(il, lowlevelil.LowLevelILInstruction):
        size_code = sz_lookup.get(il.size, '?') if il.size else ''
        flags_code = '' if not hasattr(il, 'flags') or not il.flags else '{%s}'%il.flags

        # print size-specified IL constants in hex
        if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR] and il.size:
            tmp = il.operands[0]
            if tmp < 0: tmp = (1<<(il.size*8))+tmp
            tmp = '0x%X' % tmp if il.size else '%d' % il.size
            return 'LLIL_CONST%s(%s)' % (size_code, tmp)
        else:
            return '%s%s%s(%s)' % (il.operation.name, size_code, flags_code, ','.join([il2str(o) for o in il.operands]))
    elif isinstance(il, list):
        return '[' + ','.join([il2str(x) for x in il]) + ']'
    else:
        return str(il)

def instr_to_il(data):
    RETURN = b'\x4e\x75'

    platform = binaryninja.Platform['M68000']
    # make a pretend function that returns
    bv = binaryview.BinaryView.new(data + RETURN)
    bv.add_function(0, plat=platform)
    assert len(bv.functions) == 1

    result = []
    #for block in bv.functions[0].low_level_il:
    for block in bv.functions[0].lifted_il:
        for il in block:
            result.append(il2str(il))
    result = '; '.join(result)
    ret = 'LLIL_RET(LLIL_POP.d())'
    if result.endswith(ret):
        result = result[0:result.index(ret)]
    if result.endswith('; '):
        result = result[0:-2]

    return result

def il_str_to_tree(ilstr):
    result = ''
    depth = 0
    for c in ilstr:
        if c == '(':
            result += '\n'
            depth += 1
            result += '    '*depth
        elif c == ')':
            depth -= 1
        elif c == ',':
            result += '\n'
            result += '    '*depth
            pass
        else:
            result += c
    return result

def test_all():
    for (test_i, (data, expected)) in enumerate(test_cases):
        actual = instr_to_il(data)
        if actual != expected:
            print('MISMATCH AT TEST %d!' % test_i)
            print('\t   input: %s' % data.hex())
            print('\texpected: %s' % expected)
            print('\t  actual: ')
            print(actual)
            print('\t    tree:')
            print(il_str_to_tree(actual))
            return False
    return True
