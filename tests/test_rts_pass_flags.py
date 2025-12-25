from __future__ import annotations

import importlib

from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockFlag, MockLabel, MockLLIL, mllil, mreg

m68k_arch = importlib.import_module("m68k.m68k")


def _lift_to_llil(arch: object, data: bytes) -> list[MockLLIL]:
    il = lowlevelil.LowLevelILFunction(arch)

    offset = 0
    while offset < len(data):
        il.current_address = offset  # type: ignore[attr-defined]
        length = arch.get_instruction_low_level_il(data[offset:], offset, il)  # type: ignore[attr-defined]
        assert length is not None and length > 0
        offset += length

    return [node for node in il if not isinstance(node, MockLabel)]


def test_rts_pass_flags_is_arch_specific() -> None:
    assert m68k_arch.M68000().rts_pass_flags is True
    assert m68k_arch.M68010().rts_pass_flags is False


def test_rts_pass_flags_affects_call_and_rts_llil() -> None:
    jsr_abs = b"\x4e\xb9\x00\x05\xdc\x1c"  # jsr ($5dc1c)
    rts = b"\x4e\x75"

    expected_jsr_disabled = [mllil("CALL", [mllil("CONST_PTR.d", [0x5DC1C])])]
    expected_jsr_enabled = expected_jsr_disabled + [
        mllil("SET_FLAG", [MockFlag("c"), mllil("REG.b", [mreg("rc")])])
    ]

    expected_rts_disabled = [mllil("RET", [mllil("POP.d", [])])]
    expected_rts_enabled = [
        mllil("SET_REG.b", [mreg("rc"), mllil("FLAG", [MockFlag("c")])]),
        *expected_rts_disabled,
    ]

    assert _lift_to_llil(m68k_arch.M68010(), jsr_abs) == expected_jsr_disabled
    assert _lift_to_llil(m68k_arch.M68000(), jsr_abs) == expected_jsr_enabled

    assert _lift_to_llil(m68k_arch.M68010(), rts) == expected_rts_disabled
    assert _lift_to_llil(m68k_arch.M68000(), rts) == expected_rts_enabled

