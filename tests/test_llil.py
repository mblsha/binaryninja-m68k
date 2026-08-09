from __future__ import annotations

import importlib
import logging
from typing import Any

import pytest
from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockFlag, MockLabel, MockLLIL, MockReg, mllil, mreg

m68k_test = importlib.import_module("m68k.test")
m68k_arch = importlib.import_module("m68k.m68k")


def _lift_to_llil(data: bytes, *, start_addr: int = 0, arch_cls=m68k_arch.M68000) -> list[MockLLIL]:
    arch = arch_cls()
    il = lowlevelil.LowLevelILFunction(arch)

    offset = 0
    while offset < len(data):
        il.current_address = start_addr + offset  # type: ignore[attr-defined]
        length = arch.get_instruction_low_level_il(data[offset:], start_addr + offset, il)
        assert length is not None and length > 0
        offset += length

    # The mock IL appends LABEL pseudo-nodes for control-flow; ignore those so
    # test cases can focus on the executable LLIL operations.
    return [node for node in il if not isinstance(node, MockLabel)]


def _disasm(data: bytes, *, start_addr: int = 0, arch_cls=m68k_arch.M68000) -> str:
    arch = arch_cls()

    offset = 0
    lines: list[str] = []
    while offset < len(data):
        result = arch.get_instruction_text(data[offset:], start_addr + offset)
        assert result is not None
        tokens, length = result
        assert length is not None and length > 0
        lines.append("".join(token.text for token in tokens).rstrip())
        offset += length

    return "\n".join(lines)


def _mask_for_size(size_bytes: int) -> int:
    return (1 << (size_bytes * 8)) - 1


def _match_node(actual: Any, expected: Any, labels: dict[str, object]) -> None:
    if isinstance(expected, m68k_test.LabelRef):
        bound = labels.get(expected.name)
        if bound is None:
            labels[expected.name] = actual
            return
        assert actual is bound
        return

    if isinstance(expected, MockLLIL):
        assert isinstance(actual, MockLLIL)
        assert actual.op == expected.op

        if expected.bare_op() in ("CONST", "CONST_PTR"):
            expected_size = expected.width()
            actual_size = actual.width()
            assert expected_size == actual_size
            assert len(actual.ops) == 1 and len(expected.ops) == 1
            if expected_size is None:
                assert actual.ops[0] == expected.ops[0]
            else:
                mask = _mask_for_size(expected_size)
                assert (int(actual.ops[0]) & mask) == (int(expected.ops[0]) & mask)
            return

        assert len(actual.ops) == len(expected.ops)
        for act_op, exp_op in zip(actual.ops, expected.ops, strict=True):
            _match_node(act_op, exp_op, labels)
        return

    if isinstance(expected, MockReg):
        assert getattr(actual, "name", None) == expected.name
        return

    if isinstance(expected, MockFlag):
        assert getattr(actual, "name", None) == expected.name
        return

    assert actual == expected


def assert_llil(actual: list[MockLLIL], expected: list[MockLLIL]) -> None:
    assert len(actual) == len(expected)
    label_bindings: dict[str, object] = {}
    for act, exp in zip(actual, expected, strict=True):
        _match_node(act, exp, label_bindings)


@pytest.mark.parametrize("data, expected_disasm, expected_llil", m68k_test.test_cases)
def test_llil_regressions(data: bytes, expected_disasm: str, expected_llil: list[MockLLIL]) -> None:
    arch_cls = m68k_arch.M68020 if data.startswith(b"\x0c\xfc") else m68k_arch.M68000
    assert _disasm(data, arch_cls=arch_cls) == expected_disasm
    assert_llil(_lift_to_llil(data, arch_cls=arch_cls), expected_llil)


@pytest.mark.parametrize("data, expected_disasm", m68k_test.disasm_test_cases)
def test_disassembly_regressions(data: bytes, expected_disasm: str) -> None:
    assert _disasm(data, arch_cls=m68k_arch.M68020) == expected_disasm


def test_cas2_debug_log_includes_lifting_context(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="m68k.logging")

    _lift_to_llil(b"\x0c\xfc\x80\x80\x90\xc1", start_addr=0x1000, arch_cls=m68k_arch.M68020)

    assert caplog.messages == [
        "M68020 LLIL at 0x1000: provisional cas2.w lift "
        "(compare=d0:d1, update=d2:d3, memory=(a0):(a1)); "
        "paired compare/update semantics need verification"
    ]


@pytest.mark.parametrize(
    "data, expected_disasm, expected_llil",
    [
        (
            b"\xc1\x49",
            "exg       a0,a1",
            [
                mllil("SET_REG.d", [mreg("TEMP0"), mllil("REG.d", [mreg("a0")])]),
                mllil("SET_REG.d", [mreg("a0"), mllil("REG.d", [mreg("a1")])]),
                mllil("SET_REG.d", [mreg("a1"), mllil("REG.d", [mreg("TEMP0")])]),
            ],
        ),
        (
            b"\x30\x40",
            "movea.w   d0,a0",
            [
                mllil(
                    "SET_REG.d",
                    [mreg("a0"), mllil("SX.d", [mllil("REG.w", [mreg("d0")])])],
                )
            ],
        ),
        (
            b"\x52\x48",
            "addq.w    #$1,a0",
            [
                mllil(
                    "SET_REG.d",
                    [
                        mreg("a0"),
                        mllil(
                            "ADD.d",
                            [
                                mllil("REG.d", [mreg("a0")]),
                                mllil("ZX.d", [mllil("CONST.b", [1])]),
                            ],
                        ),
                    ],
                )
            ],
        ),
        (
            b"\xc0\xc1",
            "mulu.w    d1,d0",
            [
                mllil(
                    "SET_REG.d",
                    [
                        mreg("d0"),
                        mllil(
                            "MUL.d{nzvc}",
                            [
                                mllil("ZX.d", [mllil("REG.w", [mreg("d1")])]),
                                mllil("ZX.d", [mllil("REG.w", [mreg("d0")])]),
                            ],
                        ),
                    ],
                )
            ],
        ),
        (
            b"\xc1\xc1",
            "muls.w    d1,d0",
            [
                mllil(
                    "SET_REG.d",
                    [
                        mreg("d0"),
                        mllil(
                            "MUL.d{nzvc}",
                            [
                                mllil("SX.d", [mllil("REG.w", [mreg("d1")])]),
                                mllil("SX.d", [mllil("REG.w", [mreg("d0")])]),
                            ],
                        ),
                    ],
                )
            ],
        ),
        (
            b"\x10\x1f",
            "move.b    (sp)+,d0",
            [
                mllil(
                    "SET_REG.b{nzvc}",
                    [mreg("d0.b"), mllil("LOAD.b", [mllil("REG.d", [mreg("sp")])])],
                ),
                mllil(
                    "SET_REG.d",
                    [
                        mreg("sp"),
                        mllil(
                            "ADD.d",
                            [mllil("REG.d", [mreg("sp")]), mllil("CONST.d", [2])],
                        ),
                    ],
                ),
            ],
        ),
        (
            b"\x30\x38\xff\xff",
            "move.w    ($ffffffff).w,d0",
            [
                mllil(
                    "SET_REG.w{nzvc}",
                    [
                        mreg("d0.w"),
                        mllil("LOAD.w", [mllil("CONST_PTR.d", [0xffffffff])]),
                    ],
                )
            ],
        ),
    ],
)
def test_common_lifting_correctness_regressions(
    data: bytes, expected_disasm: str, expected_llil: list[MockLLIL]
) -> None:
    assert _disasm(data) == expected_disasm
    assert_llil(_lift_to_llil(data), expected_llil)


def test_addx_uses_incoming_extend_and_sticky_zero() -> None:
    nodes = _lift_to_llil(b"\xd1\x01")

    assert [node.bare_op() for node in nodes] == ["SET_REG", "SET_REG", "SET_REG", "SET_FLAG"]
    assert nodes[1].ops[1].bare_op() == "ADC"
    assert getattr(nodes[1].ops[1].ops[2].ops[0], "name", None) == "x"
    sticky_zero = nodes[3].ops[1]
    assert sticky_zero.bare_op() == "AND"
    assert sticky_zero.ops[1].bare_op() == "CMP_E"


def test_neg_sets_extend_when_the_operand_is_nonzero() -> None:
    nodes = _lift_to_llil(b"\x44\x00")

    assert [node.bare_op() for node in nodes] == ["SET_REG", "SET_REG", "SET_FLAG"]
    assert nodes[1].ops[1].op == "NEG.b{nzvc}"
    assert getattr(nodes[2].ops[0], "name", None) == "x"
    assert nodes[2].ops[1].bare_op() == "CMP_NE"


def test_bit_test_uses_mask_and_sets_z_when_clear() -> None:
    nodes = _lift_to_llil(b"\x08\x00\x00\x00")

    assert len(nodes) == 2
    zero_write = nodes[1]
    assert zero_write.bare_op() == "SET_FLAG"
    comparison = zero_write.ops[1]
    assert comparison.bare_op() == "CMP_E"
    assert comparison.ops[0].bare_op() == "AND"
    assert comparison.ops[0].ops[1].bare_op() == "LSL"


def test_word_index_and_movem_loads_are_sign_extended() -> None:
    index_nodes = _lift_to_llil(b"\x43\xf0\x10\xff")
    index_multiply = index_nodes[0].ops[1].ops[1]
    assert index_multiply.bare_op() == "MUL"
    assert index_multiply.ops[0].bare_op() == "SX"

    movem_nodes = _lift_to_llil(b"\x4c\x98\x00\x01")
    assert movem_nodes[1].op == "SET_REG.d"
    assert movem_nodes[1].ops[1].bare_op() == "SX"


def test_status_writes_restore_each_condition_flag() -> None:
    nodes = _lift_to_llil(b"\x44\xfc\x00\x01")

    assert nodes[1].op == "SET_REG.b"
    flag_writes = nodes[2:]
    assert [getattr(node.ops[0], "name", None) for node in flag_writes] == ["c", "v", "z", "n", "x"]
    masks = [node.ops[1].ops[0].ops[1].ops[0] for node in flag_writes]
    assert masks == [1, 2, 4, 8, 16]


def test_stop_updates_sr_and_terminates_the_block() -> None:
    nodes = _lift_to_llil(b"\x4e\x72\x27\x00")

    assert nodes[1].op == "SET_REG.w"
    assert getattr(nodes[1].ops[0], "name", None) == "sr"
    assert nodes[-1].bare_op() == "NORET"


def test_decoder_enforces_cpu_generation_and_instruction_length() -> None:
    m68000 = m68k_arch.M68000()
    m68020 = m68k_arch.M68020()

    cas2 = b"\x0c\xfc\x80\x80\x90\xc1"
    assert m68000.disasm.decode_instruction(cas2, 0x1000)[:2] == ("unimplemented", 2)
    assert m68020.disasm.decode_instruction(cas2, 0x1000)[0] == "cas2"

    long_branch = b"\x60\xff\x00\x00\x00\x04"
    assert m68000.disasm.decode_instruction(long_branch, 0x1000)[1] == 2
    assert m68020.disasm.decode_instruction(long_branch, 0x1000)[1] == 6

    invalid = b"\xa0\x00" + bytes(20)
    assert m68000.disasm.decode_instruction(invalid, 0x1000)[:2] == ("unimplemented", 2)


def test_decoder_rejects_reserved_and_cpu32_full_extensions() -> None:
    m68020 = m68k_arch.M68020()
    cpu32 = m68k_arch.M68330()

    valid_full_extension = b"\x11\x10"
    assert m68020.disasm.decode_effective_address(6, 0, valid_full_extension, 2)[0] is not None
    assert cpu32.disasm.decode_effective_address(6, 0, valid_full_extension, 2) == (None, None)

    for reserved_extension in (b"\x11\x00", b"\x11\x14", b"\x11\x54"):
        assert m68020.disasm.decode_effective_address(6, 0, reserved_extension, 2) == (None, None)


def test_cmp2_register_comes_from_extension_word() -> None:
    assert _disasm(b"\x02\xd0\x90\x00", arch_cls=m68k_arch.M68020) == "cmp2.w    (a0),a1"

    nodes = _lift_to_llil(b"\x02\xd0\x90\x00", arch_cls=m68k_arch.M68020)
    assert nodes[1].ops[1].bare_op() == "SX"
    assert nodes[2].ops[1].bare_op() == "SX"
    assert nodes[-2].ops[1].bare_op() == "OR"
    carry_test = nodes[-1].ops[1]
    assert [operand.bare_op() for operand in carry_test.ops] == ["CMP_SLT", "CMP_SGT"]


def test_rte_restores_flags_and_rotate_preserves_x() -> None:
    rte_nodes = _lift_to_llil(b"\x4e\x73")
    assert [getattr(node.ops[0], "name", None) for node in rte_nodes[2:7]] == ["c", "v", "z", "n", "x"]
    assert rte_nodes[-1].bare_op() == "RET"

    rotate_nodes = _lift_to_llil(b"\xe1\x98")
    assert rotate_nodes[0].ops[1].op == "ROL.d{nzvc}"
