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
                            "MUL.d",
                            [
                                mllil("ZX.d", [mllil("REG.w", [mreg("d1")])]),
                                mllil("ZX.d", [mllil("REG.w", [mreg("d0")])]),
                            ],
                        ),
                    ],
                ),
                mllil(
                    "SET_FLAG",
                    [MockFlag("n"), mllil("CMP_SLT.d", [mllil("REG.d", [mreg("d0")]), mllil("CONST.d", [0])])],
                ),
                mllil(
                    "SET_FLAG",
                    [MockFlag("z"), mllil("CMP_E.d", [mllil("REG.d", [mreg("d0")]), mllil("CONST.d", [0])])],
                ),
                mllil("SET_FLAG", [MockFlag("v"), mllil("CONST.b", [0])]),
                mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [0])]),
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
                            "MUL.d",
                            [
                                mllil("SX.d", [mllil("REG.w", [mreg("d1")])]),
                                mllil("SX.d", [mllil("REG.w", [mreg("d0")])]),
                            ],
                        ),
                    ],
                ),
                mllil(
                    "SET_FLAG",
                    [MockFlag("n"), mllil("CMP_SLT.d", [mllil("REG.d", [mreg("d0")]), mllil("CONST.d", [0])])],
                ),
                mllil(
                    "SET_FLAG",
                    [MockFlag("z"), mllil("CMP_E.d", [mllil("REG.d", [mreg("d0")]), mllil("CONST.d", [0])])],
                ),
                mllil("SET_FLAG", [MockFlag("v"), mllil("CONST.b", [0])]),
                mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [0])]),
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
    assert nodes[1].ops[1].bare_op() == "AND"
    assert nodes[1].ops[1].ops[1].ops[0] == 0x1f
    flag_writes = nodes[2:]
    assert [getattr(node.ops[0], "name", None) for node in flag_writes] == ["c", "v", "z", "n", "x"]
    masks = [node.ops[1].ops[0].ops[1].ops[0] for node in flag_writes]
    assert masks == [1, 2, 4, 8, 16]


def test_stop_updates_sr_and_keeps_the_interrupt_resume_path() -> None:
    nodes = _lift_to_llil(b"\x4e\x72\x27\x00")

    assert nodes[1].op == "SET_REG.w"
    assert getattr(nodes[1].ops[0], "name", None) == "sr"
    assert nodes[-1].bare_op() == "NOP"


@pytest.mark.parametrize(
    "data, arch_cls",
    [
        (b"\x10\x08", m68k_arch.M68000),  # MOVE.B A0,D0
        (b"\x10\x40", m68k_arch.M68000),  # MOVEA.B D0,A0
        (b"\x00\x08\x00\x00", m68k_arch.M68000),  # ORI.B #0,A0
        (b"\x52\x08", m68k_arch.M68000),  # ADDQ.B #1,A0
        (b"\x4e\x80", m68k_arch.M68000),  # JSR D0
        (b"\x41\x00", m68k_arch.M68000),  # CHK.L on a 68000
        (b"\x41\xc0", m68k_arch.M68020),  # reserved LEA D0,A0 encoding
    ],
)
def test_decoder_rejects_illegal_effective_addresses(data: bytes, arch_cls: type) -> None:
    assert arch_cls().disasm.decode_instruction(data, 0x1000)[:2] == ("unimplemented", 2)


@pytest.mark.parametrize(
    "data, arch_cls",
    [
        (b"\x40\xc8", m68k_arch.M68000),  # MOVE SR,A0
        (b"\x40\xfa\x00\x00", m68k_arch.M68000),  # MOVE SR,(PC)
        (b"\x40\xfc\x00\x00", m68k_arch.M68000),  # MOVE SR,#0
        (b"\x44\xc8", m68k_arch.M68010),  # MOVE A0,CCR
        (b"\x46\xc8", m68k_arch.M68000),  # MOVE A0,SR
        (b"\x4a\x08", m68k_arch.M68020),  # TST.B A0
        (b"\x4a\x48", m68k_arch.M68000),  # TST.W A0 before 68020
        (b"\x4a\x3a\x00\x00", m68k_arch.M68000),  # TST.B (PC) before 68020
        (b"\x48\x98\x00\x01", m68k_arch.M68000),  # MOVEM store via postincrement
        (b"\x48\x88\x00\x01", m68k_arch.M68000),  # MOVEM store via An direct
        (b"\x4c\xa0\x00\x01", m68k_arch.M68000),  # MOVEM load via predecrement
        (b"\x00\xc0\x00\x00", m68k_arch.M68020),  # CMP2.B D0,D0
        (b"\xb0\x08", m68k_arch.M68000),  # CMP.B A0,D0
        (b"\x17\xc1\x01\x90", m68k_arch.M68020),  # MOVE.B D1,PC-full-EA with base suppressed
    ],
)
def test_decoder_rejects_audited_illegal_effective_addresses(
    data: bytes, arch_cls: type
) -> None:
    assert arch_cls().disasm.decode_instruction(data, 0x1000)[0] == "unimplemented"


@pytest.mark.parametrize(
    "data, arch_cls, expected_instr",
    [
        (b"\xd0\x48", m68k_arch.M68000, "add"),  # ADD.W A0,D0
        (b"\x90\x48", m68k_arch.M68000, "sub"),  # SUB.W A0,D0
        (b"\xb0\x48", m68k_arch.M68000, "cmp"),  # CMP.W A0,D0
        (b"\x01\x3c\x00\x00", m68k_arch.M68000, "btst"),  # BTST D0,#0
        (b"\x0c\x3a\x00\x00\x00\x00", m68k_arch.M68020, "cmpi"),  # CMPI.B #0,(PC)
        (b"\x4a\x48", m68k_arch.M68020, "tst"),  # TST.W A0 on 68020+
        (b"\x4a\x48", m68k_arch.M68330, "tst"),  # TST.W A0 on CPU32
        (b"\x4a\x3a\x00\x00", m68k_arch.M68020, "tst"),  # TST.B (PC) on 68020+
    ],
)
def test_decoder_accepts_audited_effective_address_exceptions(
    data: bytes, arch_cls: type, expected_instr: str
) -> None:
    assert arch_cls().disasm.decode_instruction(data, 0x1000)[0] == expected_instr


def test_decoder_handles_truncated_extension_words_without_exceptions() -> None:
    cases = [
        (m68k_arch.M68000, b"\x4e\x72\x27\x00"),
        (m68k_arch.M68000, b"\x20\x39\x12\x34\x56\x78"),
        (m68k_arch.M68020, b"\x60\xff\x00\x00\x00\x04"),
        (m68k_arch.M68020, b"\x4c\xba\x00\x01\x00\x04"),
    ]
    for arch_cls, complete in cases:
        decoder = arch_cls().disasm
        for length in range(len(complete)):
            result = decoder.decode_instruction(complete[:length], 0x1000)
            assert result[0] == "unimplemented"
            assert result[1] == min(length, 2)


def test_extb_uses_its_real_opcode_and_addx_memory_uses_address_fields() -> None:
    assert _disasm(b"\x49\xc0", arch_cls=m68k_arch.M68020) == "extb      d0"
    assert _disasm(b"\xd1\x08") == "addx.b    -(a0),-(a0)"
    assert _disasm(b"\x91\x08") == "subx.b    -(a0),-(a0)"

    nodes = _lift_to_llil(b"\xd1\x08")
    assert [node.bare_op() for node in nodes[:3]] == ["SET_REG", "SET_REG", "SET_REG"]
    assert [getattr(node.ops[0], "name", None) for node in nodes[:3]] == ["a0", "TEMP100", "a0"]
    assert nodes[1].ops[1].bare_op() == "LOAD"


def test_pc_relative_ea_uses_its_own_extension_word_as_the_base() -> None:
    data = b"\x4c\xba\x00\x01\x00\x04"  # MOVEM.W 4(PC),D0

    assert _disasm(data, start_addr=0x1000, arch_cls=m68k_arch.M68020) == "movem.w   ($00001008),d0"
    nodes = _lift_to_llil(data, start_addr=0x1000, arch_cls=m68k_arch.M68020)
    assert nodes[0].ops[1].bare_op() == "CONST_PTR"
    assert nodes[0].ops[1].ops[0] == 0x1008


@pytest.mark.parametrize(
    "data, logical_op",
    [
        (b"\x00\x7c\x20\x00", "OR"),
        (b"\x02\x7c\xdf\xff", "AND"),
        (b"\x0a\x7c\x20\x00", "XOR"),
    ],
)
def test_immediate_logical_to_sr_updates_the_full_status_register(data: bytes, logical_op: str) -> None:
    nodes = _lift_to_llil(data)

    assert nodes[0].op == "SET_REG.w"
    assert getattr(nodes[0].ops[0], "name", None) == "TEMP7"
    assert nodes[0].ops[1].bare_op() == logical_op
    assert nodes[0].ops[1].width() == 2
    composed_status = nodes[0].ops[1].ops[0]
    assert composed_status.bare_op() == "OR"
    assert composed_status.ops[0].bare_op() == "AND"
    assert composed_status.ops[0].ops[1].ops[0] == 0xa700
    assert composed_status.ops[1].bare_op() == "OR"
    assert nodes[1].op == "SET_REG.w"
    assert getattr(nodes[1].ops[0], "name", None) == "sr"
    assert [getattr(node.ops[0], "name", None) for node in nodes[2:]] == ["c", "v", "z", "n", "x"]


@pytest.mark.parametrize("data, operation", [(b"\x10\xd8", "STORE"), (b"\xb1\x08", "SUB")])
def test_shared_postincrement_eas_are_evaluated_in_source_then_destination_order(
    data: bytes, operation: str
) -> None:
    nodes = _lift_to_llil(data)

    assert getattr(nodes[0].ops[0], "name", None) == "TEMP100"
    assert nodes[0].ops[1].bare_op() == "LOAD"
    assert getattr(nodes[1].ops[0], "name", None) == "a0"
    assert nodes[2].bare_op() == operation
    assert getattr(nodes[2].ops[-1].ops[0], "name", None) == "TEMP100"
    assert getattr(nodes[3].ops[0], "name", None) == "a0"


def test_68020_movem_stores_the_original_predecrement_base_value() -> None:
    nodes = _lift_to_llil(b"\x48\xe0\x80\x80", arch_cls=m68k_arch.M68020)

    base_store = nodes[2]
    assert base_store.bare_op() == "STORE"
    assert base_store.ops[0].bare_op() == "SUB"
    assert base_store.ops[1].bare_op() == "SUB"
    assert base_store.ops[0].ops[1].ops[0] == 4
    assert base_store.ops[1].ops[1].ops[0] == 4


def test_register_shift_counts_are_modulo_64_and_asl_has_distinct_overflow() -> None:
    asl_nodes = _lift_to_llil(b"\xe1\x21")  # ASL.B D0,D1
    lsl_nodes = _lift_to_llil(b"\xe1\x29")  # LSL.B D0,D1

    for nodes in (asl_nodes, lsl_nodes):
        masked_count = nodes[1].ops[1]
        assert masked_count.bare_op() == "AND"
        assert masked_count.width() == 4
        assert masked_count.ops[1].ops[0] == 0x3f
        assert nodes[2].ops[1].op == "LSL.b{nzvc}"
        assert getattr(nodes[-2].ops[0], "name", None) == "x"
        assert getattr(nodes[-1].ops[0], "name", None) == "v"

    asl_overflow = asl_nodes[-1].ops[1]
    assert asl_overflow.bare_op() == "CMP_NE"
    assert asl_overflow.ops[0].bare_op() == "ASR"
    assert lsl_nodes[-1].ops[1].bare_op() == "CONST"
    assert lsl_nodes[-1].ops[1].ops[0] == 0

    roxl_nodes = _lift_to_llil(b"\xe1\x30")  # ROXL.B D0,D0
    assert roxl_nodes[0].op == "SET_REG.d"
    assert getattr(roxl_nodes[0].ops[0], "name", None) == "TEMP4"
    assert roxl_nodes[0].ops[1].bare_op() == "AND"
    assert roxl_nodes[2].ops[1].ops[1].bare_op() == "REG"
    assert getattr(roxl_nodes[2].ops[1].ops[1].ops[0], "name", None) == "TEMP4"


def test_cas_snapshots_memory_before_the_compare_and_failure_paths() -> None:
    nodes = _lift_to_llil(b"\x0c\xd0\x00\x40", arch_cls=m68k_arch.M68020)

    assert nodes[0].op == "SET_REG.w"
    assert getattr(nodes[0].ops[0], "name", None) == "TEMP0"
    assert nodes[0].ops[1].bare_op() == "LOAD"
    assert nodes[1].bare_op() == "SUB"
    assert nodes[1].ops[0].bare_op() == "REG"
    assert getattr(nodes[1].ops[0].ops[0], "name", None) == "TEMP0"
    failure_write = next(
        node
        for node in nodes
        if node.bare_op() == "SET_REG" and getattr(node.ops[0], "name", "").startswith("d0")
    )
    assert failure_write.ops[1].bare_op() == "REG"
    assert getattr(failure_write.ops[1].ops[0], "name", None) == "TEMP0"


def test_long_division_snapshots_an_aliased_divisor_before_writing_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    division_calls: list[tuple[int, MockLLIL, MockLLIL, bool]] = []

    def fake_division(
        il: Any, size: int, dividend: MockLLIL, divisor: MockLLIL, signed: bool
    ) -> tuple[MockLLIL, MockLLIL]:
        division_calls.append((size, dividend, divisor, signed))
        return il.const(size, 3), il.const(size, 1)

    monkeypatch.setattr(m68k_arch.M68020, "_division_result_il", staticmethod(fake_division))
    monkeypatch.setattr(
        m68k_arch.M68020,
        "_system_call_il",
        staticmethod(lambda il: il.unimplemented()),
    )

    data = b"\x4c\x41\x00\x01"  # DIVUL D1,D1:D0
    assert _disasm(data, arch_cls=m68k_arch.M68020) == "divul     d1,d1:d0"
    nodes = _lift_to_llil(data, arch_cls=m68k_arch.M68020)

    assert [getattr(node.ops[0], "name", None) for node in nodes[:2]] == ["TEMP0", "TEMP1"]
    assert getattr(nodes[0].ops[1].ops[0], "name", None) == "d1"
    assert getattr(nodes[1].ops[1].ops[0], "name", None) == "d0"
    assert len(division_calls) == 1
    size, dividend, divisor, signed = division_calls[0]
    assert (size, signed) == (4, False)
    assert getattr(dividend.ops[0], "name", None) == "TEMP1"
    assert divisor.bare_op() == "ZX"
    assert getattr(divisor.ops[0].ops[0], "name", None) == "TEMP0"

    architectural_writes = [
        getattr(node.ops[0], "name", "")
        for node in nodes
        if node.bare_op() == "SET_REG" and not getattr(node.ops[0], "name", "").startswith("TEMP")
    ]
    assert architectural_writes == ["d1", "d0"]
    assert [getattr(node.ops[0], "name", None) for node in nodes[-5:-1]] == ["n", "z", "v", "c"]


def test_wide_signed_division_checks_zero_and_32_bit_quotient_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    division_calls: list[tuple[int, bool]] = []

    def fake_division(
        il: Any, size: int, dividend: MockLLIL, divisor: MockLLIL, signed: bool
    ) -> tuple[MockLLIL, MockLLIL]:
        division_calls.append((size, signed))
        return il.const(size, 3), il.const(size, 1)

    monkeypatch.setattr(m68k_arch.M68020, "_division_result_il", staticmethod(fake_division))
    monkeypatch.setattr(
        m68k_arch.M68020,
        "_system_call_il",
        staticmethod(lambda il: il.unimplemented()),
    )

    nodes = _lift_to_llil(b"\x4c\x41\x0c\x01", arch_cls=m68k_arch.M68020)
    conditions = [node.ops[0] for node in nodes if node.bare_op() == "IF"]

    assert division_calls == [(8, True)]
    assert conditions[0].bare_op() == "CMP_E"  # divisor == 0
    assert conditions[1].bare_op() == "AND"  # INT64_MIN / -1
    assert conditions[2].bare_op() == "OR"  # quotient outside signed 32-bit range
    assert [operand.bare_op() for operand in conditions[2].ops] == ["CMP_SLT", "CMP_SGT"]
    assert any(
        node.bare_op() == "SET_FLAG"
        and getattr(node.ops[0], "name", None) == "v"
        and node.ops[1].ops[0] == 1
        for node in nodes
    )


def test_chk_sets_n_to_identify_the_failed_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        m68k_arch.M68000,
        "_system_call_il",
        staticmethod(lambda il: il.unimplemented()),
    )

    nodes = _lift_to_llil(b"\x41\x90")  # CHK.W (A0),D0
    n_writes = [
        node
        for node in nodes
        if node.bare_op() == "SET_FLAG" and getattr(node.ops[0], "name", None) == "n"
    ]

    assert [node.ops[1].ops[0] for node in n_writes] == [1, 0]
    assert any(node.bare_op() == "UNIMPL" for node in nodes)


def test_newer_cpu_rte_dispatches_on_the_exception_frame_format() -> None:
    nodes = _lift_to_llil(b"\x4e\x73", start_addr=0x1000, arch_cls=m68k_arch.M68020)

    assert all(node.bare_op() != "UNIMPL" for node in nodes)
    format_tests = [node.ops[0] for node in nodes if node.bare_op() == "IF"]
    assert [test.ops[1].ops[0] for test in format_tests] == [0, 1, 2, 9, 10, 11]
    frame_sizes = [
        node.ops[1].ops[0]
        for node in nodes
        if node.op == "SET_REG.d" and getattr(node.ops[0], "name", None) == "TEMP44"
    ]
    assert frame_sizes == [8, 12, 20, 32, 92]
    assert any(node.bare_op() == "NORET" for node in nodes)
    assert nodes[-1].bare_op() == "RET"


def test_rte_throwaway_frame_restarts_frame_processing() -> None:
    arch = m68k_arch.M68020()
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = 0x1000  # type: ignore[attr-defined]

    arch.get_instruction_low_level_il(b"\x4e\x73", 0x1000, il)

    process_label = next(node.label for node in il if isinstance(node, MockLabel))
    gotos = [node for node in il if node.bare_op() == "GOTO"]
    assert any(node.ops[0] is process_label for node in gotos)


def test_decoder_enforces_cpu_generation_and_instruction_length() -> None:
    m68000 = m68k_arch.M68000()
    m68020 = m68k_arch.M68020()
    cpu32 = m68k_arch.M68330()

    cas2 = b"\x0c\xfc\x80\x80\x90\xc1"
    assert m68000.disasm.decode_instruction(cas2, 0x1000)[:2] == ("unimplemented", 2)
    assert m68020.disasm.decode_instruction(cas2, 0x1000)[0] == "cas2"

    long_branch = b"\x60\xff\x00\x00\x00\x04"
    assert m68000.disasm.decode_instruction(long_branch, 0x1000)[1] == 2
    assert m68020.disasm.decode_instruction(long_branch, 0x1000)[1] == 6
    assert cpu32.disasm.decode_instruction(long_branch, 0x1000)[1] == 6

    assert cpu32.disasm.decode_instruction(b"\x41\x00", 0x1000)[0] == "unimplemented"

    invalid = b"\xa0\x00" + bytes(20)
    assert m68000.disasm.decode_instruction(invalid, 0x1000)[:2] == ("unimplemented", 2)


def test_decoder_rejects_reserved_full_extensions_and_accepts_cpu32_full_format() -> None:
    m68020 = m68k_arch.M68020()
    cpu32 = m68k_arch.M68330()

    valid_full_extension = b"\x11\x10"
    assert m68020.disasm.decode_effective_address(6, 0, valid_full_extension, 2)[0] is not None
    assert cpu32.disasm.decode_effective_address(6, 0, valid_full_extension, 2)[0] is not None

    for reserved_extension in (b"\x11\x00", b"\x11\x14", b"\x11\x54"):
        assert m68020.disasm.decode_effective_address(6, 0, reserved_extension, 2) == (None, None)

    # With base/index/BD suppressed, a non-null outer displacement is still
    # an active full-format address element.
    assert m68020.disasm.decode_instruction(b"\x43\xf0\x01\xd2\x00\x04", 0x1000)[:2] == (
        "lea",
        6,
    )


@pytest.mark.parametrize(
    "data, arch_cls",
    [
        (b"\x71\x00", m68k_arch.M68000),  # reserved MOVEQ bit 8
        (b"\x4c\x80", m68k_arch.M68020),  # wrong-direction pseudo EXT.W
        (b"\x4c\xc0", m68k_arch.M68020),  # wrong-direction pseudo EXT.L
        (b"\x02\xd0\x90\x01", m68k_arch.M68020),  # CHK2/CMP2 reserved extension bit
        (b"\x0c\xd0\x02\x40", m68k_arch.M68020),  # CAS reserved extension bit
        (b"\x0c\xfc\x82\x80\x90\xc1", m68k_arch.M68020),  # CAS2 reserved extension bit
        (b"\x4c\x02\x06\x01", m68k_arch.M68020),  # long MUL reserved extension bit
        (b"\x4c\x42\x06\x01", m68k_arch.M68020),  # long DIV reserved extension bit
        (b"\x0e\x50\x08\x01", m68k_arch.M68020),  # MOVES reserved extension bit
        (b"\x06\xd0\x01\x01", m68k_arch.M68020),  # CALLM reserved extension byte
    ],
)
def test_decoder_rejects_reserved_opcode_and_extension_bits(data: bytes, arch_cls: type) -> None:
    assert arch_cls().disasm.decode_instruction(data, 0x1000)[0] == "unimplemented"


def test_bitfield_decoder_consumes_the_ea_and_exposes_the_operand() -> None:
    decoded = m68k_arch.M68020().disasm.decode_instruction(b"\xe8\xf0\x00\x00\x00\x00", 0x1000)

    assert decoded[:2] == ("bftst", 6)
    assert decoded[4] is not None
    assert _disasm(b"\xe8\xf0\x00\x00\x00\x00", arch_cls=m68k_arch.M68020) == (
        "bftst     (a0,d0.w){0:32}"
    )
    nodes = _lift_to_llil(b"\xe8\xf0\x00\x00\x00\x00", arch_cls=m68k_arch.M68020)
    assert all(node.bare_op() != "UNIMPL" for node in nodes)
    assert [
        getattr(node.ops[0], "name", None)
        for node in nodes
        if node.bare_op() == "SET_FLAG"
    ] == ["n", "z", "v", "c"]


def test_long_multiply_writes_explicit_flags_from_the_architectural_result() -> None:
    single = _lift_to_llil(b"\x4c\x02\x00\x00", arch_cls=m68k_arch.M68020)
    pair = _lift_to_llil(b"\x4c\x02\x04\x01", arch_cls=m68k_arch.M68020)

    single_flags = [node for node in single if node.bare_op() == "SET_FLAG"]
    assert [getattr(node.ops[0], "name", None) for node in single_flags] == ["n", "z", "v", "c"]
    assert single_flags[2].ops[1].bare_op() == "CMP_NE"
    assert [
        getattr(node.ops[0], "name", None)
        for node in pair
        if node.bare_op() == "SET_REG" and not getattr(node.ops[0], "name", "").startswith("TEMP")
    ] == ["d1", "d0"]
    pair_flags = [node for node in pair if node.bare_op() == "SET_FLAG"]
    assert [getattr(node.ops[0], "name", None) for node in pair_flags] == ["n", "z", "v", "c"]
    assert pair_flags[2].ops[1].ops[0] == 0


def test_bgnd_is_not_lifted_as_an_ordinary_nop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        m68k_arch.M68330,
        "_system_call_il",
        staticmethod(lambda il: il.unimplemented()),
    )

    assert [node.bare_op() for node in _lift_to_llil(
        b"\x4a\xfa", arch_cls=m68k_arch.M68330
    )] == ["UNIMPL"]


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


@pytest.mark.parametrize(
    "data, arch_cls",
    [
        (b"\x41\x40", m68k_arch.M68020),  # CHK reserved fixed bit
        (b"\xc1\x80", m68k_arch.M68000),  # reserved EXG/AND collision
        (b"\x0a\xfc\x80\x80\x90\xc1", m68k_arch.M68020),  # CAS2.B is illegal
        (b"\x08\x00\x55\x00", m68k_arch.M68000),  # static bit reserved byte
        (b"\x00\x3c\x55\x00", m68k_arch.M68000),  # ORI.B reserved byte
        (b"\x02\x3c\x55\x00", m68k_arch.M68000),  # ANDI.B reserved byte
        (b"\x0a\x3c\x55\x00", m68k_arch.M68000),  # EORI.B reserved byte
        (b"\xf4\x20", m68k_arch.M68040),  # CPUSH scope 00
    ],
)
def test_decoder_rejects_newly_audited_reserved_encodings(data: bytes, arch_cls: type) -> None:
    assert arch_cls().disasm.decode_instruction(data, 0x1000)[0] == "unimplemented"


@pytest.mark.parametrize(
    "data, expected_instr",
    [
        (b"\xc1\x41", "exg"),  # EXG D0,D1
        (b"\xc1\x89", "exg"),  # EXG D0,A1
        (b"\xf4\x28", "cpush"),  # CPUSHL with legal scope 01
    ],
)
def test_decoder_keeps_valid_encodings_adjacent_to_reserved_fields(
    data: bytes, expected_instr: str
) -> None:
    arch_cls = m68k_arch.M68040 if data.startswith(b"\xf4") else m68k_arch.M68000
    assert arch_cls().disasm.decode_instruction(data, 0x1000)[0] == expected_instr


def test_cas2_alias_failure_keeps_memory_operand_one() -> None:
    nodes = _lift_to_llil(b"\x0c\xfc\x80\x80\x90\xc0", arch_cls=m68k_arch.M68020)
    compare_register_writes = [
        node
        for node in nodes
        if node.bare_op() == "SET_REG" and getattr(node.ops[0], "name", None) == "d0"
    ]

    assert len(compare_register_writes) == 1
    assert getattr(compare_register_writes[0].ops[1].ops[0], "name", None) == "TEMP0"


@pytest.mark.parametrize(
    "data, arch_cls",
    [
        (b"\x81\xc0", m68k_arch.M68000),
        (b"\x4c\x40\x00\x00", m68k_arch.M68020),
    ],
)
def test_divide_by_zero_clears_c_before_the_trap(
    data: bytes, arch_cls: type, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(arch_cls, "_system_call_il", staticmethod(lambda il: il.unimplemented()))
    monkeypatch.setattr(
        arch_cls,
        "_division_result_il",
        staticmethod(
            lambda il, size, dividend, divisor, signed: (
                il.const(size, 0),
                il.const(size, 0),
            )
        ),
    )
    nodes = _lift_to_llil(data, arch_cls=arch_cls)
    trap_index = next(i for i, node in enumerate(nodes) if node.bare_op() == "UNIMPL")
    carry_write = nodes[trap_index - 1]

    assert carry_write.bare_op() == "SET_FLAG"
    assert getattr(carry_write.ops[0], "name", None) == "c"
    assert carry_write.ops[1].ops[0] == 0


def test_word_divs_checks_host_width_overflow_before_dividing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        m68k_arch.M68000,
        "_division_result_il",
        staticmethod(lambda il, size, dividend, divisor, signed: (il.const(size, 0), il.const(size, 0))),
    )
    monkeypatch.setattr(
        m68k_arch.M68000,
        "_system_call_il",
        staticmethod(lambda il: il.unimplemented()),
    )

    nodes = _lift_to_llil(b"\x81\xc0")
    conditions = [node.ops[0] for node in nodes if node.bare_op() == "IF"]

    assert conditions[0].bare_op() == "CMP_E"  # divisor == 0
    assert conditions[1].bare_op() == "AND"  # INT32_MIN / -1
    assert conditions[2].bare_op() == "OR"  # quotient outside signed 16-bit range


def test_long_multiply_with_an_aliased_result_pair_is_not_over_specified(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="m68k.logging")

    assert _disasm(b"\x4c\x00\x04\x00", arch_cls=m68k_arch.M68020) == "mulu      d0,d0:d0"
    assert [node.bare_op() for node in _lift_to_llil(
        b"\x4c\x00\x04\x00", start_addr=0x1000, arch_cls=m68k_arch.M68020
    )] == ["UNIMPL"]
    assert caplog.messages == [
        "M68020 LLIL at 0x1000: mulu uses the same register (d0) for both halves of an "
        "undefined 64-bit result; emitting unimplemented instead of deterministic register state"
    ]


@pytest.mark.parametrize(
    "data, expected_disasm, arithmetic_op",
    [
        (b"\xc1\x01", "abcd      d1,d0", "ADD"),
        (b"\x81\x01", "sbcd      d1,d0", "SUB"),
        (b"\x48\x00", "nbcd      d0", "SUB"),
    ],
)
def test_bcd_lifting_writes_decimal_result_and_defined_flags(
    data: bytes, expected_disasm: str, arithmetic_op: str
) -> None:
    assert _disasm(data) == expected_disasm
    nodes = _lift_to_llil(data)

    assert all(node.bare_op() != "UNIMPL" for node in nodes)
    result_write = next(
        node
        for node in nodes
        if node.bare_op() == "SET_REG" and getattr(node.ops[0], "name", None) == "d0.b"
    )
    assert getattr(result_write.ops[1].ops[0], "name", None) == "TEMP5"
    assert any(
        node.bare_op() == "SET_REG"
        and getattr(node.ops[0], "name", None) == "TEMP5"
        and node.ops[1].bare_op() == arithmetic_op
        for node in nodes
    )

    flag_writes = [node for node in nodes if node.bare_op() == "SET_FLAG"]
    assert [getattr(node.ops[0], "name", None) for node in flag_writes] == ["x", "c", "z"]
    assert flag_writes[0].ops[1] == flag_writes[1].ops[1]
    assert flag_writes[2].ops[1].bare_op() == "AND"


def test_bcd_memory_form_evaluates_shared_predecrement_operands_in_order() -> None:
    nodes = _lift_to_llil(b"\xc1\x08")  # ABCD -(A0),-(A0)

    assert [getattr(node.ops[0], "name", None) for node in nodes[:4]] == [
        "a0",
        "TEMP100",
        "a0",
        "TEMP0",
    ]
    assert nodes[1].ops[1].bare_op() == "LOAD"
    assert any(node.bare_op() == "STORE" for node in nodes)


@pytest.mark.parametrize(
    "data, expected_loads, expected_stores",
    [
        (b"\x01\x08\x00\x00", 2, 0),  # MOVEP.W (0,A0),D0
        (b"\x01\x48\x00\x00", 4, 0),  # MOVEP.L (0,A0),D0
        (b"\x01\x88\x00\x00", 0, 2),  # MOVEP.W D0,(0,A0)
        (b"\x01\xc8\x00\x00", 0, 4),  # MOVEP.L D0,(0,A0)
    ],
)
def test_movep_uses_interleaved_peripheral_bytes(
    data: bytes, expected_loads: int, expected_stores: int
) -> None:
    nodes = _lift_to_llil(data)

    assert all(node.bare_op() != "UNIMPL" for node in nodes)
    loads: list[MockLLIL] = []

    def collect_loads(node: Any) -> None:
        if not isinstance(node, MockLLIL):
            return
        if node.bare_op() == "LOAD":
            loads.append(node)
        for operand in node.ops:
            collect_loads(operand)

    for node in nodes:
        collect_loads(node)
    stores = [node for node in nodes if node.bare_op() == "STORE"]
    assert len(loads) == expected_loads
    assert len(stores) == expected_stores
    assert all(node.width() == 1 for node in loads + stores)
    if stores:
        assert [node.ops[0].ops[1].ops[0] for node in stores] == list(
            range(0, expected_stores * 2, 2)
        )


def test_moves_preserves_register_width_and_reports_flat_address_space(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="m68k.logging")

    data_nodes = _lift_to_llil(b"\x0e\x50\x00\x00", start_addr=0x1000, arch_cls=m68k_arch.M68010)
    address_nodes = _lift_to_llil(b"\x0e\x50\x80\x00", start_addr=0x1002, arch_cls=m68k_arch.M68010)
    store_nodes = _lift_to_llil(b"\x0e\x50\x48\x00", start_addr=0x1004, arch_cls=m68k_arch.M68010)

    assert data_nodes[0].op == "SET_REG.w"
    assert getattr(data_nodes[0].ops[0], "name", None) == "d0.w"
    assert address_nodes[0].op == "SET_REG.d"
    assert getattr(address_nodes[0].ops[0], "name", None) == "a0"
    assert address_nodes[0].ops[1].bare_op() == "SX"
    assert [node.bare_op() for node in store_nodes] == ["STORE"]
    assert all(
        node.bare_op() != "SET_FLAG"
        for node in data_nodes + address_nodes + store_nodes
    )
    assert caplog.messages == [
        "M68010 LLIL at 0x1000: moves.w uses SFC; alternate address-space selection "
        "is represented in Binary Ninja's flat LLIL memory",
        "M68010 LLIL at 0x1002: moves.w uses SFC; alternate address-space selection "
        "is represented in Binary Ninja's flat LLIL memory",
        "M68010 LLIL at 0x1004: moves.w uses DFC; alternate address-space selection "
        "is represented in Binary Ninja's flat LLIL memory",
    ]


@pytest.mark.parametrize(
    "data",
    [
        b"\xe8\xd0\x00\x08",  # BFTST
        b"\xea\xd0\x00\x08",  # BFCHG
        b"\xec\xd0\x00\x08",  # BFCLR
        b"\xeb\xd0\x10\x08",  # BFEXTS
        b"\xe9\xd0\x10\x08",  # BFEXTU
        b"\xed\xd0\x10\x08",  # BFFFO
        b"\xef\xd0\x10\x08",  # BFINS
        b"\xee\xd0\x00\x08",  # BFSET
    ],
)
def test_all_bitfield_instructions_have_explicit_lifts(data: bytes) -> None:
    nodes = _lift_to_llil(data, arch_cls=m68k_arch.M68020)

    assert all(node.bare_op() != "UNIMPL" for node in nodes)
    flags = [
        getattr(node.ops[0], "name", None)
        for node in nodes
        if node.bare_op() == "SET_FLAG"
    ]
    assert flags == ["n", "z", "v", "c"]


def test_memory_bitfields_use_only_byte_sized_accesses_and_dynamic_span_guards() -> None:
    nodes = _lift_to_llil(b"\xea\xd0\x01\xc0", arch_cls=m68k_arch.M68020)  # BFCHG (A0){7:32}

    accesses: list[MockLLIL] = []

    def collect_accesses(node: Any) -> None:
        if not isinstance(node, MockLLIL):
            return
        if node.bare_op() in ("LOAD", "STORE"):
            accesses.append(node)
        for operand in node.ops:
            collect_accesses(operand)

    for node in nodes:
        collect_accesses(node)
    assert accesses
    assert all(access.width() == 1 for access in accesses)
    span_guards = [node for node in nodes if node.bare_op() == "IF"]
    assert len(span_guards) == 8  # four read guards and four write guards
    assert all(node.ops[0].bare_op() == "CMP_UGT" for node in span_guards)


def test_register_bitfield_wraps_with_rotates_and_bfffo_scans_the_selected_width() -> None:
    changed = _lift_to_llil(b"\xea\xc0\x00\x08", arch_cls=m68k_arch.M68020)
    first_one = _lift_to_llil(b"\xed\xc0\x10\x08", arch_cls=m68k_arch.M68020)

    changed_ops = [node.bare_op() for node in changed]
    assert "LOAD" not in changed_ops and "STORE" not in changed_ops
    assert any(
        isinstance(operand, MockLLIL) and operand.bare_op() == "ROL"
        for node in changed
        for operand in node.ops
    )
    result_write = next(
        node
        for node in first_one
        if node.bare_op() == "SET_REG" and getattr(node.ops[0], "name", None) == "d1"
    )
    assert result_write.ops[1].bare_op() == "ADD"
    assert sum(
        1
        for node in first_one
        for operand in node.ops
        if isinstance(operand, MockLLIL) and operand.bare_op() == "SUB"
    ) >= 1


def test_callm_resolves_the_module_entry_and_logs_unrepresented_module_state(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="m68k.logging")

    nodes = _lift_to_llil(b"\x06\xd0\x00\x03", start_addr=0x1000, arch_cls=m68k_arch.M68020)

    assert [node.bare_op() for node in nodes] == ["SET_REG", "CALL"]
    target = nodes[1].ops[0]
    assert target.bare_op() == "ADD"
    assert target.ops[0].bare_op() == "LOAD"
    assert target.ops[0].ops[0].ops[1].ops[0] == 4
    assert target.ops[1].ops[0] == 2
    assert caplog.messages == [
        "M68020 LLIL at 0x1000: CALLM #3,(a0) resolves the descriptor entry point; "
        "module-stack and external access-level changes are represented by call side effects"
    ]


def test_rtm_restores_module_frame_state_and_returns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="m68k.logging")

    nodes = _lift_to_llil(b"\x06\xc0", start_addr=0x1000, arch_cls=m68k_arch.M68020)

    assert all(node.bare_op() != "UNIMPL" for node in nodes)
    d0_write = next(
        node
        for node in nodes
        if node.bare_op() == "SET_REG" and getattr(node.ops[0], "name", None) == "d0"
    )
    assert d0_write.ops[1].bare_op() == "LOAD"
    assert d0_write.ops[1].ops[0].ops[1].ops[0] == 0x10
    assert any(
        node.bare_op() == "SET_REG" and getattr(node.ops[0], "name", None) == "sp"
        for node in nodes
    )
    assert nodes[-1].bare_op() == "RET"
    assert caplog.messages == [
        "M68020 LLIL at 0x1000: RTM restores the architectural module frame; "
        "external access-level validation is not represented in LLIL"
    ]


def test_cpush_is_an_explicit_value_level_noop_with_debug_context(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="m68k.logging")

    nodes = _lift_to_llil(b"\xf4\x28", start_addr=0x1000, arch_cls=m68k_arch.M68040)

    assert [node.bare_op() for node in nodes] == ["NOP"]
    assert caplog.messages == [
        "M68040 LLIL at 0x1000: CPUSH cache state has no architectural value-level LLIL effect"
    ]


@pytest.mark.parametrize(
    "arch_cls, expected_formats",
    [
        (m68k_arch.M68010, [0, 8]),
        (m68k_arch.M68020, [0, 1, 2, 9, 10, 11]),
        (m68k_arch.M68040, [0, 1, 2, 3, 4, 7]),
        (m68k_arch.M68330, [0, 1, 2, 12]),
    ],
)
def test_rte_uses_cpu_specific_frame_formats(arch_cls: type, expected_formats: list[int]) -> None:
    nodes = _lift_to_llil(b"\x4e\x73", arch_cls=arch_cls)
    conditions = [node.ops[0] for node in nodes if node.bare_op() == "IF"]

    assert [condition.ops[1].ops[0] for condition in conditions] == expected_formats
    assert nodes[-1].bare_op() == "RET"


@pytest.mark.parametrize(
    "arch_cls, expected_mask",
    [
        (m68k_arch.M68000, 0xA71F),
        (m68k_arch.M68020, 0xF71F),
        (m68k_arch.M68330, 0xE71F),
    ],
)
def test_status_register_writes_mask_reserved_bits(arch_cls: type, expected_mask: int) -> None:
    nodes = _lift_to_llil(b"\x4e\x72\xff\xff", arch_cls=arch_cls)
    sr_write = nodes[1]

    assert sr_write.op == "SET_REG.w"
    assert sr_write.ops[1].bare_op() == "AND"
    assert sr_write.ops[1].ops[1].ops[0] == expected_mask


def test_ccr_reads_and_writes_cannot_leak_reserved_bits() -> None:
    write_nodes = _lift_to_llil(b"\x44\xfc\x00\xe0")
    read_nodes = _lift_to_llil(b"\x40\xc0")  # MOVE SR,D0

    assert write_nodes[1].ops[1].ops[1].ops[0] == 0x1f
    composed_sr = read_nodes[0].ops[1]
    assert composed_sr.bare_op() == "OR"
    assert composed_sr.ops[0].ops[1].ops[0] == 0xA700


@pytest.mark.parametrize(
    "data, arch_cls",
    [
        (b"\x50\xd8", m68k_arch.M68000),  # ST.B (A0)+
        (b"\x0c\xd8\x00\x40", m68k_arch.M68020),  # CAS.W D0,D1,(A0)+
    ],
)
def test_internal_joins_cannot_bypass_postincrement(data: bytes, arch_cls: type) -> None:
    arch = arch_cls()
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = 0x1000  # type: ignore[attr-defined]
    length = arch.disasm.decode_instruction(data, 0x1000)[1]
    next_label = il.register_label_for_address(0x1000 + length)  # type: ignore[attr-defined]

    assert arch.get_instruction_low_level_il(data, 0x1000, il) == length
    nodes = [node for node in il if not isinstance(node, MockLabel)]
    gotos = [node for node in nodes if node.bare_op() == "GOTO"]

    assert gotos
    assert all(node.ops[0] is not next_label for node in gotos)
    assert nodes[-1].bare_op() == "SET_REG"
    assert getattr(nodes[-1].ops[0], "name", None) == "a0"


@pytest.mark.parametrize("data", [b"\x80\xd8", b"\x41\x98"])
def test_trapping_source_postincrement_happens_before_internal_control_flow(
    data: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        m68k_arch.M68000,
        "_system_call_il",
        staticmethod(lambda il: il.unimplemented()),
    )
    monkeypatch.setattr(
        m68k_arch.M68000,
        "_division_result_il",
        staticmethod(
            lambda il, size, dividend, divisor, signed: (
                il.const(size, 0),
                il.const(size, 0),
            )
        ),
    )
    nodes = _lift_to_llil(data)

    assert getattr(nodes[0].ops[0], "name", None) == "TEMP100"
    assert nodes[0].ops[1].bare_op() == "LOAD"
    assert getattr(nodes[1].ops[0], "name", None) == "a0"
    first_branch = next(i for i, node in enumerate(nodes) if node.bare_op() == "IF")
    assert first_branch > 1
    trap = next(i for i, node in enumerate(nodes) if node.bare_op() == "UNIMPL")
    assert trap > 1


@pytest.mark.parametrize(
    "data, branch_selector",
    [
        (b"\x60\x04", lambda nodes: nodes[0].ops[0]),  # BRA.S
        (b"\x66\x04", lambda nodes: nodes[0].ops[1]),  # BNE.S true edge
        (b"\x51\xc8\x00\x04", lambda nodes: [n for n in nodes if n.bare_op() == "IF"][1].ops[2]),
    ],
)
def test_pc_relative_label_probing_keeps_the_real_current_address(
    data: bytes, branch_selector: Any
) -> None:
    arch = m68k_arch.M68000()
    il = lowlevelil.LowLevelILFunction(arch)
    il.current_address = 0x1000  # type: ignore[attr-defined]
    target = 0x1006 if len(data) == 2 else 0x1006
    target_label = il.register_label_for_address(target)  # type: ignore[attr-defined]

    arch.get_instruction_low_level_il(data, 0x1000, il)
    nodes = [node for node in il if not isinstance(node, MockLabel)]

    assert branch_selector(nodes) is target_label
