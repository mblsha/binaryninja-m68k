from __future__ import annotations

import importlib
from typing import Any

import pytest
from binaryninja import lowlevelil
from binja_test_mocks.mock_llil import MockFlag, MockLLIL, MockReg

m68k_test = importlib.import_module("m68k.test")
m68k_arch = importlib.import_module("m68k.m68k")


def _lift_to_llil(data: bytes, *, start_addr: int = 0) -> list[MockLLIL]:
    arch = m68k_arch.M68000()
    il = lowlevelil.LowLevelILFunction(arch)

    offset = 0
    while offset < len(data):
        il.current_address = start_addr + offset  # type: ignore[attr-defined]
        length = arch.get_instruction_low_level_il(data[offset:], start_addr + offset, il)
        assert length is not None and length > 0
        offset += length

    return list(il)


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


@pytest.mark.parametrize("data, expected", m68k_test.test_cases)
def test_llil_regressions(data: bytes, expected: list[MockLLIL]) -> None:
    assert_llil(_lift_to_llil(data), expected)

