from __future__ import annotations

import importlib

import pytest
from binaryninja import lowlevelil

m68k_test = importlib.import_module("m68k.test")
m68k_arch = importlib.import_module("m68k.m68k")


def _strip_finalizer(il_str: str) -> str:
    finalizer = m68k_test.FINALIZER
    if il_str.endswith(finalizer):
        il_str = il_str[: il_str.index(finalizer)]
    if il_str.endswith("; "):
        il_str = il_str[:-2]
    return il_str


def _canonicalize_labels(il_str: str) -> str:
    label_map: dict[str, int] = {}
    next_label = 1

    def _alloc(label_str: str) -> str:
        nonlocal next_label
        if label_str not in label_map:
            label_map[label_str] = next_label
            next_label += 2
        return str(label_map[label_str])

    def _split_top_level_args(arg_str: str) -> list[str]:
        parts: list[str] = []
        buf: list[str] = []
        depth = 0
        for ch in arg_str:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif ch == "," and depth == 0:
                parts.append("".join(buf).strip())
                buf = []
                continue
            buf.append(ch)
        parts.append("".join(buf).strip())
        return parts

    instructions = [] if not il_str else il_str.split("; ")
    out: list[str] = []
    for instr in instructions:
        if instr.startswith("LLIL_GOTO(") and instr.endswith(")"):
            label = instr[len("LLIL_GOTO(") : -1].strip()
            out.append(f"LLIL_GOTO({_alloc(label)})")
            continue

        if instr.startswith("LLIL_IF(") and instr.endswith(")"):
            inner = instr[len("LLIL_IF(") : -1]
            args = _split_top_level_args(inner)
            if len(args) == 3:
                args[1] = _alloc(args[1])
                args[2] = _alloc(args[2])
                out.append(f"LLIL_IF({','.join(args)})")
                continue

        out.append(instr)

    return "; ".join(out)


def _normalize_il(il_str: str) -> str:
    il_str = _strip_finalizer(il_str)
    if not il_str:
        return ""

    finalizer_parts = {p.strip() for p in m68k_test.FINALIZER.split("; ") if p.strip()}
    instructions = [p for p in il_str.split("; ") if p and p not in finalizer_parts]
    return _canonicalize_labels("; ".join(instructions))


def _lift_to_il_str(data: bytes, *, start_addr: int = 0) -> str:
    arch = m68k_arch.M68000()
    il = lowlevelil.LowLevelILFunction(arch)

    offset = 0
    while offset < len(data):
        il.current_address = start_addr + offset  # type: ignore[attr-defined]
        il.__class__._default_current_address = il.current_address  # type: ignore[attr-defined]
        length = arch.get_instruction_low_level_il(data[offset:], start_addr + offset, il)
        assert length is not None and length > 0
        offset += length

    result = "; ".join(m68k_test.il2str(instr) for instr in il)
    return _strip_finalizer(result)


@pytest.mark.parametrize("data, expected", m68k_test.test_cases)
def test_llil_regressions(data: bytes, expected: str) -> None:
    assert _normalize_il(_lift_to_il_str(data)) == _normalize_il(expected)
