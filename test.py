from __future__ import annotations

import os
from dataclasses import dataclass

os.environ.setdefault("FORCE_BINJA_MOCK", "1")

# Installs a stubbed `binaryninja` module into `sys.modules`.
from binja_test_mocks import binja_api  # noqa: F401  # pyright: ignore
from binja_test_mocks import mock_llil
from binja_test_mocks.mock_llil import MockFlag, MockLLIL, MockReg, mllil, mreg

from .m68k import RTS_PASS_FLAGS

mock_llil.set_size_lookup(
    {1: ".b", 2: ".w", 4: ".d", 8: ".q", 16: ".o"},
    {"b": 1, "w": 2, "d": 4, "q": 8, "o": 16},
)


@dataclass(frozen=True)
class LabelRef:
    """Placeholder for a LowLevelILLabel (bound during assertion)."""

    name: str


def _l(name: str) -> LabelRef:
    return LabelRef(name)


def _flag(name: str) -> MockFlag:
    return MockFlag(name)


def _il(op: str, *ops: object) -> MockLLIL:
    return mllil(op, list(ops))


def _maybe_restore_flags() -> list[MockLLIL]:
    if not RTS_PASS_FLAGS:
        return []
    return [_il("SET_FLAG", _flag("c"), _il("REG.b", mreg("rc")))]


def _rts_expected() -> list[MockLLIL]:
    out: list[MockLLIL] = []
    if RTS_PASS_FLAGS:
        out.append(_il("SET_REG.b", mreg("rc"), _il("FLAG", _flag("c"))))
    out.append(_il("RET", _il("POP.d")))
    return out


test_cases: list[tuple[bytes, list[MockLLIL]]] = [
    # moveq     #$0000,d0
    (b"\x70\x00", [_il("SET_REG.d{nzvc}", mreg("d0"), _il("CONST.d", 0))]),

    # subq.b    #$1,d0
    # FIXME: Generate flag 'x'
    (
        b"\x53\x00",
        [
            _il(
                "SET_REG.b",
                mreg("d0.b"),
                _il("SUB.b{*}", _il("REG.b", mreg("d0")), _il("CONST.b", 1)),
            )
        ],
    ),

    # jsr 0x5dc1c, no arguments for this call
    (b"\x4e\xb9\x00\x05\xdc\x1c", [_il("CALL", _il("CONST_PTR.d", 0x5DC1C))] + _maybe_restore_flags()),

    # at 0x53a, jsr 0x546, seems to be correctly interpreted as a call
    (b"\x4e\xba\x00\x0a", [_il("CALL", _il("CONST_PTR.d", 0xC))] + _maybe_restore_flags()),

    # lea (data_7a9ee[2]),a1
    (b"\x43\xf9\x00\x07\xa9\xf0", [_il("SET_REG.d", mreg("a1"), _il("CONST_PTR.d", 0x7A9F0))]),

    # tst.w     d1
    (
        b"\x4a\x41",
        [
            _il("SUB.w{nz}", _il("REG.w", mreg("d1")), _il("CONST.w", 0)),
            _il("SET_FLAG", _flag("v"), _il("CONST.b", 0)),
            _il("SET_FLAG", _flag("c"), _il("CONST.b", 0)),
        ],
    ),

    # lea       ($279d2e),a0
    # move      $-004(a0),$0074(a6)
    (
        b"\x41\xf9\x00\x27\x9d\x2e\x2d\x68\xff\xfc\x00\x74",
        [
            _il("SET_REG.d", mreg("a0"), _il("CONST_PTR.d", 0x279D2E)),
            _il(
                "STORE.d{nzvc}",
                _il("ADD.d", _il("REG.d", mreg("a6")), _il("CONST.w", 0x74)),
                _il(
                    "LOAD.d",
                    _il("SUB.d", _il("REG.d", mreg("a0")), _il("CONST.w", 0x4)),
                ),
            ),
        ],
    ),

    # beq       (data_10)
    (
        b"\x67\x00\x00\x0e",
        [
            _il("IF", _il("FLAG_COND", 0, None), _l("t"), _l("f")),
            _il("JUMP", _il("CONST_PTR.d", 0x10)),
        ],
    ),

    # jmp       ($4c862)
    (b"\x4e\xf9\x00\x04\xc8\x62", [_il("JUMP", _il("CONST_PTR.d", 0x4C862))]),

    # bra       (data_28)
    (b"\x60\x00\x00\x26", [_il("JUMP", _il("CONST_PTR.d", 0x28))]),

    # dbf       d7,(data_-2c)
    (
        b"\x51\xcf\xff\xd4",
        [
            _il("IF", _il("CONST.b", 0), _l("skip"), _l("decrement")),
            _il(
                "SET_REG.w",
                mreg("TEMP0"),
                _il("SUB.w", _il("REG.w", mreg("d7")), _il("CONST.w", 1)),
            ),
            _il("SET_REG.w", mreg("d7.w"), _il("REG.w", mreg("TEMP0"))),
            _il(
                "IF",
                _il(
                    "CMP_E.w",
                    _il("REG.w", mreg("TEMP0")),
                    _il("CONST.w", -1),
                ),
                _l("skip"),
                _l("branch"),
            ),
            _il("JUMP", _il("CONST_PTR.d", -42)),
        ],
    ),

    # bcc       (data_5a)
    (
        b"\x64\x00\x00\x58",
        [
            _il("IF", _il("FLAG_COND", 7, None), _l("t"), _l("f")),
            _il("JUMP", _il("CONST_PTR.d", 0x5A)),
        ],
    ),

    # rts
    (b"\x4e\x75", _rts_expected()),

    # andi.b    #$-2,ccr
    (b"\x02\x3c\x00\xfe", [_il("SET_FLAG", _flag("c"), _il("CONST.b", 0))]),

    # ori.b     #$1,ccr
    (
        b"\x00\x3c\x00\x01",
        [
            _il("SET_FLAG", _flag("c"), _il("CONST.b", 1)),
            _il("SET_FLAG", _flag("x"), _il("CONST.b", 1)),
        ],
    ),

    # scs.b     d1
    (
        b"\x55\xc1",
        [
            _il("IF", _il("FLAG_COND", 3, None), _l("set"), _l("clear")),
            _il("SET_REG.b", mreg("d1.b"), _il("CONST.b", 1)),
            _il("GOTO", _l("skip")),
            _il("SET_REG.b", mreg("d1.b"), _il("CONST.b", 0)),
            _il("GOTO", _l("skip")),
        ],
    ),

    # swap      d6
    (
        b"\x48\x46",
        [_il("SET_REG.d", mreg("d6"), _il("ROR.d", _il("REG.d", mreg("d6")), _il("CONST.b", 0x10)))],
    ),

    # rtr
    (
        b"\x4e\x77",
        [
            _il("SET_REG.w", mreg("ccr"), _il("POP.w")),
            _il("RET", _il("POP.d")),
        ],
    ),
]

