from __future__ import annotations

from dataclasses import dataclass
import importlib.util
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from binja_test_mocks.mock_llil import MockLLIL


@dataclass(frozen=True)
class LabelRef:
    """Placeholder for a LowLevelILLabel (bound during assertion)."""

    name: str


def _running_under_pytest() -> bool:
    return any(name == "pytest" or name.startswith("_pytest") for name in sys.modules)

def _running_inside_binary_ninja() -> bool:
    try:
        return importlib.util.find_spec("binaryninjaui") is not None
    except (ValueError, ImportError):
        return False


test_cases: list[tuple[bytes, str, list[MockLLIL]]] = []

if _running_under_pytest() and not _running_inside_binary_ninja():
    from binja_test_mocks.mock_llil import MockFlag, MockLLIL, mllil, mreg

    from .m68k import RTS_PASS_FLAGS

    def _maybe_restore_flags() -> list[MockLLIL]:
        if not RTS_PASS_FLAGS:
            return []
        return [mllil("SET_FLAG", [MockFlag("c"), mllil("REG.b", [mreg("rc")])])]

    def _rts_expected() -> list[MockLLIL]:
        out: list[MockLLIL] = []
        if RTS_PASS_FLAGS:
            out.append(mllil("SET_REG.b", [mreg("rc"), mllil("FLAG", [MockFlag("c")])]))
        out.append(mllil("RET", [mllil("POP.d", [])]))
        return out

    test_cases = [
        # moveq     #$0000,d0
        (
            b"\x70\x00",
            "moveq     #$0000,d0",
            [mllil("SET_REG.d{nzvc}", [mreg("d0"), mllil("CONST.d", [0])])],
        ),

        # subq.b    #$1,d0
        # FIXME: Generate flag 'x'
        (
            b"\x53\x00",
            "subq.b    #$1,d0",
            [
                mllil(
                    "SET_REG.b",
                    [
                        mreg("d0.b"),
                        mllil(
                            "SUB.b{*}",
                            [
                                mllil("REG.b", [mreg("d0")]),
                                mllil("CONST.b", [1]),
                            ],
                        ),
                    ],
                ),
            ],
        ),

        # jsr 0x5dc1c, no arguments for this call
        (
            b"\x4e\xb9\x00\x05\xdc\x1c",
            "jsr       ($5dc1c)",
            [mllil("CALL", [mllil("CONST_PTR.d", [0x5DC1C])])] + _maybe_restore_flags(),
        ),

        # at 0x53a, jsr 0x546, seems to be correctly interpreted as a call
        (
            b"\x4e\xba\x00\x0a",
            "jsr       ($0000000c)",
            [mllil("CALL", [mllil("CONST_PTR.d", [0xC])])] + _maybe_restore_flags(),
        ),

        # lea (data_7a9ee[2]),a1
        (
            b"\x43\xf9\x00\x07\xa9\xf0",
            "lea       ($7a9f0),a1",
            [mllil("SET_REG.d", [mreg("a1"), mllil("CONST_PTR.d", [0x7A9F0])])],
        ),

        # tst.w     d1
        (
            b"\x4a\x41",
            "tst.w     d1",
            [
                mllil(
                    "SUB.w{nz}",
                    [
                        mllil("REG.w", [mreg("d1")]),
                        mllil("CONST.w", [0]),
                    ],
                ),
                mllil("SET_FLAG", [MockFlag("v"), mllil("CONST.b", [0])]),
                mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [0])]),
            ],
        ),

        # lea       ($279d2e),a0
        # move      $-004(a0),$0074(a6)
        (
            b"\x41\xf9\x00\x27\x9d\x2e\x2d\x68\xff\xfc\x00\x74",
            "lea       ($279d2e),a0\nmove      $-004(a0),$0074(a6)",
            [
                mllil("SET_REG.d", [mreg("a0"), mllil("CONST_PTR.d", [0x279D2E])]),
                mllil(
                    "STORE.d{nzvc}",
                    [
                        mllil(
                            "ADD.d",
                            [
                                mllil("REG.d", [mreg("a6")]),
                                mllil("CONST.w", [0x74]),
                            ],
                        ),
                        mllil(
                            "LOAD.d",
                            [
                                mllil(
                                    "SUB.d",
                                    [
                                        mllil("REG.d", [mreg("a0")]),
                                        mllil("CONST.w", [0x4]),
                                    ],
                                )
                            ],
                        ),
                    ],
                ),
            ],
        ),

        # beq       (data_10)
        (
            b"\x67\x00\x00\x0e",
            "beq       ($00000010)",
            [
                mllil(
                    "IF",
                    [
                        mllil("FLAG_COND", [0, None]),
                        LabelRef("t"),
                        LabelRef("f"),
                    ],
                ),
                mllil("JUMP", [mllil("CONST_PTR.d", [0x10])]),
            ],
        ),

        # jmp       ($4c862)
        (
            b"\x4e\xf9\x00\x04\xc8\x62",
            "jmp       ($4c862)",
            [mllil("JUMP", [mllil("CONST_PTR.d", [0x4C862])])],
        ),

        # bra       (data_28)
        (
            b"\x60\x00\x00\x26",
            "bra       ($00000028)",
            [mllil("JUMP", [mllil("CONST_PTR.d", [0x28])])],
        ),

        # dbf       d7,(data_-2c)
        (
            b"\x51\xcf\xff\xd4",
            "dbf       d7,($-000002a)",
            [
                mllil(
                    "IF",
                    [
                        mllil("CONST.b", [0]),
                        LabelRef("skip"),
                        LabelRef("decrement"),
                    ],
                ),
                mllil(
                    "SET_REG.w",
                    [
                        mreg("TEMP0"),
                        mllil(
                            "SUB.w",
                            [
                                mllil("REG.w", [mreg("d7")]),
                                mllil("CONST.w", [1]),
                            ],
                        ),
                    ],
                ),
                mllil("SET_REG.w", [mreg("d7.w"), mllil("REG.w", [mreg("TEMP0")])]),
                mllil(
                    "IF",
                    [
                        mllil(
                            "CMP_E.w",
                            [
                                mllil("REG.w", [mreg("TEMP0")]),
                                mllil("CONST.w", [-1]),
                            ],
                        ),
                        LabelRef("skip"),
                        LabelRef("branch"),
                    ],
                ),
                mllil("JUMP", [mllil("CONST_PTR.d", [-42])]),
            ],
        ),

        # bcc       (data_5a)
        (
            b"\x64\x00\x00\x58",
            "bcc       ($0000005a)",
            [
                mllil(
                    "IF",
                    [
                        mllil("FLAG_COND", [7, None]),
                        LabelRef("t"),
                        LabelRef("f"),
                    ],
                ),
                mllil("JUMP", [mllil("CONST_PTR.d", [0x5A])]),
            ],
        ),

        # rts
        (b"\x4e\x75", "rts", _rts_expected()),

        # andi.b    #$-2,ccr
        (
            b"\x02\x3c\x00\xfe",
            "andi.b    #$-2,ccr",
            [mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [0])])],
        ),

        # ori.b     #$1,ccr
        (
            b"\x00\x3c\x00\x01",
            "ori.b     #$1,ccr",
            [
                mllil("SET_FLAG", [MockFlag("c"), mllil("CONST.b", [1])]),
                mllil("SET_FLAG", [MockFlag("x"), mllil("CONST.b", [1])]),
            ],
        ),

        # scs.b     d1
        (
            b"\x55\xc1",
            "scs.b     d1",
            [
                mllil(
                    "IF",
                    [
                        mllil("FLAG_COND", [3, None]),
                        LabelRef("set"),
                        LabelRef("clear"),
                    ],
                ),
                mllil("SET_REG.b", [mreg("d1.b"), mllil("CONST.b", [1])]),
                mllil("GOTO", [LabelRef("skip")]),
                mllil("SET_REG.b", [mreg("d1.b"), mllil("CONST.b", [0])]),
                mllil("GOTO", [LabelRef("skip")]),
            ],
        ),

        # swap      d6
        (
            b"\x48\x46",
            "swap      d6",
            [
                mllil(
                    "SET_REG.d",
                    [
                        mreg("d6"),
                        mllil(
                            "ROR.d",
                            [
                                mllil("REG.d", [mreg("d6")]),
                                mllil("CONST.b", [0x10]),
                            ],
                        ),
                    ],
                )
            ],
        ),

        # rtr
        (
            b"\x4e\x77",
            "rtr",
            [
                mllil("SET_REG.w", [mreg("ccr"), mllil("POP.w", [])]),
                mllil("RET", [mllil("POP.d", [])]),
            ],
        ),
    ]
