from __future__ import annotations

import os
import sys
import types
from pathlib import Path

os.environ.setdefault("FORCE_BINJA_MOCK", "1")

# Installs a stubbed `binaryninja` module into `sys.modules`.
from binja_test_mocks import binja_api  # noqa: F401  # pyright: ignore


def _install_llil_test_helpers() -> None:
    import binaryninja
    from binja_test_mocks import mock_llil
    from binja_test_mocks.mock_llil import MockFlag, MockLLIL, MockLowLevelILFunction, MockReg, mreg
    from binaryninja.enums import LowLevelILOperation

    mock_llil.set_size_lookup(
        {1: ".b", 2: ".w", 4: ".d", 8: ".q", 16: ".o"},
        {"b": 1, "w": 2, "d": 4, "q": 8, "o": 16},
    )

    def _name_str(self) -> str:  # type: ignore[no-untyped-def]
        return self.name

    MockReg.__str__ = _name_str  # type: ignore[assignment]
    MockFlag.__str__ = _name_str  # type: ignore[assignment]

    if not isinstance(MockLLIL.__dict__.get("flags"), property):
        _flags_method = MockLLIL.flags

        @property
        def flags(self) -> str | None:  # type: ignore[no-redef]
            return _flags_method(self)

        MockLLIL.flags = flags  # type: ignore[assignment]

    if not hasattr(MockLLIL, "operation"):

        @property
        def operation(self) -> object:  # type: ignore[no-redef]
            return getattr(LowLevelILOperation, f"LLIL_{self.bare_op()}")

        @property
        def operands(self) -> list[object]:  # type: ignore[no-redef]
            return self.ops

        @property
        def size(self) -> int | None:  # type: ignore[no-redef]
            return self.width()

        @property
        def constant(self) -> int:  # type: ignore[no-redef]
            if self.operation in (LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR):
                return int(self.ops[0])
            raise AttributeError("Instruction has no constant")

        MockLLIL.operation = operation  # type: ignore[attr-defined]
        MockLLIL.operands = operands  # type: ignore[attr-defined]
        MockLLIL.size = size  # type: ignore[attr-defined]
        MockLLIL.constant = constant  # type: ignore[attr-defined]

    class LowLevelILFunction(MockLowLevelILFunction):  # noqa: N801
        _default_current_address: int = 0

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            super().__init__()
            self.current_address = self._default_current_address
            self._label_ids: dict[object, int] = {}
            self._next_label_id = 1

        def __iter__(self):
            return iter(self.ils)

        def __getitem__(self, idx: object) -> object:
            if isinstance(idx, int):
                return self.ils[idx]
            return idx

        def _label_id(self, label: object) -> int:
            existing = self._label_ids.get(label)
            if existing is not None:
                return existing
            assigned = self._next_label_id
            self._label_ids[label] = assigned
            self._next_label_id += 2
            return assigned

        def expr(self, *args: object, **kwargs: object) -> object:  # type: ignore[override]
            flags = kwargs.get("flags")
            if flags in (0, "0"):
                kwargs["flags"] = None
            return super().expr(*args, **kwargs)

        def reg(self, size: int, reg_obj: object) -> object:  # type: ignore[override]
            ExpressionIndex = binaryninja.lowlevelil.ExpressionIndex  # type: ignore[attr-defined]
            if isinstance(reg_obj, ExpressionIndex):
                reg_obj = mreg(f"temp{int(reg_obj) - 0x80000000}")
            return super().reg(size, reg_obj)

        def set_reg(self, size: int, reg_obj: object, value: object, flags: object = 0) -> object:  # type: ignore[override]
            ExpressionIndex = binaryninja.lowlevelil.ExpressionIndex  # type: ignore[attr-defined]
            if isinstance(reg_obj, ExpressionIndex):
                reg_obj = mreg(f"temp{int(reg_obj) - 0x80000000}")
            if isinstance(reg_obj, str):
                reg_obj = mreg(reg_obj)
            flags_arg = None if flags in (0, "0") else flags
            return self.expr(LowLevelILOperation.LLIL_SET_REG, reg_obj, value, size=size, flags=flags_arg)

        def goto(self, label, loc=None) -> object:  # type: ignore[override]
            return self.expr(LowLevelILOperation.LLIL_GOTO, self._label_id(label), size=None)

        def if_expr(self, cond, t, f) -> object:  # type: ignore[override]
            return self.expr(
                LowLevelILOperation.LLIL_IF,
                cond,
                self._label_id(t),
                self._label_id(f),
                size=None,
            )

        def flag_condition(self, cond, loc=None) -> object:  # type: ignore[override]
            return self.expr(LowLevelILOperation.LLIL_FLAG_COND, int(cond), None, size=None)

        def mark_label(self, label) -> None:  # type: ignore[override]
            self._label_id(label)
            return None

        def get_label_for_address(self, _arch: object, _addr: int):  # type: ignore[override]
            return None

    llil_mod = sys.modules.get("binaryninja.lowlevelil")
    if llil_mod is not None:
        llil_mod.LowLevelILFunction = LowLevelILFunction  # type: ignore[attr-defined]
        llil_mod.LowLevelILInstruction = MockLLIL  # type: ignore[attr-defined]
        binaryninja.lowlevelil.LowLevelILFunction = LowLevelILFunction  # type: ignore[attr-defined]
        binaryninja.lowlevelil.LowLevelILInstruction = MockLLIL  # type: ignore[attr-defined]


def _patch_missing_binaryninja_submodules() -> None:
    if "binaryninja.plugin" not in sys.modules:
        plugin_mod = types.ModuleType("binaryninja.plugin")

        class PluginCommand:  # noqa: N801
            @staticmethod
            def register_for_address(*_args, **_kwargs) -> None:
                return None

            @staticmethod
            def register(*_args, **_kwargs) -> None:
                return None

        plugin_mod.PluginCommand = PluginCommand
        sys.modules["binaryninja.plugin"] = plugin_mod

    interaction_mod = sys.modules.get("binaryninja.interaction")
    if interaction_mod is not None:
        if not hasattr(interaction_mod, "AddressField"):

            class AddressField:  # noqa: N801
                def __init__(self, *_args, **_kwargs) -> None:
                    return None

            interaction_mod.AddressField = AddressField

        if not hasattr(interaction_mod, "ChoiceField"):

            class ChoiceField:  # noqa: N801
                def __init__(self, *_args, **_kwargs) -> None:
                    return None

            interaction_mod.ChoiceField = ChoiceField

        if not hasattr(interaction_mod, "get_form_input"):

            def get_form_input(*_args, **_kwargs) -> bool:  # noqa: N802
                return False

            interaction_mod.get_form_input = get_form_input


def _install_repo_as_m68k_package() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    pkg = types.ModuleType("m68k")
    pkg.__path__ = [str(repo_root)]
    pkg.__file__ = str(repo_root / "__init__.py")
    sys.modules["m68k"] = pkg


_patch_missing_binaryninja_submodules()
_install_llil_test_helpers()
_install_repo_as_m68k_package()
