from __future__ import annotations

import importlib.util
import os
import sys
import types
from pathlib import Path

def _running_under_pytest() -> bool:
    return any(name == "pytest" or name.startswith("_pytest") for name in sys.modules)

def _running_inside_binary_ninja() -> bool:
    try:
        return importlib.util.find_spec("binaryninjaui") is not None
    except (ValueError, ImportError):
        return False

if _running_under_pytest() and not _running_inside_binary_ninja():
    os.environ.setdefault("FORCE_BINJA_MOCK", "1")

    # Installs a stubbed `binaryninja` module into `sys.modules`.
    from binja_test_mocks import binja_api  # noqa: F401  # pyright: ignore
    from binja_test_mocks import mock_llil

    mock_llil.set_size_lookup(
        {1: ".b", 2: ".w", 4: ".d", 8: ".q", 16: ".o"},
        {"b": 1, "w": 2, "d": 4, "q": 8, "o": 16},
    )

    def _install_repo_as_m68k_package() -> None:
        repo_root = Path(__file__).resolve().parents[1]
        pkg = types.ModuleType("m68k")
        pkg.__path__ = [str(repo_root)]
        pkg.__file__ = str(repo_root / "__init__.py")
        sys.modules["m68k"] = pkg

    _install_repo_as_m68k_package()
