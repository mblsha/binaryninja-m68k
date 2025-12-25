from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


# Ensure the plugin directory is available on `sys.path` so that absolute
# imports work when the plugin is loaded directly by Binary Ninja.
_plugin_dir = Path(__file__).resolve().parent
_plugin_dir_str = str(_plugin_dir)
if _plugin_dir_str not in sys.path:
    sys.path.insert(0, _plugin_dir_str)

# This repository uses a `src/` layout for the implementation package. When the
# plugin is loaded directly by Binary Ninja, extend the package search path so
# `from .m68k import ...` resolves to `src/m68k/...`.
_src_pkg_dir = _plugin_dir / "src" / "m68k"
if _src_pkg_dir.is_dir():
    _src_pkg_dir_str = str(_src_pkg_dir)
    if _src_pkg_dir_str not in __path__:
        __path__.append(_src_pkg_dir_str)

def module_exists(module_name: str) -> bool:
    if module_name in sys.modules:
        return True
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ValueError, ImportError):
        return False

if module_exists("binaryninja") and __package__:
    from ._bn_plugin import register

    register(plugin_dir=_plugin_dir)
