from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


# Ensure the plugin directory is available on `sys.path` so that absolute
# imports work when the plugin is loaded directly by Binary Ninja.
_plugin_dir = Path(__file__).resolve().parent
_plugin_dir_str = str(_plugin_dir)
if _plugin_dir_str not in sys.path:
    sys.path.insert(0, _plugin_dir_str)

# Some tooling can import this file as a plain module (not a package). Make the
# module behave like a package so `m68k.*` submodules remain importable.
_package_paths = globals().get("__path__")
if _package_paths is None:
    __path__ = [_plugin_dir_str]  # type: ignore[var-annotated]
    _package_paths = __path__

# This repository uses a `src/` layout for the implementation package. When the
# plugin is loaded directly by Binary Ninja, extend the package search path so
# `from .m68k import ...` resolves to `src/m68k/...`.
_src_pkg_dir = _plugin_dir / "src" / "m68k"
if _src_pkg_dir.is_dir():
    _src_pkg_dir_str = str(_src_pkg_dir)
    if _src_pkg_dir_str not in _package_paths:
        _package_paths.append(_src_pkg_dir_str)

def module_exists(module_name: str) -> bool:
    if module_name in sys.modules:
        return True
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ValueError, ImportError):
        return False

_force_mock = os.environ.get("FORCE_BINJA_MOCK", "").lower() in ("1", "true", "yes")

if module_exists("binaryninja") and __package__ and not _force_mock:
    from ._bn_plugin import register

    register(plugin_dir=_plugin_dir)
