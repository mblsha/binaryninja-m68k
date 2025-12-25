from __future__ import annotations

import importlib.util
import os
import sys
import traceback
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

def _running_inside_binary_ninja() -> bool:
    try:
        if module_exists("binaryninjaui"):
            return True
    except Exception:
        pass

    exe = (sys.executable or "").lower()
    if "binary ninja.app" in exe:
        return True
    return os.path.basename(exe) in ("binaryninja", "binaryninja.exe")


_force_mock_requested = os.environ.get("FORCE_BINJA_MOCK", "").lower() in ("1", "true", "yes")
_running_binja = _running_inside_binary_ninja()
_skip_registration = _force_mock_requested and not _running_binja

print(
    "m68k[debug] shim loaded "
    f"(name={__name__!r}, package={__package__!r}, plugin_dir={_plugin_dir}, "
    f"force_mock={_force_mock_requested}, running_binja={_running_binja})"
)
print(f"m68k[debug] implementation_dir={_src_pkg_dir} exists={_src_pkg_dir.is_dir()}")

_has_binaryninja = module_exists("binaryninja")
print(f"m68k[debug] binaryninja_available={_has_binaryninja} will_register={bool(_has_binaryninja and __package__ and not _skip_registration)}")

if _has_binaryninja and __package__ and not _skip_registration:
    from ._bn_plugin import register

    print("m68k[debug] calling _bn_plugin.register()")
    try:
        register(plugin_dir=_plugin_dir)
    except Exception:
        print("m68k[debug] _bn_plugin.register() raised:")
        traceback.print_exc()
        raise
    print("m68k[debug] _bn_plugin.register() completed")
else:
    if not __package__:
        print("m68k[debug] skipping registration (not imported as a package)")
    elif _skip_registration:
        print("m68k[debug] skipping registration (FORCE_BINJA_MOCK set and not running inside Binary Ninja)")
    elif not _has_binaryninja:
        print("m68k[debug] skipping registration (binaryninja module not available)")
