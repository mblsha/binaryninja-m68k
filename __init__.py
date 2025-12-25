from __future__ import annotations

import os


def _should_register_plugin() -> bool:
    # When this repo is checked out into a directory with a non-importable name
    # (e.g. `binaryninja-m68k` on GitHub Actions), pytest may import this file as
    # a standalone module named `__init__`. Avoid side effects and relative
    # imports in that context.
    return bool(__package__)


if _should_register_plugin():
    import binaryninja

    from .logging import __module__, log_debug

    log_debug(f"m68k Plugin loaded from: {os.path.dirname(__module__.__loader__.path)}")

    from .m68k import *  # noqa: F403
    from .test import test_all
    from binaryninja import Architecture, CallingConvention

    # PluginCommand.register("Create M68k vector table", "Create M68k vector table", prompt_create_vector_table)
    PluginCommand.register_for_address(  # type: ignore[name-defined]
        "Create M68k vector table",
        "Create M68k vector table",
        prompt_create_vector_table,  # type: ignore[name-defined]
    )

    M68000.register()
    M68008.register()
    M68010.register()
    M68020.register()
    M68030.register()
    M68040.register()
    M68LC040.register()
    M68EC040.register()
    M68330.register()
    M68340.register()

    # BinaryViewType['ELF'].register_arch(4, Endianness.BigEndian, Architecture['M68030'])
    BinaryViewType["ELF"].register_arch(4, Endianness.BigEndian, Architecture["M68030"])  # type: ignore[name-defined]

    class ParametersInRegistersCallingConvention(CallingConvention):
        name = "ParametersInRegisters"

    arch = Architecture["M68000"]
    arch.register_calling_convention(ParametersInRegistersCallingConvention(arch, "default"))

    BinaryViewType["ELF"].register_arch(4, Endianness.BigEndian, Architecture["M68030"])  # type: ignore[name-defined]

    test_all()
