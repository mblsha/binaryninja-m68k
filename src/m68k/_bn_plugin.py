from __future__ import annotations

from pathlib import Path


def register(*, plugin_dir: Path) -> None:
    from binaryninja import Architecture, BinaryViewType, CallingConvention, PluginCommand
    from binaryninja.enums import Endianness

    from .m68k import (
        M68000,
        M68008,
        M68010,
        M68020,
        M68030,
        M68040,
        M68EC040,
        M68LC040,
        M68330,
        M68340,
        prompt_create_vector_table,
    )

    print(f"m68k Plugin loaded from: {plugin_dir}")

    PluginCommand.register_for_address(
        "Create M68k vector table",
        "Create M68k vector table",
        prompt_create_vector_table,
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

    BinaryViewType["ELF"].register_arch(4, Endianness.BigEndian, Architecture["M68030"])

    class ParametersInRegistersCallingConvention(CallingConvention):
        name = "ParametersInRegisters"

    arch = Architecture["M68000"]
    arch.register_calling_convention(ParametersInRegistersCallingConvention(arch, "default"))
