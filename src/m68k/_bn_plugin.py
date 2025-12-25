from __future__ import annotations

import os
from pathlib import Path


def register(*, plugin_dir: Path) -> None:
    debug = os.environ.get("M68K_DEBUG", "").lower() in ("1", "true", "yes")

    def _debug(msg: str) -> None:
        if debug:
            print(f"m68k[debug] {msg}")

    _debug("Starting plugin registration")

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
    _debug("Registering PluginCommand: Create M68k vector table")

    PluginCommand.register_for_address(
        "Create M68k vector table",
        "Create M68k vector table",
        prompt_create_vector_table,
    )

    _debug("Registering architectures: M68000/M68008/M68010/M68020/M68030/M68040/M68LC040/M68EC040/M68330/M68340")
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

    _debug("Registering ELF arch mapping: (4, BigEndian) -> M68030")
    BinaryViewType["ELF"].register_arch(4, Endianness.BigEndian, Architecture["M68030"])

    class ParametersInRegistersCallingConvention(CallingConvention):
        name = "ParametersInRegisters"

    _debug("Registering calling convention: ParametersInRegisters (M68000 default)")
    arch = Architecture["M68000"]
    arch.register_calling_convention(ParametersInRegistersCallingConvention(arch, "default"))

    _debug("Finished plugin registration")
