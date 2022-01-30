from .m68k import *

#PluginCommand.register("Create M68k vector table", "Create M68k vector table", prompt_create_vector_table)
PluginCommand.register_for_address("Create M68k vector table", "Create M68k vector table", prompt_create_vector_table)

M68000.register()
# M68008.register()
# M68010.register()
# M68020.register()
# M68030.register()
# M68040.register()
# M68LC040.register()
# M68EC040.register()
# M68330.register()
# M68340.register()

# BinaryViewType['ELF'].register_arch(4, Endianness.BigEndian, Architecture['M68030'])
