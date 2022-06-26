import sys
import os
import binaryninja

__module__ = sys.modules[__name__]
__logger = binaryninja.Logger(0, __module__.__name__)

log = __logger.log
log_debug = __logger.log_debug
log_info = __logger.log_info
log_warn = __logger.log_warn
log_error = __logger.log_error
log_alert = __logger.log_alert

log_debug(f'm68k Plugin loaded from: {os.path.dirname(__module__.__loader__.path)}')

from .m68k import *
from .test import test_all

#PluginCommand.register("Create M68k vector table", "Create M68k vector table", prompt_create_vector_table)
PluginCommand.register_for_address("Create M68k vector table", "Create M68k vector table", prompt_create_vector_table)

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

BinaryViewType['ELF'].register_arch(4, Endianness.BigEndian, Architecture['M68030'])

test_all()
