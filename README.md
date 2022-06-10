# Motorola 68k Architecture Plugin (v0.2)
Original Author: [**Alex Forencich**](http://www.github.com/alexforencich)
Previous Maintainer: [**Jason Wright**](http://www.github.com/wrigjl)

_A Binary Ninja disassembler and lifter for the Motorola 68k architecture._

## Moved

Development of this plugin has moved to
[galenbwill/binaryninja-m68k](https://github.com/galenbwill/binaryninja-m68k/)

**Note:** This project is currently being maintained by [@galenbwill](https://github.com/galenbwill) as a community plugin, not as an official Vector 35 plugin.

## Description:

This plugin disassembles Motorola 68k machine code and generates LLIL.

To install this plugin, navigate to your Binary Ninja plugins directory, and run

```git clone https://github.com/galenbwill/binaryninja-m68k.git m68k```

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 * release (Personal) - 3.0

## License

This plugin is released under a [MIT](LICENSE) license.

## Modifications by [Galen Williamson](https://www.github.com/galenbwill)

* fixed and updated for Binary Ninja API 3.0
* added type hints
* fixed vector table creation to no longer create an entry point at offset 0 for zero-valued vectors

## Modifications by [Jason Wright](http://www.github.com/wrigjl)

 * register with ELF loader
 * fixups for binja il changes
 * fixed 'rtd' instruction to parse correctly
 * labels for 'jmp' and 'bra'
 * fixed 'roxr'/'roxl' instructions to add correct flag
 * fixed signedness of branches
 * added bhi, bls, bcc, bcs support
 * mark indirect jump/call as unresolved so il can figure it out
