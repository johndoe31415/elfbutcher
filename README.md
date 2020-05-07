# elfbutcher
This is a Python toolkit to perform maximally invasive surgery on ELF binaries.
It is intended to be used to force libraries into compliance for reverse
engineering purposes and modify executables with binary appendices without
access to any source code (i.e., re-link an already linked binary with
additional payload).

The current status of this software package is entirely broken. The only thing
it can do is transform ELF binaries into new ELF binaries that segfault
immediately.

## License
GNU GPL-3.
