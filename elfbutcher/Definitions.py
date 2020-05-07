#	elfbutcher - Butcher and manipulate ELF binaries
#	Copyright (C) 2020-2020 Johannes Bauer
#
#	This file is part of elfbutcher.
#
#	elfbutcher is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	elfbutcher is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with elfbutcher; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>

import enum

class EIdentClass(enum.IntEnum):
	Bit32 = 1
	Bit64 = 2

class EIdentByteOrder(enum.IntEnum):
	Little = 1
	Big = 2

class EIdentOSABI(enum.IntEnum):
	SystemV = 0
	HPUX = 1
	NetBSD = 2
	Linux = 3
	GNUHurd = 4
	Solaris = 6
	AIX = 7
	IRIX = 8
	FreeBSD = 9
	Tru64 = 0xa
	NovellModesto = 0xb
	OpenBSD = 0xc
	OpenVMS = 0xd
	NonStopKernel = 0xe
	AROS = 0xf
	FenixOS = 0x10
	CloudABI = 0x11
	StratusTechnologiesOpenVOS = 0x12

class EType(enum.IntEnum):
	ET_NONE = 0
	ET_REL = 1
	ET_EXEC = 2
	ET_DYN = 3
	ET_CORE = 4
#	ET_LOOS = 0xfe00
#	ET_HIOS = 0xfeff
#	ET_LOPROC = 0xff00
#	ET_HIPROC = 0xffff

class EMachine(enum.IntEnum):
	Undefined = 0
	SPARC = 2
	X86 = 3
	MIPS = 8
	PowerPC = 0x14
	S390 = 0x16
	ARM = 0x28
	SuperH = 0x2a
	IA64 = 0x32
	AMD64 = 0x3e
	AArch64 = 0xb7
	RISCV = 0xf3

class SegmentType(enum.IntEnum):
	Null = 0
	Load = 1
	Dynamic = 2
	Interp = 3
	Note = 4
	ShLib = 5
	ProgramHeader = 6
	TLS = 7
	GNU_EH_Frame = 0x6474e550
	GNU_Stack = 0x6474e551
	GNU_Relro = 0x6474e552
	GNU_Property = 0x6474e553
#	LOOS = 0x60000000
#	HIOS = 0x6fffffff
#	LOPROC = 0x70000000
#	HIPROC = 0x7fffffff

class SectionType(enum.IntEnum):
	Null = 0
	Progbits = 1
	SymTable = 2
	StrTable = 3
	Rela = 4
	Hash = 5
	Dynamic = 6
	Note = 7
	NoBitsBSS = 8
	Rel = 9
	ShLib = 0xa
	DynSym = 0xb
	Init_Array = 0xe
	Fini_Array = 0xf
	Preinit_Array = 0x10
	Group = 0x11
	Syntax_Shndx = 0x12
	Num = 0x13
	CapChain = 0x6fffffef
	CapInfo = 0x6ffffff0
	SymSort = 0x6ffffff1
	TLSSort = 0x6ffffff2
	LdDynSym = 0x6ffffff3
	DOF = 0x6ffffff4
	Cap = 0x6ffffff5
	Signature = 0x6ffffff6
	Annotate = 0x6ffffff7
	DebugStr = 0x6ffffff8
	Debug = 0x6ffffff9
	Move = 0x6ffffffa
	ComDat = 0x6ffffffb
	SymInfo = 0x6ffffffc
	VerDef = 0x6ffffffd
	Verneered = 0x6ffffffe
	VerSym = 0x6fffffff
