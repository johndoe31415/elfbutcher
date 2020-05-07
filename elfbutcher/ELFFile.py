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

import struct
import collections
from .NamedStruct import NamedStruct
from .Definitions import EIdentClass, EIdentByteOrder, EIdentOSABI, EType, EMachine, SegmentType, SectionType
from .FlagSet import FlagSet

class Segment():
	_FILE_ALIGN_OFFSET = 8

	def __init__(self, segment_header, content):
		self._segment_header = segment_header
		self._content = content

	@property
	def segment_header(self):
		return self._segment_header

	@property
	def content(self):
		return self._content

	@property
	def aligned_size(self):
		return (len(self) + self._FILE_ALIGN_OFFSET - 1) // self._FILE_ALIGN_OFFSET * self._FILE_ALIGN_OFFSET

	@property
	def padding_size(self):
		return self.aligned_size - len(self)

	@property
	def aligned_str(self):
		parts = [ ]
		parts.append("%-13s" % (self.segment_header.segment_type.name))
		parts.append(self._segment_header.flags.abbreviate((
			("Read", "R"),
			("Write", "W"),
			("Execute", "X"),
		)))
		parts.append("%-#10x" % (self.segment_header.vaddr))
		if self.segment_header.paddr != self.segment_header.vaddr:
			parts.append("phys %-#10x" % (self.segment_header.paddr))
		parts.append("length %-#8x" % (self.segment_header.memsize))
		parts.append("file offset %-#6x" % (self.segment_header.offset))
		if self.segment_header.filesize != self.segment_header.memsize:
			parts.append("file size %-#6x" % (self.segment_header.filesize))
		if self.segment_header.align > 1:
			parts.append("align %-#6x" % (self.segment_header.align))
		return "   ".join(parts)

	def __len__(self):
		return len(self.content)

	def __repr__(self):
		return "Segment<%s, %d bytes>" % (str(self.segment_header), len(self.content))

class Segments():
	def __init__(self, segment_header_class):
		self._segment_header_class = segment_header_class
		self._segments = [ ]

	def append(self, segment):
		assert(isinstance(segment, Segment))
		self._segments.append(segment)

	def serialize_table(self, segment_table_offset):
		result = bytearray()
		segment_data_offset = segment_table_offset + (len(self) * self._segment_header_class.size)
		for segment in self:
			header = segment.segment_header._asdict()
			header["offset"] = segment_data_offset
			result += self._segment_header_class.pack(header)
			segment_data_offset += segment.aligned_size
		return result

	def serialize_data(self):
		result = bytearray()
		for segment in self:
			result += segment.content
			result += bytes(segment.padding_size)
		return result

	def serialize(self, segment_table_offset):
		return bytes(self.serialize_table(segment_table_offset) + self.serialize_data())

	def __iter__(self):
		return iter(self._segments)

	def __len__(self):
		return len(self._segments)

class ELFFile():
	_ArchIndependentFileHeader = NamedStruct(fields = (
		("4s",	"magic"),
		("B",	"ident_class"),
		("B",	"ident_byteorder"),
		("B",	"ident_version"),
		("B",	"ident_osabi"),
		("B",	"ident_abiversion"),
		("7s",	"padding"),
	), unpacking_handlers = {
		"ident_class":		EIdentClass,
		"ident_byteorder":	EIdentByteOrder,
		"ident_osabi":		EIdentOSABI,
	})

	_SegmentFlags = FlagSet({
		0x1:	"Execute",
		0x2:	"Write",
		0x4:	"Read",
	})

	_SectionFlags = FlagSet({
		0x1:	"Write",
		0x2:	"Alloc",
		0x4:	"ExecInstr",
		0x10:	"Merge",
		0x20:	"Strings",
		0x40:	"InfoLink",
		0x80:	"LinkOrder",
		0x100:	"OS_NonConforming",
		0x200:	"Group",
		0x400:	"TLS",
	})

	def __init__(self, arch_independent_header, arch_dependent_header, segments, sections):
		self._arch_independent_header = arch_independent_header
		self._arch_dependent_header = arch_dependent_header
		self._segments = segments
		self._sections = sections

	@property
	def segments(self):
		return self._segments

	@property
	def sections(self):
		return self._sections

	def dump(self, f = None):
		print("ELF class %s, byteorder %s, version %d, OS ABI %s v%d." % (self._arch_independent_header.ident_class.name, self._arch_independent_header.ident_byteorder.name, self._arch_independent_header.ident_version, self._arch_independent_header.ident_osabi.name, self._arch_independent_header.ident_abiversion), file = f)
		print("Machine %s, %d segments, %d sections." % (self._arch_dependent_header.machine.name, len(self.segments), len(self.sections)), file = f)
		print(file = f)
		if len(self.segments) > 0:
			print("Segments:", file = f)
			for (segment_id, segment) in enumerate(self.segments):
				print("%2d: %s" % (segment_id, segment.aligned_str))
			print()
		if len(self.sections) > 0:
			print("Sections:", file = f)
			for (section_id, section) in enumerate(self.sections):
				print("%2d: %s" % (section_id, section))
			print()

	@classmethod
	def create_arch_dependent_header_class(cls, little_endian = True, bits_32 = True):
		word = "L" if bits_32 else "Q"
		handler_class = NamedStruct(fields = (
			("H",	"obj_type"),
			("H",	"machine"),
			("L",	"version"),
			(word,	"entry"),
			(word,	"phoff"),
			(word,	"shoff"),
			("L",	"flags"),
			("H",	"ehsize"),
			("H",	"phentsize"),
			("H",	"phnum"),
			("H",	"shentsize"),
			("H",	"shnum"),
			("H",	"shstrndx"),
		), struct_extra = "<" if little_endian else ">", unpacking_handlers = {
			"obj_type":			EType,
			"machine":			EMachine,
		})
		return handler_class

	@classmethod
	def create_segment_header_class(cls, little_endian = True, bits_32 = True):
		word = "L" if bits_32 else "Q"
		unpacking_handlers = {
			"segment_type":		SegmentType,
			"flags":			lambda value: cls._SegmentFlags.decode(value),
		}
		packing_handlers = {
			"flags":			lambda value: cls._SegmentFlags.encode(value),
		}
		if bits_32:
			handler_class = NamedStruct(fields = (
				("L",	"segment_type"),
				(word,	"offset"),
				(word,	"vaddr"),
				(word,	"paddr"),
				(word,	"filesize"),
				(word,	"memsize"),
				("L",	"flags"),
				(word,	"align"),
			), struct_extra = "<" if little_endian else ">", unpacking_handlers = unpacking_handlers, packing_handlers = packing_handlers)
		else:
			handler_class = NamedStruct(fields = (
				("L",	"segment_type"),
				("L",	"flags"),
				(word,	"offset"),
				(word,	"vaddr"),
				(word,	"paddr"),
				(word,	"filesize"),
				(word,	"memsize"),
				(word,	"align"),
			), struct_extra = "<" if little_endian else ">", unpacking_handlers = unpacking_handlers, packing_handlers = packing_handlers)
		return handler_class

	@classmethod
	def create_section_header_class(cls, little_endian = True, bits_32 = True):
		word = "L" if bits_32 else "Q"
		unpacking_handlers = {
			"section_type":		SectionType,
			"flags":			lambda value: cls._SectionFlags.decode(value),
		}
		packing_handlers = {
			"flags":			lambda value: cls._SectionFlags.encode(value),
		}
		handler_class = NamedStruct(fields = (
			("L",	"name_offset"),
			("L",	"section_type"),
			(word,	"flags"),
			(word,	"addr"),
			(word,	"offset"),
			(word,	"size"),
			("L",	"link"),
			("L",	"info"),
			(word,	"addr_align"),
			(word,	"entry_size"),
		), struct_extra = "<" if little_endian else ">", unpacking_handlers = unpacking_handlers, packing_handlers = packing_handlers)
		return handler_class

	@classmethod
	def read_elf(cls, filename):
		with open(filename, "rb") as f:
			arch_independent_header = cls._ArchIndependentFileHeader.unpack_from_file(f)
			arch_info = {
				"little_endian":	arch_independent_header.ident_byteorder == EIdentByteOrder.Little,
				"bits_32":			arch_independent_header.ident_class == EIdentClass.Bit32,
			}
			arch_dependent_header_class = cls.create_arch_dependent_header_class(**arch_info)
			arch_dependent_header = arch_dependent_header_class.unpack_from_file(f)

#			print(arch_independent_header)
#			print(arch_dependent_header)

			segment_header_class = cls.create_segment_header_class(**arch_info)
			segments = Segments(segment_header_class)
			for i in range(arch_dependent_header.phnum):
				offset = arch_dependent_header.phoff + (i * arch_dependent_header.phentsize)
				f.seek(offset)
				segment_header = segment_header_class.unpack_from_file(f)

				f.seek(segment_header.offset)
				content = f.read(segment_header.filesize)
				assert(len(content) == segment_header.filesize)
#				print(segment_header)
				segment = Segment(segment_header, content)
				segments.append(segment)

			sections = [ ]
			section_header_class = cls.create_section_header_class(**arch_info)
			for i in range(arch_dependent_header.shnum):
				offset = arch_dependent_header.shoff + (i * arch_dependent_header.shentsize)
				f.seek(offset)

				section_header = section_header_class.unpack_from_file(f)
#				print(section_header)
				sections.append(section_header)

		return cls(arch_independent_header = arch_independent_header, arch_dependent_header = arch_dependent_header, segments = segments, sections = sections)

	@property
	def arch_info(self):
		return {
			"little_endian":	self._arch_independent_header.ident_byteorder == EIdentByteOrder.Little,
			"bits_32":			self._arch_independent_header.ident_class == EIdentClass.Bit32,
		}

	def write_elf(self, filename):
		with open(filename, "wb") as f:
			f.write(self._ArchIndependentFileHeader.pack(self._arch_independent_header))

			arch_dependent_header_class = self.create_arch_dependent_header_class(**self.arch_info)
			segment_header_class = self.create_segment_header_class(**self.arch_info)
			print(self._arch_dependent_header)



			arch_dependent_header = self._arch_dependent_header._asdict()
			arch_dependent_header["phoff"] = self._ArchIndependentFileHeader.size +  arch_dependent_header_class.size
			arch_dependent_header["phentsize"] = segment_header_class.size
			arch_dependent_header["phnum"] = len(self.segments)
			arch_dependent_header["shoff"] = 0
			arch_dependent_header["shnum"] = 0
			arch_dependent_header["shentsize"] = 0
			arch_dependent_header["shstrndx"] = 0
			f.write(arch_dependent_header_class.pack(arch_dependent_header))

			f.write(self.segments.serialize(arch_dependent_header["phoff"]))
#		self._arch_independent_header = arch_independent_header
#		self._arch_dependent_header = arch_dependent_header
#		self._segments = segments
#		self._sections = sections

	def dump_segment_contents(self, directory_name):
		for (segment_no, segment) in enumerate(self.segments):
			filename = "%s/segment_%03d.bin" % (directory_name, segment_no)
			with open(filename, "wb") as f:
				f.write(segment.content)
