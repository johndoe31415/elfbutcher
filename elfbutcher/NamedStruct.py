#!/usr/bin/python3
#
#	NamedStruct - Python structure that has named member entries
#	Copyright (C) 2017-2020 Johannes Bauer
#
#	This file is part of pycommon.
#
#	pycommon is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	pycommon is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with pycommon; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#
#	File UUID 34de558f-8b40-4899-a9d9-66e46d7d07a4

import collections
import struct

class NamedStruct():
	def __init__(self, fields, struct_extra = "<", unpacking_handlers = None, packing_handlers = None):
		struct_format = struct_extra + ("".join(fieldtype for (fieldtype, fieldname) in fields))
		self._struct = struct.Struct(struct_format)
		self._collection = collections.namedtuple("Fields", [ fieldname for (fieldtype, fieldname) in fields ])
		self._unpacking_handlers = unpacking_handlers
		self._packing_handlers = packing_handlers

	@property
	def size(self):
		return self._struct.size

	def pack(self, data):
		if isinstance(data, dict):
			fields = self._collection(**data)
		else:
			fields = data
		if self._packing_handlers is not None:
			fields = [ self._packing_handlers[name](value) if (name in self._packing_handlers) else value for (name, value) in zip(self._collection._fields, fields) ]
		return self._struct.pack(*fields)

	def unpack(self, data):
		values = self._struct.unpack(data)
		if self._unpacking_handlers is not None:
			def _convert(handler, value):
				try:
					return handler(value)
				except ValueError:
					return value
			values = [ _convert(self._unpacking_handlers[name], value) if (name in self._unpacking_handlers) else value for (name, value) in zip(self._collection._fields, values) ]
		fields = self._collection(*values)
		return fields

	def unpack_head(self, data):
		return self.unpack(data[:self._struct.size])

	def unpack_from_file(self, f, at_offset = None):
		if at_offset is not None:
			f.seek(at_offset)
		data = f.read(self._struct.size)
		return self.unpack(data)
