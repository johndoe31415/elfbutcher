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

class FlagSetValues():
	def __init__(self, present_flags, additional_value = 0):
		self._present_flags = present_flags
		self._additional_value = additional_value

	@property
	def flags(self):
		return self._present_flags

	@property
	def additional_value(self):
		return self._additional_value

	def abbreviate(self, abbreviation_tuples, not_present = " "):
		result = [ ]
		for (full_name, abbreviated_name) in abbreviation_tuples:
			if full_name in self.flags:
				result.append(abbreviated_name)
			else:
				result.append(not_present)
		return "".join(result)

	def __iter__(self):
		return iter(self._present_flags)

	def __repr__(self):
		text = ", ".join(sorted(self))
		if self.additional_value != 0:
			text += " + 0x%x" % (self.additional_value)
		return text

class FlagSet():
	def __init__(self, mask_dict):
		self._mask_dict = mask_dict
		self._rev_dict = { value: key for (key, value) in self._mask_dict.items() }
		assert(len(self._mask_dict) == len(self._rev_dict))

	def decode(self, int_value):
		present_flags = set()
		for (bit_value, name) in self._mask_dict.items():
			if (int_value & bit_value) == bit_value:
				int_value = int_value & (~bit_value)
				present_flags.add(name)
		return FlagSetValues(present_flags, int_value)

	def encode(self, flagset_values):
		value = flagset_values.additional_value
		for flag in flagset_values:
			value |= self._rev_dict[flag]
		return value

if __name__ == "__main__":
	fs = FlagSet({
		1:	"foo",
		2:	"bar",
		4:	"moo",
		8:	"koo",
	})
	print(fs.decode(123))
	print(fs.encode(FlagSetValues([ "foo", "moo" ])))
