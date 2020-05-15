#!/usr/bin/env python3


from Ezbuff.ezbuff import Ezbuff
from sys import argv


def main():
	test = Ezbuff("192.168.13.234", 80)

	print(repr(test))
	print(str(test))

	test.jump_eip = r"\x8f\x35\x4a\x5f"
	test.add_bad_char(r"\xaa")

	print(test.bad_chars, test.jump_eip)

	print(repr(test))


if __name__ == '__main__':
	main()