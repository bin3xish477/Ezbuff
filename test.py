#!/usr/bin/env python3


from Ezbuff import ezbuff
from sys import argv


def main():
	test = ezbuff.Ezbuff("192.168.13.234", 80)

	print(repr(test))
	print(str(test))

	test.jump_eip = r"\x8f\x35\x4a\x5f"
	test.add_bad_char(r"\xaa")

	print("Bad characters collected:", test.bad_chars, "Current jump eip memory address:", test.jump_eip)

	print(repr(test))


if __name__ == '__main__':
	main()