#!/usr/bin/env python3


from Ezbuff.ezbuff import Ezbuff
from sys import argv


def main():
	test = Ezbuff("192.168.230.10", 80)

	test.num_bytes_crash = 1200

	test.offset = 800

	# test.fuzz_interval_seconds = 2

	test.add_bad_char('\x00', '\x01', '\x02')

	test.fuzz()

	# print(repr(test))


if __name__ == '__main__':
	main()