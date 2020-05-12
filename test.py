#!/usr/bin/env python3


from Ezfuzz import ezfuzz
from sys import argv


def main():
	test = ezfuzz.Ezfuzz("192.168.13.234", 80)
	print(repr(test))


if __name__ == '__main__':
	main()