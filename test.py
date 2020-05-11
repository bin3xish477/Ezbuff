#!/usr/bin/env python3


from Ezfuzz import ezfuzz
from sys import argv


def main():
	test = ezfuzz.Ezfuzz(argv[1], argv[2])


if __name__ == '__main__':
	main()