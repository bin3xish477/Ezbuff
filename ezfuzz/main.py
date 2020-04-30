try:
	import subprocess as sp
	import socket as s
	import exceptions
	import logging
except ImportError as err:
	print(f"Import Error: {err}")
 
#--------------------Logging Configurations
logger = logging.getLogger(__name__)
FORMAT = "%(levelname)s:%(asctime)s - %(funcName)s - %(process)d - %(message)s"
logging.basicConfig(filename='ezfuzz.log',
					level=DEBUG,
					format=FORMAT)

#-------------------Ansicolors
rst = "\033[0m"
bld = "\033[01m"
r = "\033[91m"
g = "\033[92m"
b = "\033[94m"

#-------------------Characters
chars = ("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

#-------------------Ezfuzz
class Ezfuzz:
	"""
	"""
	def __init__(self):
		self._targ_IP = None
		self._targ_port = None
		self._bad_chars_found = []
		self._nop_sled = "\x90"*16
		self._offset = None
		self._num_bytes_crash = None
		self._receive_bytes = 1024

	@property
	def bad_chars(self):
		"""The bad characters found by user."""
		return self._bad_chars_found
	
	@property
	def num_bytes_crash(self)
		""""""
		return self._num_bytes_crash
	
	@num_bytes_crash.setter
	def num_bytes_crash(self, new_bytes_value):
		self._num_bytes_crash = new_bytes_value
		
	@property
	def offset(self):
		""""""
		return self._offset

	@offset.setter
	def offset(self, arg):
		""""""
		self._offset = arg

	def fuzz(self, targ_IP, targ_port):
		"""Sends an incrementing number of bytes to an application
		until it crashes or returns an error and then prints out the
		number of bytes at the moment of the crash/error.

		Params
		------
		targ_IP (str): The target's IP address.
		targ_port (int): The target's port number.
		"""
		try:
			if not isinstance(targ_IP, str):
				raise InvalidTargetIPError(r + "The target IP address must be a string." + rst)
			if not isinstance(targ_port, int):
				raise InvalidTargetPortError(r + "The target port number must be an integer between 1-65535" + rst)
		except TypeError as err:
			logging.error(err)

		self._targ_IP = targ_IP
		self._targ_port = targ_port
			
		self._num_bytes_crash = 50
		while True:
			with s.socket(s.AF_INET, s.SOCK_STREAM) as soc:
				try:
					soc.connect((self._targ_IP, self._targ_port))
					self._buffer = 'A'*self._num_bytes_crash
					while True:
						soc.recv(self._receive_bytes)
						soc.send("Test\r\n")
						soc.recv(self._receive_bytes)
						soc.send(self._buffer)
						soc.close()
				except:
					print(f"Number of bytes sent at crash: {self._num_bytes_crash}")
					self._num_bytes_crash -= 50
				finally:
					self._num_bytes_crash += 50
	
	def send_msf_pattern(self):
		""""""
		pass
	
	def _generate_msf_pattern(self):
		""""""
		output = sp.run(['/usr/share/metasploit-framework/tools/pattern_create.rb', self._num_bytes_crash])
		
	def test_offset(self):
		""""""
		with s.socket(s.AF_INET, s.SOCK_STREAM) as soc:
			payload = 
		
	def send_bad_chars(self):
		""""""
		pass
		
	def _store_bad_chars(self):
		""""""
		pass
		
