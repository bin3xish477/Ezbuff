""" Custom error classes created for Ezfuzz """
class InvalidTargetIPError(TypeError):
	""" Will be raised if the type of the target IP
	is not of type 'str'.
	"""
	def __init__(self, error_msg):
		super.__init__(error_msg)

class InvalidTargetPortError(TypeError):
	""" Will be raised if the type of the target IP
	is not of type 'int'.
	"""
	def __init__(self, error_msg):
		super.__init__(error_msg)