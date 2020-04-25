#!/usr/bin/env python3

try:
  import subprocess as sp
except ImportError as err:
  print(f"Import Error: {err}")
  
# ----------------Ansicolors
res = "\033[0m"
r = "\033[91m"
g = "\033[92m"
b = "\033[94m"

# ----------------Ezfuzz
class Ezfuzz:
  def __init__(self, targ_ip, targ_port):
    self._targ_ip = None
    self._targ_port = None
    self._bad_chars = []
    
  def fuzz(self, targ):
    pass
    
