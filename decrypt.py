#!/usr/bin/env python
import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, Blowfish
import re
import sys

def decrypt(Ciphertext):        
    cipher = AES.new(SHA256.new('').digest(), AES.MODE_CBC, b'\x00' * AES.block_size)
    padded_plain_bytes = cipher.decrypt(bytes.fromhex(Ciphertext))
    plain_bytes_length = int.from_bytes(padded_plain_bytes[0:4], 'little')
    plain_bytes = padded_plain_bytes[4:4 + plain_bytes_length]
    if len(plain_bytes) != plain_bytes_length:
        raise ValueError('Invalid Ciphertext.')

    plain_bytes_digest = padded_plain_bytes[4 + plain_bytes_length:4 + plain_bytes_length + SHA256.digest_size]
    if len(plain_bytes_digest) != SHA256.digest_size:
        raise ValueError('Invalid Ciphertext.')

    if SHA256.new(plain_bytes).digest() != plain_bytes_digest:
        raise ValueError('Invalid Ciphertext.')
    return plain_bytes.decode('utf-8')

if len(sys.argv) != 2:
    print('error params.')
    sys.exit()

with open(sys.argv[1]) as f:
    data = f.read()
try:
    hostname = re.compile(r'S:"Hostname"=([^\r\n]*)').search(data).group(1)
    port  = int(re.compile(r'D:"\[SSH2\] Port"=([0-9a-f]{8})').search(data).group(1),16)
    username = re.compile(r'S:"Username"=([^\r\n]*)').search(data).group(1)
    passwd = decrypt(re.compile(r'"Password.*?"=(.+)').search(data).group(1)[3:])
    
except:
    raise
print('\nDecrypt Result:\n\nhostname:%s\nport:%s\nusername:%s\npassword:%s\n'%(hostname,port,username,passwd))
