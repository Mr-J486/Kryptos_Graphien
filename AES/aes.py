# aes.py
from .aes_core import aes_encrypt_block, aes_decrypt_block

def xor_bytes(a,b):
    return bytes(x^y for x,y in zip(a,b))

def pad(m):
    p = 16 - (len(m)%16)
    return m + bytes([p]*p)

def unpad(m):
    return m[:-m[-1]]

def aes_cbc_encrypt(msg, key, iv):
    msg = pad(msg)
    out, prev = b"", iv
    for i in range(0,len(msg),16):
        blk = xor_bytes(msg[i:i+16], prev)
        enc = aes_encrypt_block(blk, key)
        out += enc
        prev = enc
    return out

def aes_cbc_decrypt(ct, key, iv):
    out, prev = b"", iv
    for i in range(0,len(ct),16):
        dec = aes_decrypt_block(ct[i:i+16], key)
        out += xor_bytes(dec, prev)
        prev = ct[i:i+16]
    return unpad(out)
