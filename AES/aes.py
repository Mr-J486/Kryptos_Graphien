
from AES.aes_core import aes_encrypt_block, aes_decrypt_block

def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

def pad(m):
    p = 16 - (len(m) % 16)
    return m + bytes([p] * p)

def unpad(m):
    return m[:-m[-1]]

def aes_cbc_encrypt(msg, key, iv):
    msg = pad(msg)
    out = b""
    prev = iv

    for i in range(0, len(msg), 16):
        block = xor_bytes(msg[i:i+16], prev)
        enc = aes_encrypt_block(block, key)
        out += enc
        prev = enc

    return out

def aes_cbc_decrypt(ct, key, iv):
    out = b""
    prev = iv

    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        dec = aes_decrypt_block(block, key)
        out += xor_bytes(dec, prev)
        prev = block

    return unpad(out)
