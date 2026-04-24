import math


def _left_rotate(x, c):
    return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF


def generate_md5(data):
    if isinstance(data, str):
        data = data.encode("utf-8")

    s = (
        [7, 12, 17, 22] * 4 +
        [5, 9, 14, 20] * 4 +
        [4, 11, 16, 23] * 4 +
        [6, 10, 15, 21] * 4
    )

    k = [int(abs(math.sin(i + 1)) * (2 ** 32)) & 0xFFFFFFFF for i in range(64)]

    a0 = 0x67452301
    b0 = 0xEFCDAB89
    c0 = 0x98BADCFE
    d0 = 0x10325476

    original_bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    data += b"\x80"

    while len(data) % 64 != 56:
        data += b"\x00"

    data += original_bit_len.to_bytes(8, byteorder="little")

    for offset in range(0, len(data), 64):
        chunk = data[offset:offset + 64]
        M = [int.from_bytes(chunk[i:i + 4], byteorder="little") for i in range(0, 64, 4)]

        A, B, C, D = a0, b0, c0, d0

        for i in range(64):
            if i < 16:
                F = (B & C) | ((~B) & D)
                g = i
            elif i < 32:
                F = (D & B) | ((~D) & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | (~D))
                g = (7 * i) % 16

            F &= 0xFFFFFFFF
            temp = D
            D = C
            C = B
            B = (B + _left_rotate((A + F + k[i] + M[g]) & 0xFFFFFFFF, s[i])) & 0xFFFFFFFF
            A = temp

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    digest = (
        a0.to_bytes(4, byteorder="little") +
        b0.to_bytes(4, byteorder="little") +
        c0.to_bytes(4, byteorder="little") +
        d0.to_bytes(4, byteorder="little")
    )

    return digest.hex()


def hmac_md5(key, message):
    
    if isinstance(key, str):
        key = key.encode("utf-8")
    if isinstance(message, str):
        message = message.encode("utf-8")

    block_size = 64  

    if len(key) > block_size:
        key = bytes.fromhex(generate_md5(key))
    
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))

    o_key_pad = bytes([b ^ 0x5C for b in key])
    i_key_pad = bytes([b ^ 0x36 for b in key])

    # HMAC = MD5(o_key_pad || MD5(i_key_pad || message))
    inner_hash = bytes.fromhex(generate_md5(i_key_pad + message))
    return generate_md5(o_key_pad + inner_hash)