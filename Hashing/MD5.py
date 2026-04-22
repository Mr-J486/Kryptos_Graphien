import math

A = 0x67452301
B = 0xefcdab89
C = 0x98badcfe
D = 0x10325476
R1 = [7, 12, 17, 22]
R2 = [5, 9, 14, 20]
R3 = [4, 11, 16, 23]
R4 = [6, 10, 15, 21]
T = [hex(int((2**32) * abs(math.sin(i+1)))) for i in range(64)]

message = "hello"
#md5 has of "hello" = 5d41402abc4b2a76b9719d911017c592
message_bytes = bytes(message,"utf-8")


#print(len(message_bytes))
T =[]
def string_to_binary(text):
    # Convert each character to its 8-bit binary representation and join them
    binary_representation = ''.join(format(ord(char), '08b') for char in text)
    return binary_representation

def padding(message,message_bits):
    if len(message_bits) <= 448:
        padding_len = 448 - len(message_bits) - 1
        message_bits += '1'
        for i in range(padding_len):
            message_bits += '0'
        message_bitlen =  f"{len(message):064b}"
        #print (message_bitlen)
    total_message_bits = message_bits + message_bitlen
    return total_message_bits

def paddingHex(message,message_hex):
    if len(message_hex) <= 112:
        padding_len = 112 - len(message_hex) - 1
        message_hex += '1'  
        for i in range(padding_len):
            message_hex += '0'
        message_len = hex(len(message) * 8)
        print(len(message_len))
        message_lenPadding_len = 16 - len(message_len) - 2 
        message_bitlen =  f"{message_len[2:]:015x}"
        print (message_bitlen)
    total_message_bits = message_hex + message_len
    return total_message_bits
def F():
    return (B & C) | (~B & D) 
def G():
    return (B & D) | (C & ~D) 
def H():
    return B ^ C ^ D 
def I():
    return C ^ (B | ~D) 

def message_splits(message512bits):
    mesage_splits =[0]*16
    for i in range(16):
        message_splits[i] = message512bits[(i*32):((i+1)*32)]

    return
def cycle1():
    global A, B, C, D
    for i in range(16):
        cls = R1[i%4]
        g = F(B, C, D)
        A = A | g | T[i]
        A = A << cls
        B |= A

        A = D
        C = B
        D = C

#print (message_bits)
#print (len(message_bits))
message_bits = string_to_binary(message)
message512bits = padding(message, message_bits)
#print(message512bits)
#print(type(message512bits))

message_hex = message_bytes.hex()
print(type(message_hex))
print(paddingHex(message,message_hex))
#print(type(A))
#print(A)

