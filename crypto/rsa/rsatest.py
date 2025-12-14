from sympy import randprime, isprime
from Crypto.Util.number import inverse, bytes_to_long, long_to_bytes
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from utils.EuclideanAlgorithm import GCD, EEA
def gen_rsa_1024():
    e = 65537
    # 512-bit primes -> ~1024-bit modulus
    lower, upper = 1 << 511, (1 << 512) - 1
    while True:
        p = randprime(lower, upper)
        q = randprime(lower, upper)
        if p == q: 
            continue
        phi = (p - 1) * (q - 1)
        if GCD(e, phi) == 1:
            n = p * q
            d = EEA(e, phi)
            return p, q, n, e, d
        
def gen_rsa_2048():
    e = 65537
    # 512-bit primes -> ~1024-bit modulus
    lower, upper = 1 << 1023, (1 << 1024) - 1
    while True:
        p = randprime(lower, upper)
        q = randprime(lower, upper)
        if p == q: 
            continue
        phi = (p - 1) * (q - 1)
        if GCD(e, phi) == 1:
            n = p * q
            d = EEA(e, phi)
            return p, q, n, e, d

def request_key():
    p, q, n, e, d = gen_rsa_2048()
    public_key = (n,e)
    private_key = (n,d)
    return public_key, private_key

def rsa_test():
    p, q  = 700001, 700103
    n = p * q
    totientphi = (p - 1) * (q - 1) #totient = 490071400000
    e = 65537
    if GCD(e, totientphi) == 1:
        d = EEA(e, totientphi) #d = 345256673473
    #print(f"d= {d}")
    public_key = (n,e)
    private_key = (n,d)
    return public_key, private_key

def rsa_enc(plain, pub_key):
    #print(f"plain: {plain} \n public key: {pub_key} ")

    n, e = pub_key
    #print(f"n= {n}, e= {e}")
    #m = int.from_bytes(plain.encode(),'big')
    # plain = plain.encode()   # convert str → bytes
    print(f"type is : {type(plain)}")
    m = bytes_to_long(plain)
    #print(f"message encoded = {m}")
    return pow(m, e, n)

def rsa_dec(cipher, pri_key):
    #print(f"cipher: {cipher} \n private key: {pri_key} ")
    n, d = pri_key
    #print (f"cipher: {cipher}, d= {d}, n= {n}")
    #print(f"pow= {pow(cipher, d, n)}")
    m = pow(cipher, d, n)
    #print(f"m= {m}")
    #byte_length = (int.bit_length(m) + 7) // 8
    #plaintext = int.to_bytes(m, byte_length).decode()
    
    return long_to_bytes(m)



    
p, q, n, e, d = gen_rsa_1024()
#print(f"d= {d}")
# sanity checks
assert isprime(p) and isprime(q)
assert p * q == n
# demo encryption/decryption
plaintext = "THM"
m = int.from_bytes(plaintext.encode())
#print(f"p= {m}")
c = pow(m, e, n)
m2 = pow(c, d, n)
byte_length = (int.bit_length(m2) + 7) // 8
plaintext_bytes = int.to_bytes(m2, byte_length)
#print(plaintext_bytes.decode())  # should print the original plaintext

pub, pri = rsa_test()
#print(f"pub: {pub} \n pri: {pri}")
testplain = b"hello"
#c = rsa_enc(testplain, pub)
#print(f"c= {c}")

#p = rsa_dec(c, pri)
#print(f"decrypted_message= {p}")