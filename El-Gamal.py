import sys, os
from crypto.utils.EuclideanAlgorithm import GCD, EEA
import sympy
import random
from binascii import hexlify, unhexlify

# x -> Xa
# g -> A
# p -> q
# r -> Xb
# h -> Ya
#
#
def shared_secret(A,Xa,q): # Done by Alice
  # Shared Secret (Ya)
  Ya = pow(A,Xa,q)
  return Ya

def encrypt(m,Xb,A,q,Ya): # Done by Bob
  K = pow(Ya, Xb, q)
  c1 = pow(A,Xb,q) # c1 = Yb
  c2 = (m * K) % q # c2 = encrypted message
  return c1,c2

def decrypt(Xa,c1,c2,q): # Done by Alice
  K = pow(c1,Xa,q)
  dm = (c2 * EEA(K,q)) % q
  return dm

if __name__ == "__main__":
#   input_message = input("Enter message to encrypt: ")
  input_message = "Hello"
  
  inputbytes = str.encode(input_message)
  m = int(inputbytes.hex(), 16)
  
  q = sympy.randprime(m*2, m*4)
  A = sympy.randprime(int(m/2), m)
  Xa = random.randint(int(m/2),m)
  Xb = random.randint(int(m/2),m)

#   print("Bob's MESSAGE          : {}".format(input_message))
#   print("MESSAGE as an int (M)  : {}".format(m))
#   print("Prime number (P)       : {}".format(q))
#   print("Generator (G)          : {}".format(A))
#   print("Alice private key (Xa) : {}".format(Xa))
#   print("Bob's private key (Xb) : {}".format(Xb))

  Ya = shared_secret(A,Xa,q)
#   print("Shared secret (Ya)      : {}".format(Ya))

  c1, c2 = encrypt(m,Xb,A,q,Ya)
#   print("Encrypted Message (C1 or Yb) : {}".format(c1))
#   print("Encrypted Message (C2) : {}".format(c2))

  dm = decrypt(Xa,c1,c2,q)
#   print("Decrypted Integer (dm) : {}".format(dm))
  x = format(dm, 'x')
#   print("Decrypted Hex (x)     : {}".format(Xa))
  message = unhexlify(x)
  print("Decrypted Message      : {}".format(message))