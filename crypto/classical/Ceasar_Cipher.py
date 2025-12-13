# Ceasar Cipher
# handle non-alphabets characters
# handle uppercase alphabets

def ceasar_bf(cipher, key=0 ):
    newcipher = ""  
    if key != 0:
        for i in cipher:
            charascii = ord(i)
            if charascii < 65:
                newcipher += chr(charascii)
                continue
            elif  charascii > 90 and charascii < 97:
                newcipher += chr(charascii)
                continue
            elif charascii > 122:
                newcipher += chr(charascii)
                continue
            charascii &= 31
            charascii -=1
            charascii = (charascii + key) % 26
            charascii |= 96 
            charascii +=1
            newcipher+= chr(charascii)
        return newcipher
            #newcipher+=chr(i)
        #print(newcipher)
    else:
        for i in range(26):
            for j in cipher:
                charascii = ord(j)
                if charascii < 65:
                    newcipher += chr(charascii)
                    continue
                elif  charascii > 90 and charascii < 97:
                    newcipher += chr(charascii)
                    continue
                elif charascii > 122:
                    newcipher += chr(charascii)
                    continue
                #print(charascii)
                charascii &= 31
                charascii -=1
                #print(f"ascii value before= {charascii}")
                charascii = (charascii - i) % 26
                #print(f"ascii value after= {charascii}")
                charascii |= 96 
                charascii +=1
                newcipher += chr(charascii)
            print(f"{i} --> {newcipher}")
            newcipher = ""
    

a ='a'
a= ord(a) + 1
#print(a)

#ceasar_bf("abcd",0)
#ceasar_bf("PHHW PH DIWHU WKH WRJD SDUWB",0)
#ceasar_bf("phhwphdiwhuwkhwrjdsduwb",0)
#ceasar_bf("Pm ol ohk hufaopun jvumpkluaphs av zhf, ol dyval pa pu jpwoly, aoha pz, if zv johunpun aol vykly vm aol slaalyz vm aol hswohila, aoha uva h dvyk jvbsk il thkl vba.")

def Polyalphabetic(text, key, key_type,operation):
    ciphertext = ""  
    mod_key = ""
    if key_type == "Repeating key":
        while(len(mod_key)<len(text)):
            mod_key += key
    elif key_type == "Auto-key":
        mod_key = key
        while(len(mod_key)<len(text)):
            mod_key += text
    else:
        return "Theoritical...🤦"
    #print(mod_key)
    for i in range(len(text)):
        plain_ascii = ord(text[i])
        key_ascii = ord(mod_key[i])
        if plain_ascii < 65:
            continue
        elif  plain_ascii > 90 and plain_ascii < 97:
            continue
        elif plain_ascii > 122:
            continue

        plain_ascii &= 31
        key_ascii &= 31

        plain_ascii -=1
        key_ascii -=1
        
        if operation == "encrypt":
            plain_ascii = (plain_ascii + key_ascii) % 26
        else:
            plain_ascii = (plain_ascii - key_ascii) % 26

        plain_ascii |= 96 
        plain_ascii +=1
        ciphertext+= chr(plain_ascii).upper()
    return ciphertext
print(Polyalphabetic("computer", "hello", "Repeating key", "encrypt"))
print(Polyalphabetic("JSXAIAIC", "hello", "Repeating key", "decrypt"))

#print(Polyalphabetic("computer", "hello", "Auto-key", "encrypt"))
#print(Polyalphabetic("computer", "hello", "One-time-pad", "encrypt"))

