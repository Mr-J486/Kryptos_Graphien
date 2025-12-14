
def Freq_Analysis(ciphertext):

    Alphapets =['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    Freq_dict = dict((letter, 0) for letter in Alphapets)
    print(Freq_dict)
    for i in ciphertext:
        if i in Alphapets:
            Freq_dict[i]+=1
    for letter, instances in Freq_dict.items():
        Freq_dict[letter] = (instances / len(ciphertext)) * 100
        #print(f"{letter} {instances:.2f}")
    sorted_freq =dict(sorted(Freq_dict.items(), key=lambda item: item[1], reverse=True))
    for letter, instances in sorted_freq.items(): print(f"{letter} {instances:.2f}%")
#Freq_Analysis("UZQSOVUOHXMOPVGPOZPEVSGZWSZOPFPESXUDBMETSXAIZVUEPHZHMDZSHZOWSFPAPPDTSVPQUZWYMXUZUHSXEPYEPOPDZSZUFPOMBZWPFUPZHMDJUDTMOHMQ")

def Monoalphabetic(text, key, operation):
    if len(key) != 26:
        return "key size is wrong"
    if operation == 'E':
        ciphertext = ""
        #text = text.upper()
        print (text)
        for i in text:
            charascii = ord(i)
            if charascii < 65:
                continue
            elif  charascii > 90 and charascii < 97:
                continue
            elif charascii > 122:
                continue
            charascii &= 31
            charascii -=1
            ciphertext += key[charascii]
        print(ciphertext)


   



#Monoalphabetic("it was disclosed., yesterday that several informal but direct contacts have been made with political representatives of the viet cong in moscow", "SAHVPBJWUKCXTDMYLEOZIFQRGN", 'E' )
#Monoalphabetic("UZQSOVUOHXMOPVGPOZPEVSGZWSZOPFPESXUDBMETSXAIZVUEPHZHMDZSHZOWSFPAPPDTSVPQUZWYMXUZUHSXEPYEPOPDZSZUFPOMBZWPFUPZHMDJUDTMOHMQ", "BFKNRVYCUGJQOZSEWXAMIDHLPT", 'E' )
Monoalphabetic("UZQSOVUOHXMOPVGPOZPEVSGZWSZOPFPESXUDBMETSXAIZVUEPHZHMDZSHZOWSFPAPPDTSVPQUZWYMXUZUHSXEPYEPOPDZSZUFPOMBZWPFUPZHMDJUDTMOHMQ", "BFKNRVYCUGJQOZSEWXAMIDHLPT", 'E' )


#def rail_fence:
    