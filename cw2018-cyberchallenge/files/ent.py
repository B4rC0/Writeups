import base64
def decipher(key, cipher):
    cipher = base64.b64decode(cipher)[:-1] # remove the null char
    ans = ""
    for i in range(len(cipher)):
        ans += chr(ord(cipher[i])^ord(key[i % len(key)]))
    return ans


text = "a" * 20
cipher = "Ug8VUgMDUlERUhNSDxVSAwNSURE5"    
print decipher(text, cipher) #'3nt3bb30p3r3nt3bb30p'

key = '3nt3bb30p3r'
# 'ls'
cipher = 'eD9MBlQ9flEZXQZWABVdAQcdQBRVeHg/TAZUPUNRA0AXXQkRQRFMQ1QWOQFbCxhfTBJbQHo='
print decipher(key, cipher) #'KQ856_Maintenance.pdf\nKQ856_passengers.pdf\nshell.php'

# 'cat KQ856_passengers.pdf'
cipher = "" # Way too long to bother
with  open('KQ856_passengers.pdf', 'wb') as fd:
   fd.write(decipher(key, cipher))