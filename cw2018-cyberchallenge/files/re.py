import md5
password = "l0lh4ck3r"
v15 = list(password) + ['\0'] # add null to mimic c-string
v13 = 4 # chosen by fair dice roll. guaranteed to be random.
for v11 in range(8):
    v14 = v15[0]
    for i in range(8):
        v15[i] = chr(ord(v15[i+1]) ^ v13)
    v15[8] = chr(ord(v14) ^ v13)
    v12 += 1
    
for j in range(9):
    v15[j] = chr(ord(v15[j]) - (v12 % 4))

v15 = "".join(v15[:-1])
if v15 == "pj.jf2ai1":
    print md5.new(password).hexdigest()
else:
    print "fail"
