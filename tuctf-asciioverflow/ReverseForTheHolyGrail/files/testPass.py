#!/usr/bin/env python

firstchar =   [0x41,  0x69,  0x6e,  0x45,  0x6f,  0x61]
thirdchar =   [0x2ef, 0x2c4, 0x2dc, 0x2c7, 0x2de, 0x2fc]
masterarray = [0x1d7, 0xc,   0x244, 0x25e, 0x93,  0x6c]

password = "AfricanOrEuropean?"
failed = False

# check every 3rd character - starting with 0
for i in range(0,len(password),3):
    if ord(password[i]) != firstchar[i/3]:
        failed = True
        break

xor_val  = 0x29a
xored_pass = []

# xor each character with a different value
for c in password:
    xored_pass.append(ord(c) ^ xor_val)
    xor_val += xor_val % 5

# check every 3rd character - starting with 2
for i in range(2, len(xored_pass), 3):
    if xored_pass[i] != thirdchar[(i-2)/3]:
        failed = True
        break

# check every 3rd character - starting with 1
for i in range(0, len(xored_pass), 3):
    if masterarray[i/3] != ((xored_pass[i] * xored_pass[i+1]) % xored_pass[i+2]):
        failed = True
        break

if (failed):
    print "Wrong!"
else:
    print "Correct!"
