
#!/usr/bin/env python

firstchar =   [0x41,  0x69,  0x6e,  0x45,  0x6f,  0x61]
thirdchar =   [0x2ef, 0x2c4, 0x2dc, 0x2c7, 0x2de, 0x2fc]
masterarray = [0x1d7, 0xc,   0x244, 0x25e, 0x93,  0x6c]

password = ""

xor_arr = []
xor_val  = 0x29a
for i in range(18):
    xor_arr.append(xor_val)
    xor_val += xor_val % 5

for i in range(6):
    first = firstchar[i]
    third = thirdchar[i] ^ xor_arr[(i*3) + 2]
    for c in range(128):
        if masterarray[i] == ((c ^ xor_arr[(i*3) + 1]) * (first ^ xor_arr[i*3])) % thirdchar[i]:
            password += chr(first) + chr(c) + chr(third)
            break

print password
