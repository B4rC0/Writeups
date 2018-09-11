import string

def rot13(ch):
    c = ord(ch)
    if (ch <= 'z'):
        if (ch > 'Z'):
            pass
        else:
            if (ch <= 'M'):
                c += 13
            else:
                c -= 13
    else:
        if (ch <= 'm'):
            c += 13
        else:
            c -= 13
    return chr(c)

rot13str = "e2pba{.V_4z_e00bb000g=4aq_V_4z_P00Y!}"

flag = ""
for c in rot13str:
    if (c in string.ascii_letters):
        flag += rot13(c)
    else:
        flag += c

print(flag)  # r2con{.I_4m_r00oo000t=4nd_I_4m_C00L!}