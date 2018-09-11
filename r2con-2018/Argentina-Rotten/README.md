# Argentina - Rotten - 250pts
```
Get the rot...burp....rotten flag.
```
---

We've got a 64bit elf file, lets run it:
```
$ ./rotten_1e6df4a2c18f7dcd39b8358998955f9e 
- Say the magic word: 
banana
[+] This is wrong!
```

Looking at the binary we can see there are *a lot* of strings, but 2 things stand out:
- 'e2pba{.V_4z_e00bb000g=4aq_V_4z_P00Y!}' - a flag?! (I accidently found this one)
- plenty of GO related strings (section names, *.go file paths etc.) 

So we can assume this is GO binary.
Following [RedNaga's blog post](https://rednaga.io/2016/09/21/reversing_go_binaries_like_a_pro/)
we can search for any `'main'` strings in the binary:

```
$  strings rotten | grep main
...
runtime.main
runtime.main.func1
runtime.main.func2
main
main.x
main.main
main.init
```
They exist! But r2 didn't recognize them, so we can find their addresses using a part of RedNaga's IDA script adapted to r2pipe (Only later did I discover f0rki's [r2-go-helpers script](https://github.com/f0rki/r2-go-helpers))


```python
#! /usr/bin/python3
import r2pipe
import json
import string
from tqdm import tqdm

r2 = r2pipe.open("rotten")
ptr_size = r2.cmdj("ij")['bin']['bits']//8

def Dword(ea):
    res = r2.cmdj("pxwj 4 @ 0x%x"%(ea))[0]
    return res

def Qword(ea):
    res = r2.cmdj("pxqj 8 @ 0x%x"%(ea))[0]
    return res

def GetStr(ea):
    res = r2.cmd("ps @ 0x%x" % ea)
    return res

def MakeFunc(vaddr, name=""):
    r2.cmd("af %s 0x%x" %(name, vaddr))

def find_section(sec_name):
    sections_json = r2.cmdj("iSj")
    for sec in sections_json:
        if sec['name'] == sec_name:
            return sec
    return None

def get_funcs_names():
    gopcl = find_section(".gopclntab")
    if gopcl is None:
        print("[-] Couldn't find .gopclntab")
        return None

    # Get the section's size
    gopcl_vaddr = gopcl['vaddr']
    gopcl_vsize = gopcl['vsize']
    print("[+] Found %s @ 0x%x (size 0x%x)" %(gopcl['name'], gopcl_vaddr, gopcl_vsize))

    ptr = gopcl_vaddr + 8
    size = Qword(ptr)
    print("[+] 0x%x entries exist" % (size))
    ptr += ptr_size
    gopcl_end = ptr + min(size*ptr_size*2, gopcl_vsize) 
    go_strings = []

    while (ptr < gopcl_end):
        func_off = Qword(ptr)
        ptr += ptr_size
        name_off = Qword(ptr)
        ptr += ptr_size
        func_name_addr = Dword(name_off + gopcl_vaddr + ptr_size) + gopcl_vaddr
        func_name = GetStr(func_name_addr)
        go_strings.append((func_off, func_name))
    
    return go_strings

def define_and_rename(arr):
    if (arr is None) or (len(arr) == 0):
        print("#[-] Got an empty list")
        return
    for tup in tqdm(arr):
        MakeFunc(tup[0], tup[1])

all_funcs = get_funcs_names()
mains = [m for m in all_funcs if "main" in m[1]]
print("[+] Found %d functions containing 'main'" % (len(mains)))
for m in mains:
    print(" -> 0x%08x - %s" %(m[0], m[1]))
print("[+] Running 'af' on each function")
define_and_rename(mains)
print("[+] Running 'aaa'")
r2.cmd("aaa")
print("[+] Done!")
```

In order to run the script within r2 we can use the ```. (dot)``` command:

```asm
$ r2 -A rotten_1e6df4a2c18f7dcd39b8358998955f9e
...
[0x004524f0]> #?
Usage #!interpreter [<args>] [<file] [<<eof]
|  #                     comment - do nothing
|  #!                    list all available interpreters
|  #!python              run python commandline
|  #!python foo.py       run foo.py python script (same as '. foo.py')
|  #!python arg0 a1 <<q  set arg0 and arg1 and read until 'q'
[0x004524f0]> . go-main.py
[+] Found .gopclntab @ 0x4cf100 (size 0x4fc9a)
[+] 0x709 entries exist
[+] Found 7 functions containing 'main'
 -> 0x00428870 - runtime.main
 -> 0x0044dd90 - runtime.main.func1
 -> 0x0044dde0 - runtime.main.func2
 -> 0x00452510 - main
 -> 0x0048b450 - main.x
 -> 0x0048b4a0 - main.main
 -> 0x0048b7f0 - main.init
[+] Running 'af' on each function
100%|██████████████████████████████████████| 7/7 [00:11<00:00,  1.66s/it]
[+] Running 'aaa'
[+] Done!

```

Looking at `main.main` doesn't look too promising, let's see `main.x`

```asm
pdf @ main.x
[0x00452510]> pdf @ main.x
/ (fcn) main.x 67
|   main.x (int arg_8h, int arg_10h);
|           ; arg int arg_8h @ rsp+0x8
|           ; arg int arg_10h @ rsp+0x10
|           0x0048b450      8b442408       mov eax, dword [arg_8h]     ; [0x8:4]=-1 ; 8
|           0x0048b454      8d489f         lea ecx, [rax - 0x61]
|           0x0048b457      83f919         cmp ecx, 0x19               ; 25
|       ,=< 0x0048b45a      7715           ja 0x48b471
|       |   0x0048b45c      83f86d         cmp eax, 0x6d               ; 'm' ; 109
|      ,==< 0x0048b45f      7e08           jle 0x48b469
|      ||   0x0048b461      83c0f3         add eax, 0xfffffffffffffff3
|      ||   0x0048b464      89442410       mov dword [arg_10h], eax
|      ||   0x0048b468      c3             ret
|      `--> 0x0048b469      83c00d         add eax, 0xd
|       |   0x0048b46c      89442410       mov dword [arg_10h], eax
|       |   0x0048b470      c3             ret
|       `-> 0x0048b471      8d48bf         lea ecx, [rax - 0x41]
|           0x0048b474      83f919         cmp ecx, 0x19               ; 25
|       ,=< 0x0048b477      7715           ja 0x48b48e
|       |   0x0048b479      83f84d         cmp eax, 0x4d               ; 'M' ; 77
|      ,==< 0x0048b47c      7e08           jle 0x48b486
|      ||   0x0048b47e      83c0f3         add eax, 0xfffffffffffffff3
|      ||   0x0048b481      89442410       mov dword [arg_10h], eax
|      ||   0x0048b485      c3             ret
|      `--> 0x0048b486      83c00d         add eax, 0xd
|       |   0x0048b489      89442410       mov dword [arg_10h], eax
|       |   0x0048b48d      c3             ret
|       `-> 0x0048b48e      89442410       mov dword [arg_10h], eax
\           0x0048b492      c3             ret

```

That looks better, and quite like `rot...burp....rot13` cipher.

```python
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
```

Since `rot13(rot13(c)) == c` we can apply it to the jibberish flag we found earlier. Though it looks like it was only applied to `a-zA-Z` characters. 

```python
import string

rot13str = "e2pba{.V_4z_e00bb000g=4aq_V_4z_P00Y!}"

flag = ""
for c in rot13str:
    if (c in string.ascii_letters):
        flag += rot13(c)
    else:
        flag += c

print(flag)  # r2con{.I_4m_r00oo000t=4nd_I_4m_C00L!}
```

