#! /usr/bin/python3

# Adapted to radare2 from - https://github.com/strazzere/golang_loader_assist/blob/master/golang_loader_assist.py 
# by "Tim 'diff' Strazzere"

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

STRIP_CHARS = [ '(', ')', '[', ']', '{', '}', ' ', '"' ]
REPLACE_CHARS = ['.', '*', '-', ',', ';', ':', '/', '\xb7' ]
def clean_function_name(str):
    # Kill generic 'bad' characters
    str = filter(lambda x: x in string.printable, str)

    for c in STRIP_CHARS:
        str = str.replace(c, '')

    for c in REPLACE_CHARS:
        str = str.replace(c, '_')

    return str


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
        clean_name = func_name#clean_function_name(func_name)
        go_strings.append((func_off, clean_name))
    
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
#r2.cmd("aaa")
print("[+] Done!")


