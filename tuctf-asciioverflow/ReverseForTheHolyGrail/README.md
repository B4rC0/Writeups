# Reverse For The Holy Grail

## Challenge
[A 64Bit ELF file](files/44f8fe99f38c0ec9e398f1c1f674ad4a78aaf144) is given for 350 points

Running the file we're asked 3 questions:

>*What... is your name?*  
Sir_Lancelot_of_Camelot  
*What... is your quest?*  
To seek the holy grail  
*What...  is the secret password?*  
Blue.  
*Auuuuuuuugh*

---
## Solution
Guessing didn't work so lets open this in IDA.  
Starting with the **main** function, it seems pretty straightforward.  
We can see the 3 questions output, though the input for the first 2 is ignored.  
A string object is constructed from our answer and is checked for valid characters.

So far so good, then we see a call to the function **stringMod**, that if successful the flag is printed : *Go on. Off you go. tuctf{}*

The stringMod takes the password string and validates it against 3 arrays.  
each array has 6 cells, so we can conclude our password is 18 characters long.

```python
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
  ```

  Reversing the function we get:
  ```python

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

  ```

  >*What... is your name?*  
  Sir_Lancelot_of_Camelot  
  *What... is your quest?*  
  To seek the holy grail  
  *What...  is the secret password?*  
  AfricanOrEuropean?  
  *Go on. Off you go. tuctf{AfricanOrEuropean?}*
