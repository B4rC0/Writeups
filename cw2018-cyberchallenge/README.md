# CyberWeek 2018 - Cyber Challenge

There were a total of 9 challenges that must be solved in a consecutive manner  
![Challenges](files/images/challenges.png)

## Entebbe International Airport
### Airport Security
>Entebbe International Airport servers are located at http://40.113.226.176/ There should be an Admin backdoor available. Find it and provide its URL. Use the following format - http://xxx.xxx.xxx.xxx/xxxx


Open page source and search for 'admin'   
![Page Source](files/images/1-1.png)  
Solution is:  http://40.113.226.176/EIAAdminConsole/shell.php


### Crack the Shell
>What is the encryption key to the shell?

We get access to the admin console which accepts `ls, cat, echo`.  
So we try `'echo aaaaaaaaaaaaaaaaaaaa'` and get a base64 result:  
![Admin Console](files/images/1-2.png)  
After decoding the base64 and xoring with the input `aaaaaaaaaaaaaaaaaaaa`, we get `3nt3bb30p3r3nt3bb30p`
```python
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
```
Solution is:  '3nt3bb30p3r'

### Get the Lists
>Retrieve the lists of flight KQ856. What is the name of the passenger seated at 12C?

Now that we have the key, we can run *'ls'* which returns 3 files:
`KQ856_Maintenance.pdf, KQ856_passengers.pdf, shell.php`

we can perform `'cat KQ856_passengers.pdf'`, decipher the output into a file, open it normally ans search for seat C12:
![Passenger List](files/images/1-3.png)
Solution is: Danso Sane

You can find the python script [Here](files/ent.py).

---

## ABC Capital Bank
### Customer Support
>Hack into the ABC Capital Bank system at http://40.113.226.89/ and gain access to the Customer Support system. What do you get when gaining access?

Examining the cookies we can see there's an odd one (`isDebugMode=false`):   
![Cookie](files/images/2-1.png)

Changing the value to *'true'* adds a link that wasn't there previously  
![Cookie](files/images/2-1a.png)

Which leads to http://40.113.226.89/2018-Mar-Jun-Transactions.csv  
Solution is: 2018-Mar-Jun-Transactions.csv


### Transaction Database
>look for a suspicious transaction. What is the Transaction ID?

After downloading the file we get a standard csv file with the following format: 

ID,Date,Name,, Amount ,Currency,Type,,,

Throwing it in Excel and playing with various parameters, we eventually find a transaction that has the highest transaction amount:  
`20183521797,01/04/2018,Sultan,Okereke," 57,250,600 ",UGX,Transfer,,,`

Solution is: 20183521797

---

## Technician Home
### Logs Analysis
>The logs are available at [/media/Evidences/NetworkLogs.pcap](files/NetworkLogs.pcap). Analyze them and find the IP of the ransomware CnC server.

In Wireshark we go to *File->Export Objects->HTTP* and get a list of objects.
Looking through them we find several objects with no Hostname/Content Type.  
![PCAP](files/images/3-1.png)

Following the TCP stream, we get a base64 conversation:
| | Base64  | Plaintext|
|:-|:--------|:---------|
|Client | SEVMTE8=                         |  HELLO  
|Server | SEVMTE8=                         |  HELLO  
|Client | R2V0Q05DU2VydmVy                 |  GetCNCServer  
|Server | Q05DIFNFUlZFUiAyMy45OS4yMjYuMTc= |  CNC SERVER 23.99.226.17  
|Client | R09PREJZRQ==                     |  GOODBYE  
|Server | R09PREJZRQ==                     |  GOODBYE  

Solution is: 23.99.226.17

---

## Datanet Server Farm
### CnC Access
> First see if you can access the CnC server. What is the value passed to the server that lets you in?

Entering the website (http://23.99.226.17/) we're greeted with a minimal login  
![Login](files/images/4-1.png)

Looking at the source we find an obfuscated js script
```javascript
var _0xeb5f = ["\x76\x61\x6C\x75\x65", "\x70\x61\x73\x73\x69\x6E\x70", "\x70\x61\x73\x73\x77\x6F\x72\x64", "\x66\x6F\x72\x6D\x73", "\x63\x6F\x6C\x6F\x72", "\x73\x74\x79\x6C\x65", "\x76\x61\x6C\x69\x64", "\x67\x65\x74\x45\x6C\x65\x6D\x65\x6E\x74\x42\x79\x49\x64", "\x67\x72\x65\x65\x6E", "\x69\x6E\x6E\x65\x72\x48\x54\x4D\x4C", "", "\x72\x65\x64", "\x49\x6E\x63\x6F\x72\x72\x65\x63\x74\x21"];
function validate() {
    var _0xb252x2 = 123211;
    var _0xb252x3 = 3422543454;
    var _0xb252x4 = document[_0xeb5f[3]][_0xeb5f[2]][_0xeb5f[1]][_0xeb5f[0]];
    var _0xb252x5 = md5(_0xb252x4);
    _0xb252x4 += 7655;
    _0xb252x4 -= 128274654548;
    _0xb252x4 *= 1828;
    _0xb252x2 -= 3748;
    _0xb252x3 += 458403;
    if (_0xb252x4 == 988102976119596) {
        document[_0xeb5f[3]][_0xeb5f[2]][_0xeb5f[1]][_0xeb5f[0]] = _0xb252x5;
        return true;
    } else {
        document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[5]][_0xeb5f[4]] = _0xeb5f[11];
        document[_0xeb5f[7]](_0xeb5f[6])[_0xeb5f[9]] = _0xeb5f[12]
    }
    ;return false
}
```
After some clean up we get 
```javascript
function validate() {
    var pass = document["forms"]["password"]["passinp"]["value"];
    var pass_md5 = md5(pass);
    pass += 7655;
    pass -= 128274654548;
    pass *= 1828;
    if (pass == 988102976119596) {
        document["forms"]["password"]["passinp"]["value"] = pass_md5;
        return true;
    } else {
        document["getElementById"]("valid")["style"]["color"] ="red";
        document["getElementById"("valid")["innerHTML"] = "Incorrect!"
    };
    return false
}
```
We can see the function checks if `pass == 988102976119596` after some arithmetic operations.  
Reversing that we find the original value is `668812380000` (A number, **not** the string), and its md5 is sent to the server.  
You can either send the POST with the md5 value manually, or break into the Validate function and change the input manually.  
Solution is: "622838154f7f6e26fd9c137c822c4b31"  


### Locate the Location
>Excellent! Now see if you can find the location of the ISIS hideaway. Send it in the following format: xx.xxxxxx N, xx.xxxxxx E. Make it fast, time is running out!

We get access to several files (images/pdf), our first suspect is exif metadata as it might contain geolocation.  
Since there are only 6 files, we can check each one manually, eventually we find that `Agent0kereke.jpg` has some interesting data
```
root@kali2:~/Desktop/ctf# exiftool -c "%.6f" AgentOkereke.jpg 
ExifTool Version Number         : 11.01
File Name                       : AgentOkereke.jpg
...
Artist                          : 1337 h4ck3r
...
GPS Latitude                    : 0.271433 N
GPS Longitude                   : 32.547283 E
GPS Position                    : 0.271433 N, 32.547283 E
```
Solution is: 0.271433 N, 32.547283 E

Exif usage taken from [here](https://exposingtheinvisible.org/resources/image-digging)

---

## Isis Hideaway
### Dead Men Can't Speak
>M. finds a decryption tool on the Laptop which he thinks may include the key to the ransomware. He uploads the file to: [/media/Evidences/DecryptionTool](/files/DecryptionTool). Get the ransomware decryption key!

The file is a 64bit ELF, so let's run it and see what happens.  
```
root@kali2:~/Desktop/ctf# ./DecryptionTool 
enter password to get the decryption key:
asdf

fail
```
Nothing too exciting. Time for IDA.  
Looking at the `main` function we can distinguish 4 interesting parts:  
1) First we have the initialization where our input password is saved into v15  
![RE Init](files/images/5-1.png)  

2) Here we see a double loop that uses the random value `v13` to xor our password  
![RE Xor](files/images/5-1a.png)  
let's try to simplify with some Python
```python
v12 = 30
v13 = 4 # chosen by fair dice roll. guaranteed to be random.
for v11 in range(8):
    v14 = password[0]
    for i in range(8):
        password[i] = chr(ord(password[i+1]) ^ v13)
    password[8] = chr(ord(v14) ^ v13)
    v12 += 1
```
There are 2 important things to notice here:
- Each outer iteration performs a xor and rotates the result by 1 byte (including the null byte), 8 times total.
- each byte is xored an even amount of times (8*8) with the same value, thus nullyfing the xor.

3) This one is straight forward, substract from each char `(v12 % 4)`. Looking back at `v12`, we can see its value is a constant `38` so we will always substract `2`.  
![RE Shift](files/images/5-1b.png)  

```python
for j in range(9):
    password[j] = chr(ord(password[j]) - (v12 % 4))
```

4) Eventually we test whether we got `"pj.jf2ai1"` and if so print out the password's md5 value.  
![RE Test](files/images/5-1c.png)  
```python
v15 = "".join(v15[:-1])
if v15 == "pj.jf2ai1":
    print md5.new(password).hexdigest()
else:
    print "fail"
```

So in order to solve this one, we need to add 2 for each char in `"pj.jf2ai1"` which is `"rl0lh4ck3"`, taking the rotation into account we fix it up and try it:
```
root@kali2:~/Desktop/ctf# ./DecryptionTool 
enter password to get the decryption key:
l0lh4ck3r

success
Decyrption Key Is f2ddd1c9cb75129ac8e69f305e77750e
```
Solution is: l0lh4ck3r

You can find the python script [Here](files/re.py).