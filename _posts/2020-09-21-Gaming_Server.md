---
title: Gaming Server 
category: writeup
tags: tryhackme
---

# Summary

Tryhackme

Gaming server is a easy machine which requires some basic enumeration to find a username in the page's source and doing some dirbusting to find a encrypted ssh-key and a password list which is used to crack the passphrase for the ssh-key. To escalate privileges we abuse the lxd group permissions to mount the host file system inside the container.

# Enumeration

## NMAP

Running a NMAP scan reveals the following:

```
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 34:0e:fe:06:12:67:3e:a4:eb:ab:7a:c4:81:6d:fe:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCrmafoLXloHrZgpBrYym3Lpsxyn7RI2PmwRwBsj1OqlqiGiD4wE11NQy3KE3Pllc/C0WgLBCAAe+qHh3VqfR7d8uv1MbWx1mvmVxK8l29UH1rNT4mFPI3Xa0xqTZn4Iu5RwXXuM4H9OzDglZas6RIm6Gv+sbD2zPdtvo9zDNj0BJClxxB/SugJFMJ+nYfYHXjQFq+p1xayfo3YIW8tUIXpcEQ2kp74buDmYcsxZBarAXDHNhsEHqVry9I854UWXXCdbHveoJqLV02BVOqN3VOw5e1OMTqRQuUvM5V4iKQIUptFCObpthUqv9HeC/l2EZzJENh+PmaRu14izwhK0mxL
|   256 49:61:1e:f4:52:6e:7b:29:98:db:30:2d:16:ed:f4:8b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEaXrFDvKLfEOlKLu6Y8XLGdBuZ2h/sbRwrHtzsyudARPC9et/zwmVaAR9F/QATWM4oIDxpaLhA7yyh8S8m0UOg=
|   256 b8:60:c4:5b:b7:b2:d0:23:a0:c7:56:59:5c:63:1e:c4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLrnjg+MVLy+IxVoSmOkAtdmtSWG0JzsWVDV2XvNwrY
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: House of danak
```

## Port 80

Checking port 80 reveals a page with a lot of dummy text. 

Checking the web page source reveals a interesting comment that says:

> john, please add some actual content to the site! lorem ipsum is horrible to look at

This could be a potential username that can be used later.

Fuzzing the directories using gobuster reveals the following:

```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.35.125/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/09/21 21:38:43 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/robots.txt (Status: 200)
/secret (Status: 301)
/server-status (Status: 403)
/uploads (Status: 301)
===============================================================
2020/09/21 21:41:03 Finished
===============================================================
```

Checking the uploads directory reveals a word list which possibly contains a list that we might use for doing some sort of bruteforcing.

Checking secret reveals a encrypted ssh key and we most likely would need to use the wordlist to crack the passphrase.

![WGET](..//images/gamingserver/wget.png)

However, in order to crack a ssh-key we need to convert it to a form than johntheripper will be able to understand. In order to do this we use a python script named `[ssh2john.py](http://ssh2john.py)` which comes with the johntheripper package.

```bash
/usr/share/john/ssh2john.py secretKey > ssh-hash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh-hash
```

![Crack](../images/gamingserver/crack.png)

John returns the password letmein.

## SSH

Logging in with ssh with the username `john` we found earlier and passphrase for the key `letmein` we are able to log in.

```bash
ssh -i secretKey john@10.10.35.125
```

## Privilege Escalation

Checking the current groups that the user is a part of reveals an interesting group `lxc` this group from past experience allows privilege escalation commonly done by mounting the rootfs inside a container and then interacting with the container and getting access to all the fs.

Following the privilege escalation steps in this article allows us to use a lxd container to mount the host machines rootfs inside the container giving us access to the root flag.

[Lxd Privilege Escalation](https://www.hackingarticles.in/lxd-privilege-escalation/)
